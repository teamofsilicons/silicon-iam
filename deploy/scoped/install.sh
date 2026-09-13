#!/usr/bin/env bash
# Run on the existing IAM instance after deploying the IAM migrations and image.
# Installs only the scoped service and its own nginx virtual host.
set -euo pipefail
umask 077

SCOPED_IMAGE=""
SCOPED_ORIGINS="https://interface.teamofsilicons.com,https://auth.iam.teamofsilicons.com"
SCOPED_REGION="${AWS_REGION:-us-east-1}"
SCOPED_TLS=false
SCOPED_HOST="scoped.backend.iam.teamofsilicons.com"
SCOPED_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while (($#)); do
  case "$1" in
    --image) SCOPED_IMAGE="${2:?missing image}"; shift 2 ;;
    --cors-origins) SCOPED_ORIGINS="${2:?missing origins}"; shift 2 ;;
    --tls) SCOPED_TLS=true; shift ;;
    -h|--help)
      echo 'Usage: install.sh --image <registry/repository@sha256:digest> [--cors-origins https://interface.teamofsilicons.com,https://auth.iam.teamofsilicons.com] [--tls]'
      exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 64 ;;
  esac
done

[[ "$EUID" == 0 ]] || { echo 'Run on the IAM instance as root.' >&2; exit 1; }
[[ "$SCOPED_IMAGE" =~ ^[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}$ ]] || {
  echo 'An immutable image digest is required.' >&2; exit 64;
}
[[ "$SCOPED_ORIGINS" =~ ^https://[a-zA-Z0-9.-]+(:[0-9]+)?(,https://[a-zA-Z0-9.-]+(:[0-9]+)?)*$ ]] || {
  echo 'Supply comma-separated exact HTTPS origins.' >&2; exit 64;
}
[[ "$SCOPED_REGION" =~ ^[a-z]{2}-[a-z]+-[0-9]+$ ]] || { echo 'Invalid AWS region.' >&2; exit 64; }
[[ -r /etc/silicon-iam/api.env ]] || { echo 'The existing IAM API environment is required.' >&2; exit 1; }

# The API environment carries the shared runtime DB role, keyrings, and canonical
# IAM callback URL. Copy it only inside the host, never into a release artifact.
# Override process-specific limits without sourcing or printing credentials.
docker image inspect "$SCOPED_IMAGE" >/dev/null
SCOPED_ENV_TEMP=$(mktemp /etc/silicon-iam/scoped.env.XXXXXX)
trap 'rm -f "$SCOPED_ENV_TEMP"' EXIT
awk '!/^(IAM_BIND_ADDR|IAM_CORS_ALLOWED_ORIGINS|IAM_DATABASE_MAX_CONNECTIONS|IAM_DATABASE_MIN_CONNECTIONS|IAM_TESTING_DATABASE_MAX_CONNECTIONS|IAM_TESTING_DATABASE_MIN_CONNECTIONS)=/' \
  /etc/silicon-iam/api.env > "$SCOPED_ENV_TEMP"
cat >> "$SCOPED_ENV_TEMP" <<ENV
IAM_BIND_ADDR=0.0.0.0:8080
IAM_CORS_ALLOWED_ORIGINS=$SCOPED_ORIGINS
IAM_DATABASE_MAX_CONNECTIONS=4
IAM_DATABASE_MIN_CONNECTIONS=0
IAM_TESTING_DATABASE_MAX_CONNECTIONS=2
IAM_TESTING_DATABASE_MIN_CONNECTIONS=0
ENV
chmod 0600 "$SCOPED_ENV_TEMP"
mv "$SCOPED_ENV_TEMP" /etc/silicon-iam/scoped.env

# Dedicated receiver keys survive reinstall without entering the main API env.
if [[ ! -e /etc/silicon-iam/scoped-webhook.env ]]; then
  install -m 0600 /dev/null /etc/silicon-iam/scoped-webhook.env
fi
chmod 0600 /etc/silicon-iam/scoped-webhook.env

install -d -m 0700 -o 10001 -g 10001 /var/lib/silicon-iam/telemetry/scoped-api

cat > /etc/systemd/system/silicon-iam-scoped-api.service <<UNIT
[Unit]
Description=Silicon IAM scoped application API
Requires=docker.service
After=docker.service network-online.target

[Service]
Restart=always
RestartSec=5
TimeoutStopSec=45
ExecStartPre=-/usr/bin/docker rm -f silicon-iam-scoped-api
ExecStart=/usr/bin/docker run --name silicon-iam-scoped-api --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:size=16m,mode=1777 --volume /opt/silicon-iam/aws-rds-global-bundle.pem:/opt/silicon-iam/aws-rds-global-bundle.pem:ro --volume /var/lib/silicon-iam/telemetry/scoped-api:/var/lib/silicon-iam/telemetry --env IAM_TELEMETRY_HOME=/var/lib/silicon-iam/telemetry --env-file /etc/silicon-iam/scoped.env --env-file /etc/silicon-iam/scoped-webhook.env --publish 127.0.0.1:8081:8080 --log-driver awslogs --log-opt awslogs-region=$SCOPED_REGION --log-opt awslogs-group=/silicon-iam/production/api --log-opt tag=scoped-api "$SCOPED_IMAGE" iam-scoped-api
ExecStop=/usr/bin/docker stop --time 35 silicon-iam-scoped-api

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 /etc/systemd/system/silicon-iam-scoped-api.service
systemctl daemon-reload
systemctl enable silicon-iam-scoped-api
systemctl restart silicon-iam-scoped-api

SCOPED_READY=false
for attempt in $(seq 1 30); do
  if curl --fail --silent --max-time 3 http://127.0.0.1:8081/readyz >/dev/null; then
    SCOPED_READY=true
    break
  fi
  sleep 2
done
[[ "$SCOPED_READY" == true ]] || { echo 'Scoped API did not become ready.' >&2; exit 1; }

# Before DNS or TLS cutover, verify excluded routes really are absent.
for path in /api/v1/obo-access/exchanges /api/v1/applications /api/v1/admin/applications /api/v1/auth/login /api/v1/provider-webhooks/workos; do
  SCOPED_STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 "http://127.0.0.1:8081$path")
  [[ "$SCOPED_STATUS" == 404 ]] || { echo "Unexpected scoped route: $path ($SCOPED_STATUS)" >&2; exit 1; }
done

if [[ "$SCOPED_TLS" == true ]]; then
  # Add scoped.backend.iam DNS pointing to this host before requesting TLS.
  # The existing Certbot account and auto-renewal timer are reused.
  SCOPED_NGINX=/etc/nginx/conf.d/scoped-iam.conf
  if [[ ! -e "/etc/letsencrypt/live/$SCOPED_HOST/fullchain.pem" ]]; then
    SCOPED_NGINX_TEMP=$(mktemp /etc/nginx/conf.d/scoped-iam.XXXXXX)
    cat > "$SCOPED_NGINX_TEMP" <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name $SCOPED_HOST;
    root /var/www/certbot;
    location /.well-known/acme-challenge/ { try_files \$uri =404; }
    location / { return 404; }
    access_log off;
}
NGINX
    if [[ -e "$SCOPED_NGINX" ]] && ! cmp --silent "$SCOPED_NGINX" "$SCOPED_NGINX_TEMP"; then
      rm -f "$SCOPED_NGINX_TEMP"
      echo 'Existing scoped nginx config has no matching certificate; inspect it before continuing.' >&2
      exit 1
    fi
    mv "$SCOPED_NGINX_TEMP" "$SCOPED_NGINX"
    nginx -t
    systemctl reload nginx
    certbot certonly --webroot --webroot-path /var/www/certbot --non-interactive \
      --cert-name "$SCOPED_HOST" --domain "$SCOPED_HOST" \
      --deploy-hook "systemctl reload nginx"
  fi
  install -m 0644 "$SCOPED_DIRECTORY/nginx.conf" "$SCOPED_NGINX"
  nginx -t
  systemctl reload nginx
  # Old nginx workers can briefly serve their previous certificate after a
  # successful reload. Retry both public checks with normal TLS verification.
  SCOPED_PUBLIC_READY=false
  for attempt in {1..5}; do
    if curl --fail --silent --show-error --max-time 3 "https://$SCOPED_HOST/healthz" >/dev/null \
      && curl --fail --silent --show-error --max-time 3 "https://$SCOPED_HOST/readyz"; then
      SCOPED_PUBLIC_READY=true
      break
    fi
    if ((attempt < 5)); then
      sleep 2
    fi
  done
  [[ "$SCOPED_PUBLIC_READY" == true ]] || { echo 'Scoped HTTPS health/readiness checks did not pass after nginx reload.' >&2; exit 1; }
  echo
fi

echo 'Scoped IAM backend installed and ready on loopback port 8081.'
