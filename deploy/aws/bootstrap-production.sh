#!/bin/bash
set -Eeuo pipefail
umask 077

# CloudFormation's small user-data wrapper exports these nonsecret values.
: "${REGION:?}" "${ACCOUNT_ID:?}" "${APP_SECRET_ARN:?}" "${DB_SECRET_ARN:?}"
: "${DB_HOST:?}" "${TEST_DB_SECRET_ARN:?}" "${TEST_DB_HOST:?}" "${BACKEND_IMAGE:?}"
: "${DIRECT_NGINX:?}"
if [[ -e /etc/silicon-iam/api.env ]]; then
  echo 'Refusing to provision over an existing IAM runtime environment.' >&2
  exit 1
fi

# A failed fresh-host bootstrap must not leave a partial writer set running.
# This trap is installed only after the existing-host guard above succeeds.
bootstrap_failed() {
  trap - ERR
  systemctl stop silicon-iam-api silicon-iam-scoped-api silicon-iam-worker 2>/dev/null || true
  echo 'Fresh IAM provisioning failed; inspect cloud-init before resuming services.' >&2
  exit 1
}
trap bootstrap_failed ERR

dnf install --assumeyes docker jq postgresql15 python3
if [[ "$DIRECT_NGINX" == true ]]; then
  dnf install --assumeyes nginx certbot python3-certbot-nginx amazon-ec2-net-utils
  # A parallel replacement must fail before touching shared database roles.
  python3 /opt/silicon-iam/provisioning/direct-ingress.py preflight
fi
systemctl enable --now docker
systemctl enable --now amazon-ssm-agent

install -d -m 0700 /etc/silicon-iam /opt/silicon-iam
curl --fail --silent --show-error --location \
  https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem \
  --output /opt/silicon-iam/aws-rds-global-bundle.pem
chmod 0644 /opt/silicon-iam/aws-rds-global-bundle.pem

aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com"
docker pull "$BACKEND_IMAGE"

APP_SECRET_JSON=$(aws secretsmanager get-secret-value --region "$REGION" \
  --secret-id "$APP_SECRET_ARN" --query SecretString --output text)
DB_SECRET_JSON=$(aws secretsmanager get-secret-value --region "$REGION" \
  --secret-id "$DB_SECRET_ARN" --query SecretString --output text)
TEST_DB_SECRET_JSON=$(aws secretsmanager get-secret-value --region "$REGION" \
  --secret-id "$TEST_DB_SECRET_ARN" --query SecretString --output text)

if ! printf '%s' "$APP_SECRET_JSON" | jq -e '
  [ .IAM_POSTMARK_SERVER_TOKEN, .IAM_TWILIO_ACCOUNT_SID,
    .IAM_TWILIO_AUTH_TOKEN, .IAM_TWILIO_MESSAGING_SERVICE_SID,
    .IAM_TWILIO_VERIFY_SERVICE_SID,
    .IAM_WORKOS_API_KEY, .IAM_WORKOS_CLIENT_ID,
    .IAM_WORKOS_WEBHOOK_SECRET ]
  | all(type == "string" and length > 0 and . != "REPLACE_IN_AWS_CONSOLE")
' >/dev/null; then
  echo 'Provider credentials have not been completed in Secrets Manager.' >&2
  exit 1
fi

DB_MASTER_USER=$(printf '%s' "$DB_SECRET_JSON" | jq -r .username)
DB_MASTER_PASSWORD=$(printf '%s' "$DB_SECRET_JSON" | jq -r .password)
TEST_DB_MASTER_USER=$(printf '%s' "$TEST_DB_SECRET_JSON" | jq -r .username)
TEST_DB_MASTER_PASSWORD=$(printf '%s' "$TEST_DB_SECRET_JSON" | jq -r .password)
API_DB_PASSWORD=$(printf '%s' "$APP_SECRET_JSON" | jq -r .IAM_LOCAL_API_DATABASE_PASSWORD)
WORKER_DB_PASSWORD=$(printf '%s' "$APP_SECRET_JSON" | jq -r .IAM_LOCAL_WORKER_DATABASE_PASSWORD)
KEY_OPERATOR_DB_PASSWORD=$(printf '%s' "$APP_SECRET_JSON" | jq -r .IAM_LOCAL_KEY_OPERATOR_DATABASE_PASSWORD)

export PGSSLMODE=verify-full PGSSLROOTCERT=/opt/silicon-iam/aws-rds-global-bundle.pem

configure_database() {
  local database_host="$1"
  local database_name="$2"
  local database_user="$3"
  local database_password="$4"
  local database_label="$5"

  export PGHOST="$database_host" PGPORT=5432 PGDATABASE="$database_name"
  export PGUSER="$database_user" PGPASSWORD="$database_password"
  for attempt in $(seq 1 90); do
    if pg_isready --timeout=5 >/dev/null 2>&1; then
      break
    fi
    if [ "$attempt" -eq 90 ]; then
      echo "$database_label RDS did not become ready in time." >&2
      exit 1
    fi
    sleep 5
  done

  psql --set=ON_ERROR_STOP=1 \
    --set=api_password="$API_DB_PASSWORD" \
    --set=worker_password="$WORKER_DB_PASSWORD" \
    --set=key_operator_password="$KEY_OPERATOR_DB_PASSWORD" <<'SQL'
DO $roles$
BEGIN
  IF pg_catalog.to_regrole('silicon_iam_api') IS NULL THEN
    CREATE ROLE silicon_iam_api NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF pg_catalog.to_regrole('silicon_iam_worker') IS NULL THEN
    CREATE ROLE silicon_iam_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF pg_catalog.to_regrole('silicon_iam_key_operator') IS NULL THEN
    CREATE ROLE silicon_iam_key_operator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF pg_catalog.to_regrole('silicon_iam_api_runtime') IS NULL THEN
    CREATE ROLE silicon_iam_api_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF pg_catalog.to_regrole('silicon_iam_worker_runtime') IS NULL THEN
    CREATE ROLE silicon_iam_worker_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF pg_catalog.to_regrole('silicon_iam_key_operator_runtime') IS NULL THEN
    CREATE ROLE silicon_iam_key_operator_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END;
$roles$;
ALTER ROLE silicon_iam_api_runtime PASSWORD :'api_password';
ALTER ROLE silicon_iam_worker_runtime PASSWORD :'worker_password';
ALTER ROLE silicon_iam_key_operator_runtime PASSWORD :'key_operator_password';
GRANT silicon_iam_api TO silicon_iam_api_runtime;
GRANT silicon_iam_worker TO silicon_iam_worker_runtime;
GRANT silicon_iam_key_operator TO silicon_iam_key_operator_runtime;
SQL
}

configure_database "$DB_HOST" silicon_iam "$DB_MASTER_USER" "$DB_MASTER_PASSWORD" Production
configure_database "$TEST_DB_HOST" silicon_iam_testing "$TEST_DB_MASTER_USER" "$TEST_DB_MASTER_PASSWORD" Testing

DB_MASTER_PASSWORD_URI=$(printf '%s' "$DB_MASTER_PASSWORD" | jq -sRr @uri)
TEST_DB_MASTER_PASSWORD_URI=$(printf '%s' "$TEST_DB_MASTER_PASSWORD" | jq -sRr @uri)
MIGRATOR_DATABASE_URL="postgresql://$DB_MASTER_USER:$DB_MASTER_PASSWORD_URI@$DB_HOST:5432/silicon_iam?sslmode=verify-full&sslrootcert=/opt/silicon-iam/aws-rds-global-bundle.pem"
TESTING_MIGRATOR_DATABASE_URL="postgresql://$TEST_DB_MASTER_USER:$TEST_DB_MASTER_PASSWORD_URI@$TEST_DB_HOST:5432/silicon_iam_testing?sslmode=verify-full&sslrootcert=/opt/silicon-iam/aws-rds-global-bundle.pem"
docker run --rm --network host --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:size=16m,mode=1777 \
  --volume /opt/silicon-iam/aws-rds-global-bundle.pem:/opt/silicon-iam/aws-rds-global-bundle.pem:ro \
  --env IAM_ENVIRONMENT=production \
  --env IAM_LOG_FILTER=silicon_iam=info \
  --env IAM_MIGRATOR_DATABASE_URL="$MIGRATOR_DATABASE_URL" \
  --env IAM_TESTING_MIGRATOR_DATABASE_URL="$TESTING_MIGRATOR_DATABASE_URL" \
  --env IAM_MIGRATOR_DATABASE_MAX_CONNECTIONS=2 \
  --env IAM_MIGRATOR_DATABASE_ACQUIRE_TIMEOUT_SECONDS=10 \
  --env IAM_MIGRATOR_DATABASE_STATEMENT_TIMEOUT_SECONDS=120 \
  "$BACKEND_IMAGE" iam-migrate

GRANT_CONTAINER=$(docker create "$BACKEND_IMAGE")
docker cp "$GRANT_CONTAINER:/opt/silicon-iam/postgres/runtime-grants.sql" /opt/silicon-iam/runtime-grants.sql
if [[ "$DIRECT_NGINX" == true ]]; then
  docker cp "$GRANT_CONTAINER:/opt/silicon-iam/scoped" /opt/silicon-iam/scoped
fi
docker rm "$GRANT_CONTAINER" >/dev/null
chmod 0400 /opt/silicon-iam/runtime-grants.sql
PGHOST="$DB_HOST" PGDATABASE=silicon_iam PGUSER="$DB_MASTER_USER" PGPASSWORD="$DB_MASTER_PASSWORD" \
  psql --set=ON_ERROR_STOP=1 --file=/opt/silicon-iam/runtime-grants.sql
PGHOST="$TEST_DB_HOST" PGDATABASE=silicon_iam_testing PGUSER="$TEST_DB_MASTER_USER" PGPASSWORD="$TEST_DB_MASTER_PASSWORD" \
  psql --set=ON_ERROR_STOP=1 --file=/opt/silicon-iam/runtime-grants.sql

API_DB_URL="postgresql://silicon_iam_api_runtime:$API_DB_PASSWORD@$DB_HOST:5432/silicon_iam?sslmode=verify-full&sslrootcert=/opt/silicon-iam/aws-rds-global-bundle.pem"
WORKER_DB_URL="postgresql://silicon_iam_worker_runtime:$WORKER_DB_PASSWORD@$DB_HOST:5432/silicon_iam?sslmode=verify-full&sslrootcert=/opt/silicon-iam/aws-rds-global-bundle.pem"
TESTING_API_DB_URL="postgresql://silicon_iam_api_runtime:$API_DB_PASSWORD@$TEST_DB_HOST:5432/silicon_iam_testing?sslmode=verify-full&sslrootcert=/opt/silicon-iam/aws-rds-global-bundle.pem"
TESTING_WORKER_DB_URL="postgresql://silicon_iam_worker_runtime:$WORKER_DB_PASSWORD@$TEST_DB_HOST:5432/silicon_iam_testing?sslmode=verify-full&sslrootcert=/opt/silicon-iam/aws-rds-global-bundle.pem"

cat > /etc/silicon-iam/api.env <<EOF
IAM_ENVIRONMENT=production
IAM_TELEMETRY=on
IAM_TELEMETRY_HOME=/var/lib/silicon-iam/telemetry
IAM_BIND_ADDR=0.0.0.0:8080
IAM_PUBLIC_BASE_URL=https://backend.iam.teamofsilicons.com
IAM_AUTH_BASE_URL=https://auth.iam.teamofsilicons.com
IAM_CORS_ALLOWED_ORIGINS=https://auth.iam.teamofsilicons.com,https://iam.teamofsilicons.com
IAM_DATABASE_URL=$API_DB_URL
IAM_TESTING_DATABASE_URL=$TESTING_API_DB_URL
IAM_TESTING_DATABASE_MAX_CONNECTIONS=4
IAM_TESTING_DATABASE_MIN_CONNECTIONS=0
IAM_DATABASE_MAX_CONNECTIONS=12
IAM_DATABASE_MIN_CONNECTIONS=1
IAM_DATABASE_ACQUIRE_TIMEOUT_SECONDS=3
IAM_DATABASE_STATEMENT_TIMEOUT_SECONDS=10
IAM_LOG_FILTER=silicon_iam=info,tower_http=info
IAM_ALLOW_LOCAL_PROVIDERS=false
IAM_EXPOSE_LOCAL_OTPS=false
EOF
printf '%s' "$APP_SECRET_JSON" | jq -r '
  [ "IAM_TOKEN_PEPPER_CURRENT_VERSION=" + .IAM_TOKEN_PEPPER_CURRENT_VERSION,
    "IAM_TOKEN_PEPPER_KEYRING=" + .IAM_TOKEN_PEPPER_KEYRING,
    "IAM_BLIND_INDEX_CURRENT_VERSION=" + .IAM_BLIND_INDEX_CURRENT_VERSION,
    "IAM_BLIND_INDEX_KEYRING=" + .IAM_BLIND_INDEX_KEYRING,
    "IAM_ENCRYPTION_CURRENT_VERSION=" + .IAM_ENCRYPTION_CURRENT_VERSION,
    "IAM_ENCRYPTION_KEYRING=" + .IAM_ENCRYPTION_KEYRING,
    "IAM_COOKIE_KEY=" + .IAM_COOKIE_KEY,
    "IAM_POSTMARK_SERVER_TOKEN=" + .IAM_POSTMARK_SERVER_TOKEN,
    "IAM_POSTMARK_FROM_EMAIL=" + .IAM_POSTMARK_FROM_EMAIL,
    "IAM_TWILIO_ACCOUNT_SID=" + .IAM_TWILIO_ACCOUNT_SID,
    "IAM_TWILIO_AUTH_TOKEN=" + .IAM_TWILIO_AUTH_TOKEN,
    "IAM_TWILIO_MESSAGING_SERVICE_SID=" + .IAM_TWILIO_MESSAGING_SERVICE_SID,
    "IAM_TWILIO_VERIFY_SERVICE_SID=" + .IAM_TWILIO_VERIFY_SERVICE_SID,
    "IAM_WORKOS_API_KEY=" + .IAM_WORKOS_API_KEY,
    "IAM_WORKOS_CLIENT_ID=" + .IAM_WORKOS_CLIENT_ID,
    "IAM_WORKOS_WEBHOOK_SECRET=" + .IAM_WORKOS_WEBHOOK_SECRET,
    "IAM_IRIS_BASE_URL=" + .IAM_IRIS_BASE_URL,
    "IAM_TELEMETRY_KEY=" + (.IAM_TELEMETRY_KEY // "") ] | .[]
' >> /etc/silicon-iam/api.env
printf '%s' "$APP_SECRET_JSON" | jq -r '
  to_entries[] | select(.key == "IAM_HONEYCOMB_APP_ID" or .key == "IAM_HONEYCOMB_CREDENTIAL_SHA256" or
    .key == "IAM_HONEYCOMB_RETIRE_LEGACY_WRITERS" or .key == "IAM_HONEYCOMB_SCHEDULED_TESTING") |
  .key + "=" + (.value | tostring)
' >> /etc/silicon-iam/api.env

cat > /etc/silicon-iam/worker.env <<EOF
IAM_ENVIRONMENT=production
IAM_TELEMETRY=on
IAM_TELEMETRY_HOME=/var/lib/silicon-iam/telemetry
IAM_AUTH_BASE_URL=https://auth.iam.teamofsilicons.com
IAM_DATABASE_URL=$WORKER_DB_URL
IAM_TESTING_DATABASE_URL=$TESTING_WORKER_DB_URL
IAM_TESTING_DATABASE_MAX_CONNECTIONS=2
IAM_TESTING_DATABASE_MIN_CONNECTIONS=0
IAM_DATABASE_MAX_CONNECTIONS=8
IAM_DATABASE_MIN_CONNECTIONS=1
IAM_DATABASE_ACQUIRE_TIMEOUT_SECONDS=3
IAM_DATABASE_STATEMENT_TIMEOUT_SECONDS=10
IAM_LOG_FILTER=silicon_iam=info
IAM_ALLOW_LOCAL_PROVIDERS=false
EOF
printf '%s' "$APP_SECRET_JSON" | jq -r '
  [ "IAM_ENCRYPTION_CURRENT_VERSION=" + .IAM_ENCRYPTION_CURRENT_VERSION,
    "IAM_ENCRYPTION_KEYRING=" + .IAM_ENCRYPTION_KEYRING,
    "IAM_POSTMARK_SERVER_TOKEN=" + .IAM_POSTMARK_SERVER_TOKEN,
    "IAM_POSTMARK_FROM_EMAIL=" + .IAM_POSTMARK_FROM_EMAIL,
    "IAM_TWILIO_ACCOUNT_SID=" + .IAM_TWILIO_ACCOUNT_SID,
    "IAM_TWILIO_AUTH_TOKEN=" + .IAM_TWILIO_AUTH_TOKEN,
    "IAM_TWILIO_MESSAGING_SERVICE_SID=" + .IAM_TWILIO_MESSAGING_SERVICE_SID,
    "IAM_IRIS_BASE_URL=" + .IAM_IRIS_BASE_URL,
    "IAM_TELEMETRY_KEY=" + (.IAM_TELEMETRY_KEY // "") ] | .[]
' >> /etc/silicon-iam/worker.env
printf '%s' "$APP_SECRET_JSON" | jq -r '
  to_entries[] | select(.key == "IAM_HONEYCOMB_APP_ID" or .key == "IAM_HONEYCOMB_NOTIFICATION_URL" or
    .key == "IAM_HONEYCOMB_NOTIFICATION_SIGNING_KEY" or .key == "IAM_HONEYCOMB_SCHEDULED_TESTING" or
    .key == "IAM_HONEYCOMB_RETIRE_LEGACY_WRITERS") | .key + "=" + (.value | tostring)
' >> /etc/silicon-iam/worker.env
chmod 0600 /etc/silicon-iam/api.env /etc/silicon-iam/worker.env

install -d -m 0700 -o 10001 -g 10001 /var/lib/silicon-iam/telemetry/api /var/lib/silicon-iam/telemetry/worker

cat > /etc/systemd/system/silicon-iam-api.service <<EOF
[Unit]
Description=Silicon IAM production API
Requires=docker.service
After=docker.service network-online.target

[Service]
Restart=always
RestartSec=5
TimeoutStopSec=45
ExecStartPre=-/usr/bin/docker rm -f silicon-iam-api
ExecStart=/usr/bin/docker run --name silicon-iam-api --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:size=16m,mode=1777 --volume /opt/silicon-iam/aws-rds-global-bundle.pem:/opt/silicon-iam/aws-rds-global-bundle.pem:ro --volume /var/lib/silicon-iam/telemetry/api:/var/lib/silicon-iam/telemetry --env-file /etc/silicon-iam/api.env --publish 8080:8080 --log-driver awslogs --log-opt awslogs-region=$REGION --log-opt awslogs-group=/silicon-iam/production/api --log-opt tag=api "$BACKEND_IMAGE" iam-api
ExecStop=/usr/bin/docker stop --time 35 silicon-iam-api

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/silicon-iam-worker.service <<EOF
[Unit]
Description=Silicon IAM production worker
Requires=docker.service
After=docker.service network-online.target silicon-iam-api.service

[Service]
Restart=always
RestartSec=5
TimeoutStopSec=315
ExecStartPre=-/usr/bin/docker rm -f silicon-iam-worker
ExecStart=/usr/bin/docker run --name silicon-iam-worker --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:size=16m,mode=1777 --volume /opt/silicon-iam/aws-rds-global-bundle.pem:/opt/silicon-iam/aws-rds-global-bundle.pem:ro --volume /var/lib/silicon-iam/telemetry/worker:/var/lib/silicon-iam/telemetry --env-file /etc/silicon-iam/worker.env --log-driver awslogs --log-opt awslogs-region=$REGION --log-opt awslogs-group=/silicon-iam/production/worker --log-opt tag=worker "$BACKEND_IMAGE" iam-worker
ExecStop=/usr/bin/docker stop --time 310 silicon-iam-worker

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now silicon-iam-api silicon-iam-worker

if [[ "$DIRECT_NGINX" == true ]]; then
  # Install the optional authentication helper in both existing database planes.
  docker run --rm --network host --read-only --cap-drop ALL \
    --security-opt no-new-privileges --tmpfs /tmp:size=16m,mode=1777 \
    --volume /opt/silicon-iam/aws-rds-global-bundle.pem:/opt/silicon-iam/aws-rds-global-bundle.pem:ro \
    --env IAM_ENVIRONMENT=production --env IAM_TELEMETRY=off \
    --env IAM_MIGRATOR_DATABASE_URL="$MIGRATOR_DATABASE_URL" \
    --env IAM_TESTING_MIGRATOR_DATABASE_URL="$TESTING_MIGRATOR_DATABASE_URL" \
    "$BACKEND_IMAGE" iam-scoped-auth-init
  SCOPED_KEYRING=$(aws secretsmanager get-secret-value --region "$REGION" \
    --secret-id "$SCOPED_WEBHOOK_SECRET_ARN" --query SecretString --output text)
  printf '%s' "$SCOPED_KEYRING" | jq -e 'type == "object" and length > 0' >/dev/null
  printf 'IAM_SCOPED_WEBHOOK_KEYRING=%s\n' "$(printf '%s' "$SCOPED_KEYRING" | jq -c .)" \
    > /etc/silicon-iam/scoped-webhook.env
  chmod 0600 /etc/silicon-iam/scoped-webhook.env
  unset SCOPED_KEYRING
  bash /opt/silicon-iam/scoped/install.sh --image "$BACKEND_IMAGE"
  for port in 8080 8081; do
    ready=false
    for attempt in $(seq 1 40); do
      if curl --fail --silent --max-time 3 "http://127.0.0.1:$port/readyz" >/dev/null; then
        ready=true; break
      fi
      sleep 2
    done
    "$ready"
  done
  python3 /opt/silicon-iam/provisioning/direct-ingress.py recover
fi
