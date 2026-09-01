#!/bin/sh

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_directory=$(dirname -- "${script_directory}")
template_path="${project_directory}/.env.example"
output_path="${project_directory}/.env"

if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required to generate local secrets" >&2
    exit 1
fi

if [ -e "${output_path}" ]; then
    echo "${output_path} already exists; refusing to overwrite it" >&2
    exit 1
fi

random_urlsafe() {
    openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'
}

token_pepper=$(random_urlsafe)
blind_index_key=$(random_urlsafe)
encryption_key=$(random_urlsafe)
cookie_key=$(random_urlsafe)
jwt_seed=$(random_urlsafe)
migrator_database_password=$(random_urlsafe)
api_database_password=$(random_urlsafe)
worker_database_password=$(random_urlsafe)
key_operator_database_password=$(random_urlsafe)

temporary_path=$(mktemp "${output_path}.tmp.XXXXXX")
trap 'rm -f "${temporary_path}"' EXIT HUP INT TERM

umask 077
sed \
    -e "s#<base64url-32-byte-token-pepper>#${token_pepper}#g" \
    -e "s#<base64url-32-byte-blind-index-key>#${blind_index_key}#g" \
    -e "s#<base64url-32-byte-encryption-key>#${encryption_key}#g" \
    -e "s#<base64url-32-byte-cookie-key>#${cookie_key}#g" \
    -e "s#<base64url-32-byte-ed25519-seed>#${jwt_seed}#g" \
    -e "s#<local-migrator-db-password>#${migrator_database_password}#g" \
    -e "s#<local-api-db-password>#${api_database_password}#g" \
    -e "s#<local-worker-db-password>#${worker_database_password}#g" \
    -e "s#<local-key-operator-db-password>#${key_operator_database_password}#g" \
    "${template_path}" >"${temporary_path}"

mv "${temporary_path}" "${output_path}"
trap - EXIT HUP INT TERM
chmod 600 "${output_path}"

echo "Created ${output_path} with independent local-only secrets."
