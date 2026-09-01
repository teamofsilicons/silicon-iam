#!/bin/sh

set -eu

: "${IAM_LOCAL_API_DATABASE_PASSWORD:?IAM_LOCAL_API_DATABASE_PASSWORD is required}"
: "${IAM_LOCAL_WORKER_DATABASE_PASSWORD:?IAM_LOCAL_WORKER_DATABASE_PASSWORD is required}"
: "${IAM_LOCAL_KEY_OPERATOR_DATABASE_PASSWORD:?IAM_LOCAL_KEY_OPERATOR_DATABASE_PASSWORD is required}"

psql \
    --set=ON_ERROR_STOP=1 \
    --set=api_password="${IAM_LOCAL_API_DATABASE_PASSWORD}" \
    --set=worker_password="${IAM_LOCAL_WORKER_DATABASE_PASSWORD}" \
    --set=key_operator_password="${IAM_LOCAL_KEY_OPERATOR_DATABASE_PASSWORD}" \
    --username "${POSTGRES_USER}" \
    --dbname "${POSTGRES_DB}" <<'SQL'
CREATE ROLE silicon_iam_api
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;

CREATE ROLE silicon_iam_worker
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;

CREATE ROLE silicon_iam_key_operator
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;

CREATE ROLE silicon_iam_api_runtime
    LOGIN
    PASSWORD :'api_password'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS
    IN ROLE silicon_iam_api;

CREATE ROLE silicon_iam_worker_runtime
    LOGIN
    PASSWORD :'worker_password'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS
    IN ROLE silicon_iam_worker;

CREATE ROLE silicon_iam_key_operator_runtime
    LOGIN
    PASSWORD :'key_operator_password'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS
    IN ROLE silicon_iam_key_operator;
SQL
