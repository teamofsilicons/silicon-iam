#!/usr/bin/env python3
"""Upgrade disposable production and testing databases using a local PostgreSQL 16+.

Creates/drops only fresh databases and restricted migration roles with a random
iam_identity_upgrade_ prefix. Migrations run as the database/table owner with
NOSUPERUSER NOBYPASSRLS, matching the deployed migration boundary.
No Docker or third-party Python packages are required. The admin connection must
be allowed to create databases and IAM's NOLOGIN runtime roles.

Example: python3 scripts/test-canonical-identity-migration.py \
    --admin-url postgres://postgres@localhost:55471/postgres
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import uuid
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin-url", default=os.environ.get("IAM_MIGRATION_TEST_ADMIN_URL"))
    parser.add_argument("--psql", default="psql")
    parser.add_argument("--keep-databases", action="store_true", help="retain failed fixtures for debugging")
    args = parser.parse_args()
    if not args.admin_url:
        parser.error("--admin-url or IAM_MIGRATION_TEST_ADMIN_URL is required")
    parsed = urlsplit(args.admin_url)
    if parsed.scheme not in ("postgres", "postgresql"):
        parser.error("admin URL must use postgres:// or postgresql://")

    def run(database, sql):
        url = urlunsplit(parsed._replace(path="/" + database)) if database else args.admin_url
        result = subprocess.run([args.psql, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", url],
                                input=sql, text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError(result.stderr[-16000:] + result.stdout[-2000:])
        return result.stdout

    def include(path):
        # psql handles SQL literal quoting for include paths, including spaces.
        return "\\i '" + str(path).replace("'", "''") + "'\n"

    base = sorted(ROOT.joinpath("migrations").glob("*.sql"))
    overlays = sorted(ROOT.joinpath("migrations/testing").glob("*.sql"))
    before = [p for p in base if int(p.name.split("_")[0]) <= 110]
    after = [p for p in base if int(p.name.split("_")[0]) > 110]
    tokens = ROOT.joinpath("src/infrastructure/postgres/tokens.rs").read_text()
    authenticate = tokens.split("let row = sqlx::query_as::<_, AccessRow>(", 1)[1]
    authenticate = re.search(r'r"(.*?)",', authenticate, re.S).group(1)
    candidate = tokens.split("async fn find_candidate(", 1)[1]
    candidate = re.search(r'r"(.*?)",', candidate, re.S).group(1)
    candidate = candidate.replace("$1", "ARRAY[1]::smallint[]").replace("$2", "ARRAY[decode(repeat(lpad(to_hex(plane+20),2,'0'),32),'hex')]").replace("$3", "'application_access'")
    authenticate = authenticate.replace("$1", "pg_temp.fixture_id(plane,'access')").replace("$2", "'application_access'")
    assertion = ROOT.joinpath("tests/sql/canonical_identity_upgrade_assert.sql").read_text()
    assertion = assertion.replace("/* ACCESS_CANDIDATE_QUERY */", candidate).replace("/* AUTHENTICATE_QUERY */", authenticate)
    run(None, "DO $$ BEGIN FOR n IN SELECT unnest(ARRAY['silicon_iam_api','silicon_iam_worker','silicon_iam_key_operator']) LOOP IF to_regrole(n) IS NULL THEN EXECUTE format('CREATE ROLE %I NOLOGIN',n); END IF; END LOOP; END $$;".replace("BEGIN FOR n", "DECLARE n text; BEGIN FOR n"))
    run(None, "DO $$ BEGIN IF to_regrole('silicon_iam_testing_definer') IS NULL THEN CREATE ROLE silicon_iam_testing_definer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF; END $$;")
    created = []
    try:
        for testing in (False, True):
            database = "iam_identity_upgrade_" + ("test_" if testing else "prod_") + uuid.uuid4().hex[:12]
            run(None, 'CREATE ROLE "' + database + '" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; GRANT silicon_iam_testing_definer TO "' + database + '" WITH ADMIN OPTION;')
            run(None, 'CREATE DATABASE "' + database + '" OWNER "' + database + '";')
            created.append(database)
            print("Testing " + database, flush=True)
            sql = "SET client_min_messages=warning;\nSET SESSION AUTHORIZATION \"" + database + "\";\n"
            # A small SQLx ledger stub is sufficient for runtime grant validation.
            sql += "CREATE TABLE public._sqlx_migrations(version bigint);\n"
            for path in before + ([p for p in overlays if int(p.name.split('_')[0]) <= 9013] if testing else []):
                sql += "BEGIN;\n" + include(path) + "COMMIT;\n"
            sql += "RESET SESSION AUTHORIZATION;\n"
            sql += include(ROOT / "tests/sql/canonical_identity_upgrade_seed.sql")
            planes = (2, 3) if testing else (1,)
            for plane in planes:
                sql += f"BEGIN; SELECT pg_temp.seed_identity_upgrade({plane},{str(testing).lower()}); COMMIT;\n"
            sql += include(ROOT / "tests/sql/canonical_identity_upgrade_security.sql")
            sql += "SET SESSION AUTHORIZATION \"" + database + "\";\n"
            for path in after + ([p for p in overlays if int(p.name.split('_')[0]) > 9013] if testing else []):
                sql += "BEGIN;\n" + include(path) + "COMMIT;\n"
                if int(path.name.split('_')[0]) == 111:
                    sql += "RESET SESSION AUTHORIZATION; SELECT pg_temp.assert_identity_migration_security(); SET SESSION AUTHORIZATION \"" + database + "\";\n"
            if testing:
                sql += "SELECT iam_private.reconcile_testing_environment_security();\n"
            sql += include(ROOT / "deploy/postgres/runtime-grants.sql")
            sql += "RESET SESSION AUTHORIZATION;\n"
            sql += assertion
            for plane in planes:
                sql += f"BEGIN; SELECT pg_temp.assert_identity_upgrade({plane},{str(testing).lower()}); ROLLBACK;\n"
            sql += "BEGIN; SET LOCAL SESSION AUTHORIZATION silicon_iam_api; SELECT pg_temp.assert_unscoped_metadata(" + str(len(planes)) + "," + str(testing).lower() + "); ROLLBACK;\n"
            run(database, sql)
            print("Passed migration, credential, profile, history, grants and isolation assertions", flush=True)
    finally:
        if not args.keep_databases:
            for database in created:
                run(None, 'DROP DATABASE "' + database + '" WITH (FORCE);')
                run(None, 'DROP ROLE "' + database + '";')
        else:
            print("Retained: " + ", ".join(created))

if __name__ == "__main__":
    main()
