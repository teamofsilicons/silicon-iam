#!/usr/bin/env python3
"""Exercise 0118 in disposable PostgreSQL 16+ production and testing databases.

Requires a local admin URL; creates only randomly named iam_public_ids_* databases
and migrators. Each migration runs as a NOSUPERUSER NOBYPASSRLS database owner.
"""
import argparse
import os
from pathlib import Path
import subprocess
import uuid
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admin-url', default=os.getenv('IAM_MIGRATION_TEST_ADMIN_URL'))
    parser.add_argument('--psql', default='psql')
    args = parser.parse_args()
    if not args.admin_url:
        parser.error('--admin-url is required')
    parsed = urlsplit(args.admin_url)

    def run(sql, database=None, expect_error=None):
        url = urlunsplit(parsed._replace(path='/' + database)) if database else args.admin_url
        result = subprocess.run([args.psql, '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-d', url], input=sql, text=True, capture_output=True)
        if expect_error:
            assert result.returncode and expect_error in result.stderr, result.stderr
        elif result.returncode:
            raise RuntimeError(result.stderr[-14000:])
        return result.stdout

    def include(path):
        return "\\i '" + str(path).replace("'", "''") + "'\n"

    run("DO $$ DECLARE n text; BEGIN FOREACH n IN ARRAY ARRAY['silicon_iam_api','silicon_iam_worker','silicon_iam_key_operator'] LOOP IF to_regrole(n) IS NULL THEN EXECUTE format('CREATE ROLE %I NOLOGIN',n); END IF; END LOOP; IF to_regrole('silicon_iam_testing_definer') IS NULL THEN CREATE ROLE silicon_iam_testing_definer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF; END $$;")
    base = sorted(ROOT.joinpath('migrations').glob('*.sql'))
    overlays = sorted(ROOT.joinpath('migrations/testing').glob('*.sql'))
    for testing in (False, True):
        name = 'iam_public_ids_' + uuid.uuid4().hex[:12]
        try:
            run(f'CREATE ROLE {name} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; GRANT silicon_iam_testing_definer TO {name} WITH ADMIN OPTION;')
            run(f'CREATE DATABASE {name} OWNER {name};')
            sql = f'SET SESSION AUTHORIZATION {name}; SET client_min_messages=warning; CREATE TABLE public._sqlx_migrations(version bigint);\n'
            before = [p for p in base if int(p.name[:4]) < 111]
            if testing:
                before += [p for p in overlays if int(p.name[:4]) < 9014]
            for path in before:
                sql += 'BEGIN;\n' + include(path) + 'COMMIT;\n'
            sql += 'RESET SESSION AUTHORIZATION;\n' + include(ROOT/'tests/sql/canonical_identity_upgrade_seed.sql')
            planes = (2, 3) if testing else (1,)
            for plane in planes:
                sql += f'BEGIN; SELECT pg_temp.seed_identity_upgrade({plane},{str(testing).lower()}); COMMIT;\n'
            sql += f'SET SESSION AUTHORIZATION {name};\n'
            for path in [p for p in base if 111 <= int(p.name[:4]) < 118] + ([p for p in overlays if int(p.name[:4]) >= 9014] if testing else []):
                sql += 'BEGIN;\n' + include(path) + 'COMMIT;\n'
            run(sql, name)
            # Check the new names cannot silently collapse across organizations.
            # Insert a second old app with the same local handle; no credentials.
            collision_scope = "SELECT set_config('iam.testing_environment_id',md5('canonical-migration/2/environment')::uuid::text,true);" if testing else ''
            collision = f'''BEGIN; {collision_scope}
INSERT INTO iam.principals(id,kind,status,activated_at) VALUES('other-org>app','application','active',now());
INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,review_status)
SELECT 'other-org>app','other-org>app',organization_id,created_by_carbon_id,'verified' FROM iam.applications WHERE app_id='identity-test>app' LIMIT 1;
COMMIT;'''
            run(collision, name)
            run(f'SET SESSION AUTHORIZATION {name}; BEGIN;\n'+include(ROOT/'migrations/0118_prefixed_public_identifiers.sql')+'COMMIT;', name, 'duplicate key value violates unique constraint')
            assert run("SELECT to_regclass('iam_private.public_id_schema_map') IS NULL;", name).strip() == 't'
            run(f"BEGIN; {collision_scope} DELETE FROM iam.applications WHERE app_id='other-org>app'; DELETE FROM iam.principals WHERE id='other-org>app'; COMMIT;", name)
            run(f'SET SESSION AUTHORIZATION {name}; BEGIN;\n'+include(ROOT/'migrations/0118_prefixed_public_identifiers.sql')+'COMMIT;\n', name)
            assert run("SELECT count(*) FROM iam.carbons WHERE id='c:migration-owner' AND carbon_id=id;", name).strip() == str(len(planes))
            assert run("SELECT count(*) FROM iam.silicons WHERE id='si:migration' AND global_silicon_id=id;", name).strip() == str(len(planes))
            assert run("SELECT count(*) FROM iam.applications WHERE id='app' AND app_id=id;", name).strip() == str(len(planes))
            assert run("SELECT count(*) FROM iam_private.membership_identifiers WHERE membership_id IN ('c:migration-owner[identity-test]','si:migration[identity-test]');", name).strip() == str(2*len(planes))
            assert run("SELECT count(*) FROM iam.access_tokens WHERE subject_principal_id='si:migration' AND client_application_id='app' AND audience_application_id='app' AND audience='app' AND revoked_at IS NULL;", name).strip() == str(len(planes))
            assert run("SELECT count(*) FROM iam.application_webhook_endpoints WHERE application_id='app' AND url_ciphertext=decode(repeat('04',17),'hex');", name).strip() == str(len(planes))
            assert run("SELECT count(*) FROM iam.outbox_events WHERE aggregate_type='silicon' AND aggregate_id='si:migration' AND payload->'actor'->>'id'='si:migration' AND payload->>'application_id'='app';", name).strip() == str(len(planes))
            assert run("SELECT count(*) FROM iam_private.public_id_application_contexts WHERE application_id='app' AND context_id='identity-test>app';", name).strip() == str(len(planes))
            # Runtime grants must explicitly keep AAD readers and forbid alias-map access.
            run(include(ROOT/'deploy/postgres/runtime-grants.sql'),name)
            assert run("SELECT has_function_privilege('silicon_iam_api','iam_private.public_id_application_contexts()','EXECUTE') AND NOT has_table_privilege('silicon_iam_api','iam_private.public_id_schema_map','SELECT');",name).strip()=='t'
            if testing:
                run(f'SET SESSION AUTHORIZATION {name}; SELECT iam_private.reconcile_testing_environment_security();', name)
                assert run(include(ROOT/'src/infrastructure/postgres/testing_security.sql'), name).strip() == 't'
            print(('testing (two worlds)' if testing else 'production') + ': collision rollback, identifiers, UUID resources, session references, ciphertext and runtime permissions PASS', flush=True)
        finally:
            run(f'DROP DATABASE IF EXISTS {name} WITH (FORCE);')
            run(f'DROP ROLE IF EXISTS {name};')


if __name__ == '__main__':
    main()
