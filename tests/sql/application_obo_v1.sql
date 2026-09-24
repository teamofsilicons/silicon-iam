-- Run only against a disposable migrated database. Every fixture is rolled back.
BEGIN;
INSERT INTO iam.cryptographic_key_versions (purpose, key_version, status)
        VALUES ('token_hmac', 1, 'active'), ('contact_aead', 1, 'active');
INSERT INTO iam.principals (id, kind, status, activated_at) VALUES
          ('c:test_carbon', 'carbon', 'active', transaction_timestamp()),
          ('c:test_admin', 'carbon', 'active', transaction_timestamp()),
          ('app-alpha', 'application', 'active', transaction_timestamp()),
          ('app-beta', 'application', 'active', transaction_timestamp());
INSERT INTO iam.carbons (id, carbon_id, display_name) VALUES
          ('c:test_carbon', 'c:test_carbon', 'Test Carbon'),
          ('c:test_admin', 'c:test_admin', 'Test Admin');
INSERT INTO iam.carbon_contacts (
            id, carbon_id, kind, ciphertext, nonce, encryption_key_version, verified_at
        ) VALUES
          ('00000000-0000-0000-0000-000000000002',
           'c:test_carbon', 'email',
           decode(repeat('02', 17), 'hex'), decode(repeat('12', 12), 'hex'), 1,
           transaction_timestamp()),
          ('00000000-0000-0000-0000-000000000003',
           'c:test_carbon', 'phone',
           decode(repeat('03', 17), 'hex'), decode(repeat('13', 12), 'hex'), 1,
           transaction_timestamp()),
          ('00000000-0000-0000-0000-000000000004',
           'c:test_admin', 'email',
           decode(repeat('04', 17), 'hex'), decode(repeat('14', 12), 'hex'), 1,
           transaction_timestamp()),
          ('00000000-0000-0000-0000-000000000005',
           'c:test_admin', 'phone',
           decode(repeat('05', 17), 'hex'), decode(repeat('15', 12), 'hex'), 1,
           transaction_timestamp());
INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name)
        VALUES ('00000000-0000-0000-0000-000000000021', 'test_org',
                'c:test_carbon', 'Test Organization');
INSERT INTO iam.organization_memberships (
            id, organization_id, principal_id, principal_kind, org_role,
            job_role, role_granted_by_membership_id
        ) VALUES (
            '00000000-0000-0000-0000-000000000031',
            '00000000-0000-0000-0000-000000000021',
            'c:test_carbon', 'carbon', 'owner', '', NULL
        ), (
            '00000000-0000-0000-0000-000000000032',
            '00000000-0000-0000-0000-000000000021',
            'c:test_admin', 'carbon', 'admin', '',
            '00000000-0000-0000-0000-000000000031'
        );
INSERT INTO iam.applications (
            id, app_id, organization_id, created_by_carbon_id, review_status, base_url
        ) VALUES
          ('app-alpha', 'app-alpha',
           '00000000-0000-0000-0000-000000000021',
           'c:test_carbon', 'verified',
           'https://alpha.example.test/api'),
          ('app-beta', 'app-beta',
           '00000000-0000-0000-0000-000000000021',
           'c:test_carbon', 'verified',
           'https://beta.example.test/api');
INSERT INTO iam.application_secrets (
            id, application_id, secret_version, secret_prefix, secret_digest,
            pepper_key_version, created_by_carbon_id
        ) VALUES (
            '00000000-0000-0000-0000-000000000131',
            'app-alpha', 1, 'ask_abcdefgh',
            decode(repeat('13', 32), 'hex'), 1,
            'c:test_carbon'
        );
INSERT INTO iam.application_webhook_endpoints (
            id, application_id, url_ciphertext, url_nonce, encryption_key_version,
            url_digest, status, activated_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000141',
            'app-alpha',
            decode(repeat('41', 17), 'hex'), decode(repeat('42', 12), 'hex'), 1,
            decode(repeat('43', 32), 'hex'), 'active', transaction_timestamp()
        );
INSERT INTO iam.application_webhook_signing_keys (
            id, application_id, endpoint_id, secret_version, key_prefix,
            secret_ciphertext, secret_nonce, encryption_key_version
        ) VALUES (
            '00000000-0000-0000-0000-000000000142',
            'app-alpha',
            '00000000-0000-0000-0000-000000000141', 1, 'whs_abcdefgh',
            decode(repeat('44', 17), 'hex'), decode(repeat('45', 12), 'hex'), 1
        );
INSERT INTO iam.authentication_sessions (
            id, subject_principal_id, subject_kind, authentication_method,
            assurance_level, subject_auth_epoch, idle_expires_at, absolute_expires_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000041',
            'c:test_carbon', 'carbon', 'email_otp', 1, 1,
            transaction_timestamp() + interval '1 day',
            transaction_timestamp() + interval '2 days'
        );
INSERT INTO iam.oauth_consent_grants (
            id, application_id, subject_principal_id, subject_kind,
            parent_authentication_session_id, selected_membership_ids
        ) VALUES (
            '00000000-0000-0000-0000-000000000071',
            'app-alpha',
            'c:test_carbon', 'carbon',
            '00000000-0000-0000-0000-000000000041',
            ARRAY['00000000-0000-0000-0000-000000000031'::uuid]
        );
INSERT INTO iam.oauth_consent_grants (
            id, application_id, subject_principal_id, subject_kind,
            organization_id, membership_id, parent_authentication_session_id,
            selected_membership_ids
        ) VALUES (
            '00000000-0000-0000-0000-000000000072',
            'app-alpha',
            'c:test_carbon', 'carbon',
            '00000000-0000-0000-0000-000000000021',
            '00000000-0000-0000-0000-000000000031',
            '00000000-0000-0000-0000-000000000041',
            ARRAY['00000000-0000-0000-0000-000000000031'::uuid]
        );
INSERT INTO iam.access_tokens (
            id, token_class, token_digest, digest_key_version, token_prefix,
            authentication_session_id, subject_principal_id, subject_kind,
            client_application_id, audience, audience_application_id,
            subject_auth_epoch, client_auth_epoch, expires_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000101', 'application_access',
            decode(repeat('10', 32), 'hex'), 1, 'oat_abcdefgh',
            '00000000-0000-0000-0000-000000000041',
            'c:test_carbon', 'carbon',
            'app-alpha', 'app-alpha',
            'app-alpha', 1, 1,
            transaction_timestamp() + interval '15 minutes'
        );
INSERT INTO iam.access_tokens (
            id, token_class, token_digest, digest_key_version, token_prefix,
            authentication_session_id, subject_principal_id, subject_kind,
            client_application_id, audience, audience_application_id,
            organization_id, membership_id, subject_auth_epoch,
            membership_authz_epoch, client_auth_epoch, expires_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000102', 'application_access',
            decode(repeat('12', 32), 'hex'), 1, 'oat_ijklmnop',
            '00000000-0000-0000-0000-000000000041',
            'c:test_carbon', 'carbon',
            'app-alpha', 'app-alpha',
            'app-alpha',
            '00000000-0000-0000-0000-000000000021',
            '00000000-0000-0000-0000-000000000031', 1, 1, 1,
            transaction_timestamp() + interval '15 minutes'
        );
INSERT INTO iam.access_tokens (
            id, token_class, token_digest, digest_key_version, token_prefix,
            authentication_session_id, subject_principal_id, subject_kind,
            client_application_id, audience, audience_application_id,
            subject_auth_epoch, client_auth_epoch, expires_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000103', 'application_access',
            decode(repeat('14', 32), 'hex'), 1, 'oat_qrstuvwx',
            '00000000-0000-0000-0000-000000000041',
            'c:test_carbon', 'carbon',
            'app-beta', 'app-beta',
            'app-beta', 1, 1,
            transaction_timestamp() + interval '15 minutes'
        );
INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name) VALUES
('00000000-0000-0000-0000-000000000023','other_org','c:test_admin','Other Organization');
INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role) VALUES
('00000000-0000-0000-0000-000000000033','00000000-0000-0000-0000-000000000023','c:test_admin','carbon','owner');
INSERT INTO iam.principals(id,kind,status,activated_at) VALUES('target','application','active',now());
INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,base_url,review_status) VALUES
('target','target','00000000-0000-0000-0000-000000000023','c:test_admin','https://example.test','verified');
INSERT INTO iam.application_obo_endpoints(organization_id,application_id,endpoint_id,path,metadata_definition,critical) VALUES
('00000000-0000-0000-0000-000000000023','target','files.read','/files','{}',false);
UPDATE iam.applications SET app_scope='{"iam":["self.identity.read"],"external":[{"app_id":"target","endpoint_id":"files.read"}]}'
WHERE id='app-alpha';
INSERT INTO iam.oauth_scope_catalog(scope,description) VALUES('obo:target:files.read','Read files');
INSERT INTO iam.application_requested_scopes(application_id,scope) VALUES('app-alpha','obo:target:files.read');
INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES
('app-alpha','obo:target:files.read','c:test_carbon');
INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES('00000000-0000-0000-0000-000000000101','obo:target:files.read');
INSERT INTO iam.oauth_consent_grant_scopes(consent_grant_id,scope) VALUES('00000000-0000-0000-0000-000000000071','obo:target:files.read');
SET LOCAL ROLE silicon_iam_api;
SELECT set_config('iam.principal_id','app-alpha',true),set_config('iam.application_id','app-alpha',true),set_config('iam.organization_id','00000000-0000-0000-0000-000000000021',true);
DO $$ BEGIN
IF EXISTS(SELECT * FROM iam_private.lock_current_application_obo_exchange_authority('app-alpha',1,'00000000-0000-0000-0000-000000000103','c:test_carbon','carbon','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000031','target','files.read')) THEN RAISE EXCEPTION 'another app subject token accepted'; END IF;
IF (SELECT count(*) FROM iam_private.discover_application_obo_endpoints('target')) <> 1 THEN RAISE EXCEPTION 'cross org discovery failed'; END IF;
IF (SELECT count(*) FROM iam_private.resolve_application_obo_memberships('00000000-0000-0000-0000-000000000101','c:test_carbon',NULL)) <> 1 THEN RAISE EXCEPTION 'subject org resolver failed'; END IF;
IF (SELECT count(*) FROM iam_private.lock_current_application_obo_exchange_authority('app-alpha',1,'00000000-0000-0000-0000-000000000101','c:test_carbon','carbon','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000031','target','files.read')) <> 1 THEN RAISE EXCEPTION 'cross org exchange failed'; END IF;
END $$;
SELECT set_config('iam.principal_id','c:test_carbon',true);
INSERT INTO iam.obo_proofs(id,proof_digest,digest_key_version,proof_prefix,issuer_application_id,audience_application_id,subject_principal_id,subject_kind,organization_id,membership_id,parent_access_token_id,endpoint_id,request_metadata,endpoint_version,request_method,request_path,request_body_sha256,request_signed_at,subject_auth_epoch,membership_authz_epoch,issuer_auth_epoch,audience_auth_epoch,expires_at)
VALUES('00000000-0000-0000-0000-000000000123',decode(repeat('39',32),'hex'),1,'obo_abcdefgh','app-alpha','target','c:test_carbon','carbon','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000031','00000000-0000-0000-0000-000000000101','files.read','{}',1,'POST','/files',decode(repeat('00',32),'hex'),now(),1,1,1,1,now()+interval '300 seconds');
-- Exercise the configured default, a storage endpoint lifetime and i32 bounds.
RESET ROLE;
DO $$ DECLARE lifetime bigint; BEGIN
 FOREACH lifetime IN ARRAY ARRAY[1::bigint,300,3600,2147483647] LOOP
  UPDATE iam.obo_proofs SET expires_at=created_at+make_interval(secs=>lifetime::double precision)
   WHERE id='00000000-0000-0000-0000-000000000123';
 END LOOP;
 FOREACH lifetime IN ARRAY ARRAY[-1::bigint,0,2147483648] LOOP
  BEGIN
   UPDATE iam.obo_proofs SET expires_at=created_at+make_interval(secs=>lifetime::double precision)
    WHERE id='00000000-0000-0000-0000-000000000123';
   RAISE EXCEPTION 'invalid proof lifetime accepted: %',lifetime;
  EXCEPTION WHEN check_violation THEN NULL;
  END;
 END LOOP;
 UPDATE iam.obo_proofs SET expires_at=created_at+interval '300 seconds'
  WHERE id='00000000-0000-0000-0000-000000000123';
END $$;
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
IF NOT iam_private.application_obo_exchange_replay_is_live('00000000-0000-0000-0000-000000000123','app-alpha','00000000-0000-0000-0000-000000000021') THEN RAISE EXCEPTION 'live replay failed'; END IF;
END $$;
SELECT set_config('iam.application_id','target',true),set_config('iam.principal_id','target',true);
DO $$ BEGIN
IF (SELECT count(*) FROM iam_private.lookup_application_obo_proof(ARRAY[1]::smallint[],ARRAY[decode(repeat('39',32),'hex')],'target'))<>1 THEN RAISE EXCEPTION 'cross org proof lookup failed'; END IF;
END $$;
SELECT set_config('iam.principal_id','c:test_carbon',true);
DO $$ DECLARE result jsonb; BEGIN
SELECT iam_private.get_current_application_authorization('00000000-0000-0000-0000-000000000101','c:test_carbon','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000031','target',1,'00000000-0000-0000-0000-000000000123') INTO result;
IF result IS NULL OR result->'scopes' <> '["obo:target:files.read"]'::jsonb OR result->>'org_role' IS NOT NULL OR result->>'tags' IS NOT NULL THEN RAISE EXCEPTION 'cross org authorization data isolation failed: %',result; END IF;
END $$;
RESET ROLE;
DELETE FROM iam.oauth_consent_grant_scopes WHERE consent_grant_id='00000000-0000-0000-0000-000000000071' AND scope='obo:target:files.read';
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
IF iam_private.get_current_application_authorization('00000000-0000-0000-0000-000000000101','c:test_carbon','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000031','target',1,'00000000-0000-0000-0000-000000000123') IS NOT NULL THEN RAISE EXCEPTION 'revoked consent remained usable'; END IF;
END $$;
RESET ROLE;
SELECT set_config('iam.principal_id','app-alpha',true),set_config('iam.application_id','app-alpha',true);
SET LOCAL ROLE silicon_iam_api;
DO $$ DECLARE created_org text; BEGIN
SELECT iam_private.create_application_testing_environment('00000000-0000-0000-0000-00000000a006','Application sandbox',NULL,decode(repeat('61',32),'hex'),1::smallint,decode(repeat('62',17),'hex'),decode(repeat('63',12),'hex'),1::smallint,10) INTO created_org;
IF created_org <> 'test_org' THEN RAISE EXCEPTION 'application environment owner mismatch'; END IF;
PERFORM iam_private.link_application_testing_environment('00000000-0000-0000-0000-00000000a006','app-alpha','app-alpha');
IF (SELECT count(*) FROM iam_private.list_application_testing_environments(NULL,25,'active'))<>1 THEN RAISE EXCEPTION 'app environment not listed'; END IF;
IF (SELECT version FROM iam_private.lock_application_testing_environment('00000000-0000-0000-0000-00000000a006'))<>1 THEN RAISE EXCEPTION 'environment not reusable'; END IF;
END $$;
SELECT set_config('iam.principal_id','target',true),set_config('iam.application_id','target',true);
DO $$ BEGIN
IF EXISTS(SELECT * FROM iam_private.list_application_testing_environments(NULL,25,'active')) THEN RAISE EXCEPTION 'application environment leaked across organizations'; END IF;
IF EXISTS(SELECT * FROM iam_private.lock_application_testing_environment('00000000-0000-0000-0000-00000000a006')) THEN RAISE EXCEPTION 'cross organization environment reuse accepted'; END IF;
END $$;

RESET ROLE;
SELECT set_config('iam.principal_id','app-alpha',true),
       set_config('iam.application_id','app-alpha',true),
       set_config('iam.organization_id','00000000-0000-0000-0000-000000000021',true);
SET LOCAL ROLE silicon_iam_api;
SELECT iam_private.create_application_testing_environment('00000000-0000-0000-0000-000000000991','Owner lifecycle',NULL,decode(repeat('91',32),'hex'),1::smallint,decode(repeat('92',32),'hex'),decode(repeat('93',12),'hex'),1::smallint,10);
SELECT iam_private.link_application_testing_environment('00000000-0000-0000-0000-000000000991','app-beta','app-beta');
DO $$ BEGIN
 IF NOT iam_private.is_application_testing_environment_administrator('00000000-0000-0000-0000-000000000991') THEN RAISE EXCEPTION 'creator not authorized'; END IF;
 IF (SELECT count(*) FROM iam.testing_environments WHERE id='00000000-0000-0000-0000-000000000991') <> 1 THEN RAISE EXCEPTION 'owner cannot read'; END IF;
END $$;
SELECT set_config('iam.principal_id','app-beta',true),
       set_config('iam.application_id','app-beta',true);
DO $$ BEGIN
 IF iam_private.is_application_testing_environment_administrator('00000000-0000-0000-0000-000000000991') THEN RAISE EXCEPTION 'dependency gained authority'; END IF;
 IF EXISTS(SELECT 1 FROM iam.testing_environments WHERE id='00000000-0000-0000-0000-000000000991') THEN RAISE EXCEPTION 'dependency can read secret-bearing row'; END IF;
 UPDATE iam.testing_environments SET name='Compromised' WHERE id='00000000-0000-0000-0000-000000000991';
 IF FOUND THEN RAISE EXCEPTION 'dependency can mutate'; END IF;
 IF NOT EXISTS(SELECT 1 FROM iam_private.list_application_testing_environments(NULL,10,'active') WHERE environment_id='00000000-0000-0000-0000-000000000991' AND can_manage=false) THEN RAISE EXCEPTION 'linked environment incorrectly listed'; END IF;
END $$;
RESET ROLE;
ROLLBACK;
