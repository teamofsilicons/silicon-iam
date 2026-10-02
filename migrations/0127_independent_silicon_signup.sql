-- Silicon identity exists independently of an organization. Historical home
-- bindings remain immutable for existing credentials and membership routes.
ALTER TABLE iam.silicons ALTER COLUMN organization_id DROP NOT NULL,
 ALTER COLUMN membership_id DROP NOT NULL, ALTER COLUMN organization_handle DROP NOT NULL;
ALTER TABLE iam.silicons ADD CONSTRAINT silicon_home_binding_shape CHECK (
 (organization_id IS NULL AND membership_id IS NULL AND organization_handle IS NULL AND reports_to_membership_id IS NULL)
 OR (organization_id IS NOT NULL AND membership_id IS NOT NULL AND organization_handle IS NOT NULL));
ALTER TABLE iam.authentication_sessions ADD COLUMN identity_only boolean NOT NULL DEFAULT false;

-- Legacy STKs remain owned by their original custodian organization. A global
-- identity may retain other memberships after leaving its original directory.
DO $$
DECLARE original text; updated text;
BEGIN
 SELECT pg_get_functiondef('iam_private.resolve_active_silicon_credential(text,smallint[],bytea[])'::regprocedure) INTO original;
 updated:=replace(original, '     AND membership.status = ''active''', '');
 IF updated=original THEN RAISE EXCEPTION 'global Silicon credential patch did not match'; END IF;
 EXECUTE updated;
END $$;

CREATE TABLE iam.silicon_signup_requests (
 id uuid PRIMARY KEY, silicon_id text NOT NULL, display_name text NOT NULL, timezone_id text NOT NULL,
 password_hash text NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
 email_ciphertext bytea NOT NULL, email_nonce bytea NOT NULL CHECK(octet_length(email_nonce)=12),
 email_key_version smallint NOT NULL, email_blind_indexes text[] NOT NULL CHECK(cardinality(email_blind_indexes)>0),
 poll_digest bytea NOT NULL CHECK(octet_length(poll_digest)=32), poll_key_version smallint NOT NULL,
 webhook_ciphertext bytea, webhook_nonce bytea, webhook_key_version smallint,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN('pending','approved','rejected','expired')),
 can_create_organizations boolean NOT NULL DEFAULT true, custodian_carbon_id text,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT transaction_timestamp()+interval '48 hours', decided_at timestamptz,
 CHECK(silicon_id ~ '^si:[a-z0-9_-]{3,50}$'), CHECK(char_length(display_name) BETWEEN 1 AND 100),
 CHECK((status IN('approved','rejected'))=(decided_at IS NOT NULL)),
 CHECK((webhook_ciphertext IS NULL AND webhook_nonce IS NULL AND webhook_key_version IS NULL)
 OR (webhook_ciphertext IS NOT NULL AND octet_length(webhook_nonce)=12 AND webhook_key_version>0))
);
CREATE UNIQUE INDEX silicon_signup_pending_handle ON iam.silicon_signup_requests(silicon_id) WHERE status='pending';
CREATE TABLE iam.silicon_password_credentials (
 silicon_id text PRIMARY KEY, password_hash text NOT NULL CHECK(password_hash LIKE '$argon2id$%'),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), last_used_at timestamptz
);
CREATE TABLE iam.silicon_custodians (
 silicon_id text PRIMARY KEY, carbon_id text, organization_id uuid,
 can_create_organizations boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 CHECK((carbon_id IS NOT NULL) <> (organization_id IS NOT NULL))
);
-- A populated shared testing database can contain the same public Silicon
-- in several worlds. Establish composite keys before backfilling custodians.
DO $$
DECLARE table_name text; key_column text;
BEGIN
 IF EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.silicons'::regclass AND attname='testing_environment_id' AND NOT attisdropped) THEN
  FOREACH table_name IN ARRAY ARRAY['silicon_signup_requests','silicon_password_credentials','silicon_custodians'] LOOP
   EXECUTE format('ALTER TABLE iam.%I ADD COLUMN testing_environment_id uuid NOT NULL DEFAULT iam_private.current_testing_environment_id()',table_name);
   key_column:=CASE WHEN table_name='silicon_signup_requests' THEN 'id' ELSE 'silicon_id' END;
   EXECUTE format('ALTER TABLE iam.%I DROP CONSTRAINT %I',table_name,table_name||'_pkey');
   EXECUTE format('ALTER TABLE iam.%I ADD PRIMARY KEY(testing_environment_id,%I)',table_name,key_column);
   EXECUTE format('CREATE POLICY testing_environment_isolation ON iam.%I AS RESTRICTIVE USING(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id()) WITH CHECK(iam_private.current_testing_environment_id() IS NULL OR testing_environment_id=iam_private.current_testing_environment_id())',table_name);
   EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',table_name);
  END LOOP;
  DROP INDEX iam.silicon_signup_pending_handle;
  CREATE UNIQUE INDEX silicon_signup_pending_handle ON iam.silicon_signup_requests(testing_environment_id,silicon_id) WHERE status='pending';
  EXECUTE 'INSERT INTO iam.silicon_custodians(testing_environment_id,silicon_id,organization_id) SELECT testing_environment_id,id,organization_id FROM iam.silicons WHERE organization_id IS NOT NULL';
 ELSE
  INSERT INTO iam.silicon_custodians(silicon_id,organization_id) SELECT id,organization_id FROM iam.silicons WHERE organization_id IS NOT NULL;
 END IF;
END $$;
ALTER TABLE iam.silicon_signup_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.silicon_password_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.silicon_custodians ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON iam.silicon_signup_requests,iam.silicon_password_credentials,iam.silicon_custodians FROM PUBLIC;

CREATE FUNCTION iam_private.seed_silicon_custodian() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 IF NEW.organization_id IS NOT NULL THEN
 INSERT INTO iam.silicon_custodians(silicon_id,organization_id) VALUES(NEW.id,NEW.organization_id) ON CONFLICT DO NOTHING;
 END IF; RETURN NEW;
END $$;
CREATE TRIGGER silicon_custodian_seed AFTER INSERT ON iam.silicons FOR EACH ROW EXECUTE FUNCTION iam_private.seed_silicon_custodian();

ALTER TABLE iam.notification_jobs DROP CONSTRAINT notification_jobs_kind;
ALTER TABLE iam.notification_jobs ADD CONSTRAINT notification_jobs_kind CHECK(notification_kind IN('invitation','security_notice','application_scope_review','silicon_custody','silicon_signup_webhook'));
ALTER TABLE iam.notification_jobs DROP CONSTRAINT notification_jobs_provider;
ALTER TABLE iam.notification_jobs ADD CONSTRAINT notification_jobs_provider CHECK(provider IN('postmark','twilio_messaging','webhook'));
ALTER TABLE iam.notification_jobs DROP CONSTRAINT notification_jobs_provider_channel;
ALTER TABLE iam.notification_jobs ADD CONSTRAINT notification_jobs_provider_channel CHECK(
 (provider='postmark' AND recipient_contact_kind='email') OR(provider='twilio_messaging' AND recipient_contact_kind='phone')
 OR(provider='webhook' AND notification_kind='silicon_signup_webhook' AND recipient_contact_kind='email'));
ALTER TABLE iam.notification_jobs DROP CONSTRAINT notification_unregistered_recipient;
ALTER TABLE iam.notification_jobs ADD CONSTRAINT notification_unregistered_recipient CHECK(recipient_contact_id IS NOT NULL OR
 (notification_kind='invitation' AND recipient_contact_kind='email' AND context_type='organization_invitation' AND template_id='invitation.created') OR
 (notification_kind IN('silicon_custody','silicon_signup_webhook') AND recipient_contact_kind='email' AND context_type='silicon_signup_request'));
DROP INDEX iam.notification_unregistered_invitation_idx;
CREATE UNIQUE INDEX notification_unregistered_invitation_idx ON iam.notification_jobs(notification_kind,context_type,context_id) WHERE recipient_contact_id IS NULL;

CREATE FUNCTION iam_private.create_silicon_signup(p_id uuid,p_identity text,p_display text,p_timezone text,p_hash text,
 p_email bytea,p_nonce bytea,p_key smallint,p_indexes text[],p_poll bytea,p_poll_key smallint,
 p_webhook bytea,p_webhook_nonce bytea,p_webhook_key smallint,p_job uuid) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE expiry timestamptz;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(p_identity,8124));
 UPDATE iam.silicon_signup_requests SET status='expired' WHERE silicon_id=p_identity AND status='pending' AND expires_at<=transaction_timestamp();
 IF EXISTS(SELECT 1 FROM iam.principals WHERE id=p_identity) THEN RAISE EXCEPTION 'silicon_id_unavailable' USING ERRCODE='23505'; END IF;
 INSERT INTO iam.silicon_signup_requests(id,silicon_id,display_name,timezone_id,password_hash,email_ciphertext,email_nonce,email_key_version,email_blind_indexes,poll_digest,poll_key_version,webhook_ciphertext,webhook_nonce,webhook_key_version)
 VALUES(p_id,p_identity,p_display,p_timezone,p_hash,p_email,p_nonce,p_key,p_indexes,p_poll,p_poll_key,p_webhook,p_webhook_nonce,p_webhook_key)
 RETURNING expires_at INTO expiry;
 INSERT INTO iam.notification_jobs(id,notification_kind,provider,recipient_contact_kind,template_id,context_type,context_id)
 VALUES(p_job,'silicon_custody','postmark','email','silicon.custody.requested','silicon_signup_request',p_id);
 RETURN expiry;
END $$;

CREATE FUNCTION iam_private.silicon_signup_status(p_id uuid,p_versions smallint[],p_digests bytea[],p_custodian boolean)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT jsonb_build_object('request_id',r.id,'silicon_id',r.silicon_id,'display_name',r.display_name,'timezone',r.timezone_id,
 'status',CASE WHEN r.status='pending' AND r.expires_at<=transaction_timestamp() THEN 'expired' ELSE r.status END,
 'expires_at',r.expires_at,'can_create_organizations',r.can_create_organizations)
 FROM iam.silicon_signup_requests r WHERE r.id=p_id AND (
 (NOT p_custodian AND EXISTS(SELECT 1 FROM unnest(p_versions,p_digests) d(v,h) WHERE d.v=r.poll_key_version AND d.h=r.poll_digest)) OR
 (p_custodian AND EXISTS(SELECT 1 FROM iam.carbon_contacts c JOIN iam.contact_blind_indexes i ON i.contact_id=c.id
 JOIN iam.principals p ON p.id=c.carbon_id AND p.kind='carbon' AND p.status='active'
 WHERE c.carbon_id=iam_private.current_principal_id() AND c.kind='email' AND c.status='active' AND c.verified_at IS NOT NULL
 AND (i.hmac_key_version::text||':'||encode(i.digest,'hex'))=ANY(r.email_blind_indexes))))
$$;

CREATE FUNCTION iam_private.decide_silicon_signup(p_id uuid,p_approve boolean,p_can_create boolean,p_job uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE r iam.silicon_signup_requests%ROWTYPE;
BEGIN
 IF iam_private.silicon_signup_status(p_id,'{}','{}',true) IS NULL THEN RAISE EXCEPTION 'custodian_forbidden' USING ERRCODE='42501'; END IF;
 SELECT * INTO r FROM iam.silicon_signup_requests WHERE id=p_id FOR UPDATE;
 IF r.status<>'pending' OR r.expires_at<=transaction_timestamp() THEN RAISE EXCEPTION 'custody_request_inactive' USING ERRCODE='23514'; END IF;
 IF p_approve THEN
  INSERT INTO iam.principals(id,kind,status,activated_at) VALUES(r.silicon_id,'silicon','active',transaction_timestamp());
  INSERT INTO iam.silicons(id,silicon_handle,display_name,timezone_id,provisioning_status)
  VALUES(r.silicon_id,substring(r.silicon_id FROM 4),r.display_name,r.timezone_id,'active');
  INSERT INTO iam.silicon_password_credentials(silicon_id,password_hash) VALUES(r.silicon_id,r.password_hash);
  INSERT INTO iam.silicon_custodians(silicon_id,carbon_id,can_create_organizations)
  VALUES(r.silicon_id,iam_private.current_principal_id(),p_can_create);
 END IF;
 UPDATE iam.silicon_signup_requests SET status=CASE WHEN p_approve THEN 'approved' ELSE 'rejected' END,
 can_create_organizations=p_can_create,custodian_carbon_id=iam_private.current_principal_id(),decided_at=transaction_timestamp() WHERE id=p_id;
 IF r.webhook_ciphertext IS NOT NULL THEN
 INSERT INTO iam.notification_jobs(id,notification_kind,provider,recipient_contact_kind,template_id,context_type,context_id)
 VALUES(p_job,'silicon_signup_webhook','webhook','email','silicon.signup.completed','silicon_signup_request',p_id);
 END IF;
 RETURN iam_private.silicon_signup_status(p_id,'{}','{}',true);
END $$;

CREATE FUNCTION iam_private.resolve_silicon_password(p_identity text)
RETURNS TABLE(principal_id text,password_hash text,principal_auth_epoch bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT p.id,c.password_hash,p.auth_epoch FROM iam.silicon_password_credentials c
 JOIN iam.principals p ON p.id=c.silicon_id AND p.kind='silicon' AND p.status='active'
 JOIN iam.silicons s ON s.id=p.id AND s.provisioning_status='active' AND s.deleted_at IS NULL WHERE p.id=p_identity
$$;
CREATE FUNCTION iam_private.touch_silicon_password() RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
 UPDATE iam.silicon_password_credentials SET last_used_at=transaction_timestamp() WHERE silicon_id=iam_private.current_principal_id()
$$;
CREATE FUNCTION iam_private.silicon_identity_profile() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT jsonb_build_object('principal_id',s.id,'silicon_id',s.global_silicon_id,'display_name',coalesce(s.display_name,s.silicon_handle),
 'timezone',coalesce(s.timezone_id,'UTC'),'profile_photo',s.profile_photo_override_uri,'status',p.status,'version',s.version,
 'can_create_organizations',coalesce(c.can_create_organizations,true))
 FROM iam.silicons s JOIN iam.principals p ON p.id=s.id AND p.kind='silicon' AND p.status='active'
 LEFT JOIN iam.silicon_custodians c ON c.silicon_id=s.id
 WHERE s.id=iam_private.current_principal_id() AND s.deleted_at IS NULL AND s.provisioning_status='active'
$$;
CREATE FUNCTION iam_private.get_worker_silicon_signup(p_job uuid,p_lease text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT jsonb_build_object('request_id',r.id,'silicon_id',r.silicon_id,'display_name',r.display_name,'status',r.status,
 'ciphertext',encode(CASE WHEN j.notification_kind='silicon_custody' THEN r.email_ciphertext ELSE r.webhook_ciphertext END,'hex'),
 'nonce',encode(CASE WHEN j.notification_kind='silicon_custody' THEN r.email_nonce ELSE r.webhook_nonce END,'hex'),
 'key_version',CASE WHEN j.notification_kind='silicon_custody' THEN r.email_key_version ELSE r.webhook_key_version END)
 FROM iam.notification_jobs j JOIN iam.silicon_signup_requests r ON r.id=j.context_id
 WHERE j.id=p_job AND j.lease_owner=p_lease AND j.status='processing' AND j.lease_expires_at>transaction_timestamp()
 AND j.context_type='silicon_signup_request' AND (
 (j.notification_kind='silicon_custody' AND j.provider='postmark' AND r.status='pending' AND r.expires_at>transaction_timestamp()) OR
 (j.notification_kind='silicon_signup_webhook' AND j.provider='webhook' AND r.status IN('approved','rejected')))
$$;
REVOKE ALL ON FUNCTION iam_private.seed_silicon_custodian() FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.create_silicon_signup(uuid,text,text,text,text,bytea,bytea,smallint,text[],bytea,smallint,bytea,bytea,smallint,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.silicon_signup_status(uuid,smallint[],bytea[],boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.decide_silicon_signup(uuid,boolean,boolean,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.resolve_silicon_password(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.touch_silicon_password() FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.silicon_identity_profile() FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_private.get_worker_silicon_signup(uuid,text) FROM PUBLIC;

CREATE FUNCTION iam_private.update_silicon_identity_profile(p_version bigint,p_name text,p_timezone text,p_photo_set boolean,p_photo text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE changed bigint;
BEGIN
 UPDATE iam.silicons s SET display_name=coalesce(p_name,s.display_name),timezone_id=coalesce(p_timezone,s.timezone_id),
 profile_photo_override_uri=CASE WHEN p_photo_set THEN p_photo ELSE s.profile_photo_override_uri END
 WHERE s.id=iam_private.current_principal_id() AND s.version=p_version AND s.deleted_at IS NULL AND s.provisioning_status='active'
 AND EXISTS(SELECT 1 FROM iam.principals p WHERE p.id=s.id AND p.status='active' AND p.kind='silicon');
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RETURN NULL; END IF;
 IF p_photo_set THEN DELETE FROM iam.profile_photos WHERE principal_id=iam_private.current_principal_id()
 AND (p_photo IS NULL OR strpos(p_photo,'/profile-photos/'||id::text)=0); END IF;
 RETURN iam_private.silicon_identity_profile();
END $$;
REVOKE ALL ON FUNCTION iam_private.update_silicon_identity_profile(bigint,text,text,boolean,text) FROM PUBLIC;

ALTER TABLE iam.silicon_custodians ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK(version>0);
CREATE FUNCTION iam_private.list_silicon_custodies() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT jsonb_build_object('items',coalesce(jsonb_agg(jsonb_build_object('silicon_id',s.global_silicon_id,'display_name',coalesce(s.display_name,s.silicon_handle),
 'can_create_organizations',c.can_create_organizations,'version',c.version) ORDER BY s.global_silicon_id),'[]'::jsonb))
 FROM iam.silicon_custodians c JOIN iam.silicons s ON s.id=c.silicon_id AND s.deleted_at IS NULL
 WHERE c.carbon_id=iam_private.current_principal_id()
$$;
REVOKE ALL ON FUNCTION iam_private.list_silicon_custodies() FROM PUBLIC;
CREATE FUNCTION iam_private.update_silicon_custody(p_identity text,p_version bigint,p_can_create boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE result jsonb;
BEGIN
 UPDATE iam.silicon_custodians SET can_create_organizations=p_can_create,version=version+1
 WHERE silicon_id=p_identity AND carbon_id=iam_private.current_principal_id() AND version=p_version
 RETURNING jsonb_build_object('silicon_id',silicon_id,'display_name',(SELECT s.display_name FROM iam.silicons s WHERE s.id=p_identity),'can_create_organizations',can_create_organizations,'version',version) INTO result;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION iam_private.update_silicon_custody(text,bigint,boolean) FROM PUBLIC;

-- Independent Silicon identities retain access to their own identity outside an organization.
CREATE POLICY silicons_identity_self_select ON iam.silicons FOR SELECT
USING (id = iam_private.current_principal_id() AND deleted_at IS NULL);
