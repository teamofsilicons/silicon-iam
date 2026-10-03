-- Silicon reauthentication proves possession of its STK for one action, target
-- and existing session. It grants no independent organization capability.
CREATE TABLE iam.silicon_step_up_assertions(
 id uuid PRIMARY KEY,principal_id text NOT NULL,session_id uuid NOT NULL,
 action text NOT NULL CHECK(action IN('account.session_revoke','account.sessions_revoke_all','organization.transfer_ownership','organization.authorization_change','organization.sso_change','organization.silicon_webhook.redirect','silicon.rotate_token','application.client_secret.rotate','application.webhook_secret.rotate','application.webhook.approve')),
 resource_id text NOT NULL,token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),digest_key_version smallint NOT NULL,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),expires_at timestamptz NOT NULL DEFAULT transaction_timestamp()+interval '5 minutes',consumed_at timestamptz,
 UNIQUE(digest_key_version,token_digest)
);
ALTER TABLE iam.silicon_step_up_assertions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON iam.silicon_step_up_assertions FROM PUBLIC;
CREATE FUNCTION iam_private.issue_silicon_step_up(p_id uuid,p_session uuid,p_action text,p_resource text,p_digest bytea,p_key smallint)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 PERFORM 1 FROM iam.principals p JOIN iam.authentication_sessions s ON s.subject_principal_id=p.id AND s.subject_kind='silicon'
 WHERE p.id=iam_private.current_principal_id() AND p.kind='silicon' AND p.status='active' AND s.id=p_session
 AND s.status='active' AND s.subject_auth_epoch=p.auth_epoch AND s.idle_expires_at>transaction_timestamp() AND s.absolute_expires_at>transaction_timestamp()
 FOR SHARE OF p,s;
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO iam.silicon_step_up_assertions(id,principal_id,session_id,action,resource_id,token_digest,digest_key_version)
 VALUES(p_id,iam_private.current_principal_id(),p_session,p_action,p_resource,p_digest,p_key);
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION iam_private.issue_silicon_step_up(uuid,uuid,text,text,bytea,smallint) FROM PUBLIC;
CREATE FUNCTION iam_private.consume_silicon_step_up(p_session uuid,p_action text,p_resource text,p_versions smallint[],p_digests bytea[])
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
DECLARE result uuid;
BEGIN
 PERFORM 1 FROM iam.principals p JOIN iam.authentication_sessions s ON s.subject_principal_id=p.id AND s.subject_kind='silicon'
 WHERE p.id=iam_private.current_principal_id() AND p.kind='silicon' AND p.status='active' AND s.id=p_session
 AND s.status='active' AND s.subject_auth_epoch=p.auth_epoch AND s.idle_expires_at>transaction_timestamp() AND s.absolute_expires_at>transaction_timestamp()
 FOR SHARE OF p,s;
 IF NOT FOUND THEN RETURN NULL; END IF;
 UPDATE iam.silicon_step_up_assertions a SET consumed_at=transaction_timestamp()
 WHERE a.principal_id=iam_private.current_principal_id() AND a.session_id=p_session AND a.action=p_action AND a.resource_id=p_resource
 AND a.consumed_at IS NULL AND a.expires_at>transaction_timestamp()
 AND EXISTS(SELECT 1 FROM unnest(p_versions,p_digests) d(v,h) WHERE d.v=a.digest_key_version AND d.h=a.token_digest)
 RETURNING a.id INTO result;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION iam_private.consume_silicon_step_up(uuid,text,text,smallint[],bytea[]) FROM PUBLIC;
