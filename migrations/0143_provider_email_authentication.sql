-- A provider proves its current verified email. Historical subject associations
-- remain private records and confer no authentication or signup authority.
ALTER TABLE iam.social_signup_requests ADD COLUMN login_contact_id uuid;

-- Pre-cutover login proofs were resolved under different authority semantics.
-- Existing IAM sessions and verified-email signup continuations remain usable.
UPDATE iam.social_signup_requests SET status='failed',
 proof_ciphertext=NULL,proof_nonce=NULL,proof_key_version=NULL
WHERE intent='login' AND status IN ('pending','processing','login_ready','link_required');

DROP TRIGGER signup_social_identity ON iam.signup_sessions;
DROP FUNCTION iam_private.bind_completed_social_signup();
DROP FUNCTION iam_private.bind_social_login_identity(uuid,text,uuid);
DROP FUNCTION iam_private.social_login_identity(text,jsonb);
DROP FUNCTION iam_private.social_identity_registered(text,smallint,bytea);

CREATE FUNCTION iam_private.social_email_login_target(p_digests jsonb)
RETURNS TABLE(principal_id text,contact_id uuid,auth_epoch bigint,eligible boolean)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,iam,iam_private AS $$
 SELECT p.id,contact.id,p.auth_epoch,
  c.deleted_at IS NULL AND p.status='active' AND p.deleted_at IS NULL
 FROM iam.carbon_contacts contact
 JOIN iam.carbons c ON c.id=contact.carbon_id
 JOIN iam.principals p ON p.id=c.id
 WHERE contact.kind='email' AND contact.status='active' AND contact.is_primary
 AND contact.verified_at IS NOT NULL AND p.kind='carbon'
 AND EXISTS (
  SELECT 1 FROM iam.contact_blind_indexes b
  JOIN jsonb_to_recordset(p_digests) AS d(key_version smallint,digest text)
   ON b.hmac_key_version=d.key_version AND b.digest=decode(d.digest,'hex')
  WHERE b.contact_id=contact.id AND b.contact_kind='email'
   AND octet_length(b.digest)=32
 )
 -- These locks cover contact retirement/reassignment and principal resets.
 FOR UPDATE OF p FOR SHARE OF contact,c
$$;
REVOKE ALL ON FUNCTION iam_private.social_email_login_target(jsonb) FROM PUBLIC;
