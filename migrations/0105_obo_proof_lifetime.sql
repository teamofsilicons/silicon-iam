-- Match the positive i32 lifetime accepted by configured OBO endpoints.
-- Runtime parent-token, consent, endpoint and revocation checks remain mandatory.
ALTER TABLE iam.obo_proofs DROP CONSTRAINT obo_proofs_lifetime;
ALTER TABLE iam.obo_proofs ADD CONSTRAINT obo_proofs_lifetime CHECK (
    expires_at > created_at
    AND expires_at <= created_at + interval '2147483647 seconds'
);
