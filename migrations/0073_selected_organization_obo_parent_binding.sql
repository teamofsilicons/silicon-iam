-- An OBO proof remains single-organization even when its parent bearer is not.
-- The old composite FK required the parent token's nullable org columns to
-- equal the proof's concrete organization, making multi-org OBO impossible.
ALTER TABLE iam.access_tokens
    ADD CONSTRAINT access_tokens_obo_parent_identity_key
    UNIQUE (id, subject_principal_id, client_application_id);

ALTER TABLE iam.obo_proofs
    DROP CONSTRAINT obo_proofs_parent_token_fk,
    ADD CONSTRAINT obo_proofs_parent_token_fk
        FOREIGN KEY (parent_access_token_id, subject_principal_id, issuer_application_id)
        REFERENCES iam.access_tokens (id, subject_principal_id, client_application_id)
        ON DELETE RESTRICT;

-- Preserve the tenant and membership binding at insertion, and forbid rewriting
-- a persisted proof's authority. Lifecycle updates (consume/revoke) need not
-- reauthorize a dead parent; they never change these columns.
CREATE FUNCTION iam_private.enforce_selected_obo_parent_binding()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.parent_access_token_id, NEW.subject_principal_id,
               NEW.issuer_application_id, NEW.organization_id, NEW.membership_id)
           IS DISTINCT FROM
           ROW(OLD.parent_access_token_id, OLD.subject_principal_id,
               OLD.issuer_application_id, OLD.organization_id, OLD.membership_id) THEN
            RAISE EXCEPTION 'obo_parent_binding_immutable' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM iam.access_tokens parent
        JOIN iam.organization_memberships member
          ON member.id = NEW.membership_id AND member.organization_id = NEW.organization_id
         AND member.principal_id = NEW.subject_principal_id
        WHERE parent.id = NEW.parent_access_token_id
          AND parent.subject_principal_id = NEW.subject_principal_id
          AND parent.client_application_id = NEW.issuer_application_id
          AND iam_private.application_token_allows_membership(parent.id, member.id)
    ) THEN
        RAISE EXCEPTION 'obo_parent_organization_not_selected' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.enforce_selected_obo_parent_binding() FROM PUBLIC;

CREATE TRIGGER obo_proofs_selected_parent_binding
BEFORE INSERT OR UPDATE OF parent_access_token_id, subject_principal_id,
    issuer_application_id, organization_id, membership_id
ON iam.obo_proofs
FOR EACH ROW EXECUTE FUNCTION iam_private.enforce_selected_obo_parent_binding();
