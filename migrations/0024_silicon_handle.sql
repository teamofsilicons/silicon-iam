-- Name the immutable Silicon ID component as a handle, never as a public local ID.

ALTER TABLE iam.silicons
    RENAME COLUMN local_silicon_id TO silicon_handle;

ALTER TABLE iam.silicons
    RENAME CONSTRAINT silicons_local_id_format TO silicons_handle_format;

ALTER TABLE iam.silicons
    RENAME CONSTRAINT silicons_organization_id_local_silicon_id_key
    TO silicons_organization_id_silicon_handle_key;

CREATE OR REPLACE FUNCTION iam_private.prevent_silicon_identity_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.id <> OLD.id
       OR NEW.organization_id <> OLD.organization_id
       OR NEW.membership_id <> OLD.membership_id
       OR NEW.organization_handle <> OLD.organization_handle
       OR NEW.silicon_handle <> OLD.silicon_handle THEN
        RAISE EXCEPTION 'Silicon identity, tenant, and handles are immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.prevent_silicon_identity_change() FROM PUBLIC;

COMMENT ON COLUMN iam.silicons.silicon_handle IS
    'Immutable component used to construct global_silicon_id; it is never independently addressable.';

