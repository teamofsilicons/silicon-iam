-- Match new Carbon identifiers and signup defaults to the public IAM contract.
-- Keep legacy rows containing zero readable while rejecting zero in every new
-- identifier; Carbon handles are immutable, so a NOT VALID constraint is the
-- safe rolling-upgrade boundary.

ALTER TABLE iam.carbons
    DROP CONSTRAINT carbons_carbon_id_format,
    ADD CONSTRAINT carbons_carbon_id_format
        CHECK (carbon_id ~ '^[a-z1-9_-]{3,30}$') NOT VALID;

COMMENT ON COLUMN iam.carbons.carbon_id IS
    'Immutable case-normalized public Carbon ID: ASCII a-z, 1-9, hyphen, or underscore; 3-30 characters. Legacy zero-containing IDs remain readable.';
