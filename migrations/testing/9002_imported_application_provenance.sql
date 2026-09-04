-- Testing-only provenance for Applications imported from production.
--
-- These columns deliberately do not exist in production. Ordinary test
-- Application creation receives the false defaults. The import endpoint sets
-- both flags, while a subsequently configured webhook signing key naturally
-- receives false and is therefore known to be test-owned without any special
-- handling in the ordinary webhook lifecycle.

ALTER TABLE iam.applications
    ADD COLUMN test_imported_from_production boolean NOT NULL DEFAULT false;

ALTER TABLE iam.application_webhook_signing_keys
    ADD COLUMN test_inherited_from_production boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN iam.applications.test_imported_from_production IS
    'True only when this testing-plane Application was copied from the production directory.';

COMMENT ON COLUMN iam.application_webhook_signing_keys.test_inherited_from_production IS
    'True only for a signing secret copied from production during test import; such a secret is never revealed by the testing plane.';
