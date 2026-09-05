-- Application-local handles may contain 1-80 ASCII characters. Keep the
-- organization handle's 3-50-character rule and both existing character sets.
-- The shared base migration also runs before the testing database overlay.
ALTER TABLE iam.applications
    DROP CONSTRAINT applications_app_id_format,
    ADD CONSTRAINT applications_app_id_format CHECK (
        app_id ~ '^[a-z0-9_-]{3,50}>[a-z][a-z0-9_-]{0,79}$'
    );
