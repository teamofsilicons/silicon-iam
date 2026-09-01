-- Close OBO delegation to the canonical organization-capability vocabulary.

ALTER TABLE iam.obo_action_catalog
    DROP CONSTRAINT obo_action_catalog_action_format,
    ADD CONSTRAINT obo_action_catalog_action_catalog CHECK (
        action = ANY(ARRAY[
            'organization.update',
            'members.invite',
            'members.update_directory',
            'members.remove',
            'silicons.create',
            'silicons.update_directory',
            'silicons.manage_hierarchy',
            'silicons.remove',
            'silicons.rotate_token',
            'tags.manage',
            'trust.manage',
            'roles.request',
            'roles.approve',
            'admins.create',
            'admins.manage',
            'sso.manage',
            'audit.read'
        ]::text[])
    );

COMMENT ON CONSTRAINT obo_action_catalog_action_catalog ON iam.obo_action_catalog IS
    'OBO actions are the fixed organization capability vocabulary; unknown strings fail closed.';

UPDATE iam.oauth_scope_catalog
SET description = 'Reserved compatibility scope; OAuth refresh-token issuance is unconditional.'
WHERE scope = 'offline_access';

ALTER TABLE iam.oidc_signing_keys
    ADD CONSTRAINT oidc_signing_keys_eddsa_jwk_shape CHECK (
        algorithm <> 'EdDSA'
        OR (
            public_jwk ->> 'kty' = 'OKP'
            AND public_jwk ->> 'crv' = 'Ed25519'
            AND public_jwk ->> 'alg' = 'EdDSA'
            AND public_jwk ->> 'use' = 'sig'
            AND public_jwk ->> 'kid' = key_id
            AND public_jwk ->> 'x' ~ '^[A-Za-z0-9_-]{43}$'
        )
    );

CREATE UNIQUE INDEX oidc_signing_keys_eddsa_public_material_unique_idx
    ON iam.oidc_signing_keys ((public_jwk ->> 'x'))
    WHERE algorithm = 'EdDSA';

COMMENT ON CONSTRAINT oidc_signing_keys_eddsa_jwk_shape ON iam.oidc_signing_keys IS
    'Ed25519 keys expose one canonical public JWK matching the stored kid and algorithm.';
COMMENT ON INDEX iam.oidc_signing_keys_eddsa_public_material_unique_idx IS
    'One Ed25519 public key may never be rebound to a different key identifier.';
