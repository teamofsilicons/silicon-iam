\set ON_ERROR_STOP on

BEGIN;

INSERT INTO iam.cryptographic_key_versions (purpose, key_version, status)
VALUES
    ('contact_aead', 1, 'active'),
    ('contact_lookup_hmac', 1, 'active'),
    ('token_hmac', 1, 'active')
ON CONFLICT (purpose, key_version) DO NOTHING;

INSERT INTO iam.principals (id, kind, status, activated_at)
VALUES (
    '70000000-0000-7000-8000-000000000001',
    'carbon',
    'deletion_pending',
    transaction_timestamp() - interval '1 year'
);

INSERT INTO iam.carbons (
    id, carbon_id, display_name, description, profile_photo_uri
) VALUES (
    '70000000-0000-7000-8000-000000000001',
    'deletion_smoke',
    'Deletion Smoke',
    'must be erased',
    'https://iris.example.test/private'
);

INSERT INTO iam.authentication_sessions (
    id, subject_principal_id, subject_kind, authentication_method,
    subject_auth_epoch, status, created_at, last_seen_at,
    idle_expires_at, absolute_expires_at, revoked_at, revocation_reason
) VALUES (
    '70000000-0000-7000-8000-000000000002',
    '70000000-0000-7000-8000-000000000001',
    'carbon',
    'email_otp',
    1,
    'revoked',
    transaction_timestamp() - interval '60 days',
    transaction_timestamp() - interval '31 days',
    transaction_timestamp() - interval '30 days',
    transaction_timestamp() - interval '1 day',
    transaction_timestamp() - interval '31 days',
    'account_deletion_requested'
);

INSERT INTO iam.carbon_contacts (
    id, carbon_id, kind, ciphertext, nonce, encryption_key_version,
    is_primary, status, verified_at, retired_at
) VALUES
    (
        '70000000-0000-7000-8000-000000000003',
        '70000000-0000-7000-8000-000000000001',
        'email',
        decode(repeat('01', 17), 'hex'),
        decode(repeat('02', 12), 'hex'),
        1,
        true,
        'active',
        transaction_timestamp() - interval '1 year',
        NULL
    ),
    (
        '70000000-0000-7000-8000-000000000004',
        '70000000-0000-7000-8000-000000000001',
        'phone',
        decode(repeat('03', 17), 'hex'),
        decode(repeat('04', 12), 'hex'),
        1,
        false,
        'retired',
        transaction_timestamp() - interval '1 year',
        transaction_timestamp() - interval '90 days'
    );

INSERT INTO iam.contact_blind_indexes (
    contact_id, contact_kind, hmac_key_version, digest
) VALUES
    (
        '70000000-0000-7000-8000-000000000003',
        'email',
        1,
        decode(repeat('05', 32), 'hex')
    ),
    (
        '70000000-0000-7000-8000-000000000004',
        'phone',
        1,
        decode(repeat('06', 32), 'hex')
    );

INSERT INTO iam.contact_change_sessions (
    id, carbon_id, authentication_session_id, kind, candidate_contact_id,
    ciphertext, nonce, encryption_key_version, code_digest, digest_key_version,
    status, created_at, expires_at, superseded_at
) VALUES (
    '70000000-0000-7000-8000-000000000005',
    '70000000-0000-7000-8000-000000000001',
    '70000000-0000-7000-8000-000000000002',
    'email',
    '70000000-0000-7000-8000-000000000006',
    decode(repeat('07', 17), 'hex'),
    decode(repeat('08', 12), 'hex'),
    1,
    decode(repeat('09', 32), 'hex'),
    1,
    'cancelled',
    transaction_timestamp() - interval '31 days',
    transaction_timestamp() - interval '30 days',
    transaction_timestamp() - interval '30 days'
);

INSERT INTO iam.contact_change_blind_indexes (
    contact_change_session_id, carbon_id, contact_kind,
    hmac_key_version, digest
) VALUES (
    '70000000-0000-7000-8000-000000000005',
    '70000000-0000-7000-8000-000000000001',
    'email',
    1,
    decode(repeat('0a', 32), 'hex')
);

INSERT INTO iam.account_deletion_requests (
    id, carbon_id, requested_from_session_id, requested_at, scheduled_for
) VALUES (
    '70000000-0000-7000-8000-000000000007',
    '70000000-0000-7000-8000-000000000001',
    '70000000-0000-7000-8000-000000000002',
    transaction_timestamp() - interval '31 days',
    transaction_timestamp() - interval '1 day'
);

SET ROLE silicon_iam_worker_runtime;
SELECT iam_private.run_worker_account_deletion_finalization(
    1,
    ARRAY['70000000-0000-7000-8000-000000000010'::uuid],
    ARRAY['70000000-0000-7000-8000-000000000011'::uuid],
    ARRAY['70000000-0000-7000-8000-000000000012'::uuid]
);
RESET ROLE;

DO $assertions$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM iam.principals AS principal
        JOIN iam.carbons AS carbon ON carbon.id = principal.id
        WHERE principal.id = '70000000-0000-7000-8000-000000000001'
          AND principal.status = 'deleted'
          AND principal.deleted_at IS NOT NULL
          AND carbon.display_name = 'Deleted Carbon'
          AND carbon.description IS NULL
          AND carbon.profile_photo_uri IS NULL
          AND carbon.deleted_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'terminal Carbon deletion state was not persisted';
    END IF;

    IF (SELECT count(*) FROM iam.carbon_contacts
        WHERE carbon_id = '70000000-0000-7000-8000-000000000001') <> 2
       OR EXISTS (
           SELECT 1
           FROM iam.carbon_contacts
           WHERE carbon_id = '70000000-0000-7000-8000-000000000001'
             AND (
                 status <> 'retired'
                 OR is_primary
                 OR ciphertext IS NOT NULL
                 OR nonce IS NOT NULL
                 OR encryption_key_version IS NOT NULL
                 OR purged_at IS NULL
             )
       ) THEN
        RAISE EXCEPTION 'active and retired contact PII was not cryptographically erased';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM iam.contact_blind_indexes AS blind_index
        JOIN iam.carbon_contacts AS contact ON contact.id = blind_index.contact_id
        WHERE contact.carbon_id = '70000000-0000-7000-8000-000000000001'
    ) OR EXISTS (
        SELECT 1
        FROM iam.contact_change_sessions
        WHERE carbon_id = '70000000-0000-7000-8000-000000000001'
    ) THEN
        RAISE EXCEPTION 'contact lookup or pending replacement material survived deletion';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM iam.account_deletion_requests
        WHERE id = '70000000-0000-7000-8000-000000000007'
          AND status = 'completed'
          AND completed_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM iam.audit_events
        WHERE id = '70000000-0000-7000-8000-000000000011'
          AND action = 'carbon.deletion_finalize'
    ) OR NOT EXISTS (
        SELECT 1 FROM iam.outbox_events
        WHERE id = '70000000-0000-7000-8000-000000000012'
          AND event_type = 'carbon.deleted'
    ) THEN
        RAISE EXCEPTION 'deletion completion, audit, and outbox records were not atomic';
    END IF;
END;
$assertions$;

ROLLBACK;
