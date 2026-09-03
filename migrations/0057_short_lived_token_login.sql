-- Login for a configured application stops being an OAuth negotiation.
--
-- UNDERSTANDING.md now describes one flow: the caller arrives at
-- `<auth_base_url>/login?app_id=...&redirect_uri=...`, IAM signs the Carbon or
-- Silicon in if they are not already, and hands back a short-lived token --
-- appended to the redirect URI when one was supplied, shown on a page when it
-- was not. The application then presents that token with its own secret and
-- receives the access and refresh pair.
--
-- Three things the old shape required are gone from that description, and each
-- one is a column that can no longer be mandatory:
--
--   * Redirect URIs are no longer registered. The caller names one in the
--     query string, so a request points at a URI by value rather than by a row
--     in `application_redirect_uris`, and that table has nothing left to hold.
--     Its only dependant was the foreign key dropped here.
--   * There is no consent screen, so `applications.notify_users` -- the flag
--     that decided whether to prompt -- has nothing to decide.
--   * There is no `state` round-trip and no PKCE exchange in the described
--     flow, so the columns carrying them become optional rather than required.
--
-- The consent *grant* is deliberately untouched. It is not the prompt: it is
-- the record of which applications a principal is authorized in, and
-- `iam_private.refresh_authorized_application_webhook_recipients` and the
-- `/api/v1/me` authorized-application listing both read it to decide who
-- receives webhooks. Removing the prompt makes the grant implicit; removing
-- the grant would silently stop webhook delivery.
--
-- Manual verification is likewise dropped as a *step*, not as a column.
-- `review_status = 'verified'` is read by an RLS policy on `iam.applications`
-- and by eight functions across 0006, 0030, 0031, 0042, 0044 and 0046 that
-- decide webhook recipients and projections. New applications are verified on
-- arrival and the ones still waiting are released; the column and every
-- authorization path built on it stay exactly as they were.

ALTER TABLE iam.oauth_authorization_requests
    DROP CONSTRAINT oauth_authorization_requests_redirect_fk;

ALTER TABLE iam.oauth_authorization_requests
    DROP COLUMN redirect_uri_id;

ALTER TABLE iam.oauth_authorization_requests
    ADD COLUMN redirect_uri text;

ALTER TABLE iam.oauth_authorization_requests
    ADD CONSTRAINT oauth_authorization_requests_redirect_uri_length
    CHECK (redirect_uri IS NULL OR char_length(redirect_uri) BETWEEN 1 AND 2048);

COMMENT ON COLUMN iam.oauth_authorization_requests.redirect_uri IS
    'Redirect URI named by the caller for this login, or NULL when the short-lived token is shown rather than delivered.';

DROP TABLE iam.application_redirect_uris;

ALTER TABLE iam.oauth_authorization_requests
    ALTER COLUMN state_digest DROP NOT NULL,
    ALTER COLUMN state_ciphertext DROP NOT NULL,
    ALTER COLUMN state_encryption_nonce DROP NOT NULL,
    ALTER COLUMN encryption_key_version DROP NOT NULL,
    ALTER COLUMN pkce_code_challenge DROP NOT NULL;

ALTER TABLE iam.applications
    DROP COLUMN notify_users;

ALTER TABLE iam.applications
    ALTER COLUMN review_status SET DEFAULT 'verified';

UPDATE iam.applications
SET review_status = 'verified'
WHERE review_status = 'under_review';

-- Login now grants the whole scope catalogue.
--
-- `scope` in UNDERSTANDING.md is the webhook's scope -- which changes an
-- application is told about -- and explicitly not the login's: "scope of the
-- login is always everything". The request-scope rows that a login writes are
-- foreign-keyed to `application_approved_scopes`, which is in turn keyed to
-- `application_requested_scopes`, so "everything" has to exist as rows rather
-- than as a special case in the code. Every application is brought up to the
-- full catalogue here, and `applications::create` does the same for new ones.
INSERT INTO iam.application_requested_scopes (application_id, scope)
SELECT application.id, catalog.scope
FROM iam.applications AS application
CROSS JOIN iam.oauth_scope_catalog AS catalog
WHERE NOT EXISTS (
    SELECT 1
    FROM iam.application_requested_scopes AS requested
    WHERE requested.application_id = application.id
      AND requested.scope = catalog.scope
);

INSERT INTO iam.application_approved_scopes (application_id, scope, approved_by_carbon_id)
SELECT application.id, catalog.scope, application.created_by_carbon_id
FROM iam.applications AS application
CROSS JOIN iam.oauth_scope_catalog AS catalog
WHERE NOT EXISTS (
    SELECT 1
    FROM iam.application_approved_scopes AS approved
    WHERE approved.application_id = application.id
      AND approved.scope = catalog.scope
      AND approved.revoked_at IS NULL
);
