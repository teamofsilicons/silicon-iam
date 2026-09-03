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

-- Approving an application's scopes is a platform authority: the policies on
-- `application_approved_scopes` admit only `can_administer_application`. That
-- was right when a human reviewer decided how much of the catalogue an
-- application could ask for. Now the answer is always "all of it", and it is
-- settled at creation by the organization owner, who deliberately does not
-- hold that authority.
--
-- So the grant is made through an owner-rights function rather than by
-- widening the policy. It is authorized narrowly -- the caller must already be
-- able to manage the application technically, which is exactly the right they
-- have just exercised by creating it -- so this grants nobody anything they
-- could not already do, and it cannot be pointed at somebody else's
-- application.
CREATE FUNCTION iam_private.grant_application_scope_catalogue(
    p_application_id uuid,
    p_approved_by_carbon_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
BEGIN
    IF p_application_id IS NULL OR p_approved_by_carbon_id IS NULL THEN
        RAISE EXCEPTION 'application_scope_catalogue_invalid' USING ERRCODE = '22023';
    END IF;

    IF NOT iam_private.can_manage_application_technical(
        p_application_id, iam_private.current_principal_id()
    ) THEN
        RAISE EXCEPTION 'application_scope_catalogue_forbidden' USING ERRCODE = '42501';
    END IF;

    INSERT INTO iam.application_requested_scopes (application_id, scope)
    SELECT p_application_id, catalog.scope
    FROM iam.oauth_scope_catalog AS catalog
    WHERE NOT EXISTS (
        SELECT 1
        FROM iam.application_requested_scopes AS requested
        WHERE requested.application_id = p_application_id
          AND requested.scope = catalog.scope
    );

    INSERT INTO iam.application_approved_scopes (
        application_id, scope, approved_by_carbon_id
    )
    SELECT p_application_id, catalog.scope, p_approved_by_carbon_id
    FROM iam.oauth_scope_catalog AS catalog
    WHERE NOT EXISTS (
        SELECT 1
        FROM iam.application_approved_scopes AS approved
        WHERE approved.application_id = p_application_id
          AND approved.scope = catalog.scope
          AND approved.revoked_at IS NULL
    );
END;
$$;

REVOKE ALL ON FUNCTION iam_private.grant_application_scope_catalogue(uuid, uuid) FROM PUBLIC;

-- Authenticating an application by its own credential could never succeed.
--
-- The resolver locks the rows it reads -- `FOR UPDATE OF application,
-- principal, secret` -- so a credential cannot be rotated out from under a
-- request midway. PostgreSQL applies a table's UPDATE policies to a locking
-- read, and the only policy governing UPDATE on `iam.applications` is
-- `applications_manager_update`, which asks whether the current principal can
-- manage the application. Here the current principal *is* the application, and
-- an application does not manage itself, so the row was filtered out and the
-- caller was told its credential was wrong.
--
-- Proven against a production-shaped database as the API runtime role with the
-- application's own context set:
--
--     no lock                                    : rows=1
--     FOR UPDATE OF application, principal, secret: rows=0
--
-- Everything downstream of this is affected: the token exchange, introspection,
-- revocation, and every on-behalf-of call, none of which can authenticate their
-- caller.
--
-- Resolved through an owner-rights function so the locks survive. The caller
-- must still present a currently valid secret digest, which is the
-- authentication itself, so this reveals nothing to anyone who could not
-- already authenticate.
CREATE FUNCTION iam_private.resolve_application_client(
    p_application_id uuid,
    p_app_id text,
    p_pepper_key_version smallint,
    p_secret_digest bytea
)
RETURNS TABLE (
    application_id uuid,
    app_id text,
    organization_id uuid,
    auth_epoch bigint
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT application.id, application.app_id,
           application.organization_id, principal.auth_epoch
    FROM iam.applications AS application
    JOIN iam.principals AS principal
      ON principal.id = application.id
     AND principal.kind = 'application'
     AND principal.status = 'active'
    JOIN iam.application_secrets AS secret
      ON secret.application_id = application.id
     AND secret.pepper_key_version = p_pepper_key_version
     AND secret.secret_digest = p_secret_digest
    WHERE application.id = p_application_id
      AND application.app_id = p_app_id
      AND application.review_status = 'verified'
      AND application.deleted_at IS NULL
      AND (
          secret.status = 'active'
          OR (secret.status = 'retiring' AND secret.retires_at > transaction_timestamp())
      )
    FOR UPDATE OF application, principal, secret
$$;

REVOKE ALL ON FUNCTION iam_private.resolve_application_client(
    uuid, text, smallint, bytea
) FROM PUBLIC;

-- The same locking-under-RLS problem, one step further into the exchange.
--
-- Before consuming a short-lived token the exchange re-checks that the client
-- is still verified on the authentication epoch it presented, and holds that
-- true with `FOR SHARE OF application, principal`. A share lock applies the
-- same UPDATE policies, so it filtered the row for exactly the same reason:
-- the current principal is the application, and an application does not manage
-- itself. The check therefore always failed and every exchange answered
-- `invalid_grant`.
CREATE FUNCTION iam_private.lock_current_application_client(
    p_application_id uuid,
    p_auth_epoch bigint
)
RETURNS uuid
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT application.id
    FROM iam.applications AS application
    JOIN iam.principals AS principal
      ON principal.id = application.id
     AND principal.kind = 'application'
     AND principal.status = 'active'
     AND principal.auth_epoch = p_auth_epoch
    WHERE application.id = p_application_id
      AND application.review_status = 'verified'
      AND application.deleted_at IS NULL
    FOR SHARE OF application, principal
$$;

REVOKE ALL ON FUNCTION iam_private.lock_current_application_client(uuid, bigint) FROM PUBLIC;

-- And the same problem again, on the scope ceiling.
--
-- Both the token exchange and refresh rotation re-read the application's
-- currently approved scopes and hold them still with `FOR SHARE OF approved`,
-- so the ceiling cannot move while a token is being issued against it. The
-- policies on `iam.application_approved_scopes` admit writes only to
-- `can_administer_application`, and a share lock applies them: the calling
-- application is not its own administrator, so the lock returned nothing and
-- every exchange decided the request had lost all of its authority.
--
-- One function serves both callers so the lock cannot drift between them. It
-- answers only for the application the caller is currently authenticated as,
-- which is the only application either query asks about.
CREATE FUNCTION iam_private.locked_application_approved_scopes(p_application_id uuid)
RETURNS TABLE (scope text)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
BEGIN
    IF p_application_id IS NULL
       OR p_application_id IS DISTINCT FROM iam_private.current_application_id() THEN
        RAISE EXCEPTION 'application_scope_ceiling_forbidden' USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT approved.scope
    FROM iam.application_approved_scopes AS approved
    WHERE approved.application_id = p_application_id
      AND approved.revoked_at IS NULL
    FOR SHARE OF approved;
END;
$$;

REVOKE ALL ON FUNCTION iam_private.locked_application_approved_scopes(uuid) FROM PUBLIC;
