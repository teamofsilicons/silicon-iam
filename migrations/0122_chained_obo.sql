-- Chained OBO delegation.
--
-- An application that consumed a proof may obtain a narrower proof for the
-- same subject, but only for calls the consumed endpoint declared up front,
-- inside that endpoint's declared window, at most ten hops from the subject's
-- own token, and never back to an application already in the chain. Every hop
-- inherits the subject's parent access token, so logout, consent removal and
-- the existing epoch checks end the whole chain. Direct exchange and
-- verification of unchained proofs keep their existing behavior.

-- 1. Endpoint catalog: declared downstream calls and their window.
ALTER TABLE iam.application_obo_endpoints
    ADD COLUMN downstream jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN downstream_ttl_seconds integer,
    ADD CONSTRAINT application_obo_endpoints_downstream_array CHECK (
        jsonb_typeof(downstream) = 'array' AND jsonb_array_length(downstream) <= 16
    ),
    -- A window without declared calls would be meaningless configuration.
    ADD CONSTRAINT application_obo_endpoints_downstream_ttl CHECK (
        downstream_ttl_seconds IS NULL
        OR (downstream_ttl_seconds BETWEEN 1 AND 3600 AND downstream <> '[]'::jsonb)
    );

-- Element shape is validated by trigger because CHECK cannot iterate. Trigger
-- firing needs no EXECUTE grant, so runtime roles remain function-free here.
CREATE FUNCTION iam_private.validate_application_obo_downstream()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    item jsonb;
BEGIN
    FOR item IN SELECT value FROM jsonb_array_elements(NEW.downstream) LOOP
        IF jsonb_typeof(item) IS DISTINCT FROM 'object'
           OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(item) AS key)
              IS DISTINCT FROM ARRAY['audience', 'endpoint_id']
           OR jsonb_typeof(item->'audience') IS DISTINCT FROM 'string'
           OR jsonb_typeof(item->'endpoint_id') IS DISTINCT FROM 'string'
           OR item->>'audience' !~ '^[a-z][a-z0-9_-]{0,79}$'
           OR item->>'endpoint_id' !~ '^[a-z][a-z0-9_.:-]{2,127}$'
           OR item->>'audience' = NEW.application_id THEN
            RAISE EXCEPTION 'invalid OBO downstream declaration' USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;
    IF (SELECT count(DISTINCT value) FROM jsonb_array_elements(NEW.downstream))
       <> jsonb_array_length(NEW.downstream) THEN
        RAISE EXCEPTION 'duplicate OBO downstream declaration' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.validate_application_obo_downstream() FROM PUBLIC;

CREATE TRIGGER application_obo_endpoints_downstream_valid
BEFORE INSERT OR UPDATE OF downstream ON iam.application_obo_endpoints
FOR EACH ROW EXECUTE FUNCTION iam_private.validate_application_obo_downstream();

-- A changed declaration is a changed endpoint: outstanding proofs pinned to
-- the previous version stop verifying and stop chaining.
CREATE OR REPLACE FUNCTION iam_private.maintain_application_obo_endpoint()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, iam
AS $$
BEGIN
    IF NEW.application_id IS DISTINCT FROM OLD.application_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.endpoint_id IS DISTINCT FROM OLD.endpoint_id
       OR NEW.path IS DISTINCT FROM OLD.path THEN
        RAISE EXCEPTION 'OBO endpoint tenant, identity, and path are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.metadata_definition IS DISTINCT FROM OLD.metadata_definition
       OR NEW.status IS DISTINCT FROM OLD.status
       OR NEW.downstream IS DISTINCT FROM OLD.downstream
       OR NEW.downstream_ttl_seconds IS DISTINCT FROM OLD.downstream_ttl_seconds THEN
        NEW.version := OLD.version + 1;
        NEW.updated_at := transaction_timestamp();
    END IF;
    RETURN NEW;
END;
$$;

-- 2. Proof lineage.
--
-- root_issuer_application_id owns the subject token every hop inherits; for a
-- direct proof it is the issuer. chain lists the ancestor proofs, root first,
-- with the epochs and endpoint versions each hop was issued under.
-- downstream_grant is the declared closure captured when a root proof is
-- issued; later catalog edits can narrow a running chain but never widen it.
-- Lineage ids are deliberately not foreign keys: retention removes a consumed
-- ancestor before its descendants' retention markers pass.
ALTER TABLE iam.obo_proofs
    ADD COLUMN root_issuer_application_id text,
    ADD COLUMN chain_depth smallint NOT NULL DEFAULT 0,
    ADD COLUMN parent_proof_id uuid,
    ADD COLUMN root_proof_id uuid,
    ADD COLUMN chain jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN chain_not_after timestamptz,
    ADD COLUMN downstream_grant jsonb;

-- The testing plane forces row security on its owner. Backfill every row,
-- then restore the original flags; ALTER TABLE holds its lock until commit.
DO $$
DECLARE
    row_security boolean;
    forced_row_security boolean;
BEGIN
    SELECT relrowsecurity, relforcerowsecurity INTO STRICT row_security, forced_row_security
    FROM pg_catalog.pg_class WHERE oid = 'iam.obo_proofs'::regclass;
    ALTER TABLE iam.obo_proofs NO FORCE ROW LEVEL SECURITY;
    ALTER TABLE iam.obo_proofs DISABLE ROW LEVEL SECURITY;
    UPDATE iam.obo_proofs SET root_issuer_application_id = issuer_application_id;
    IF row_security THEN
        ALTER TABLE iam.obo_proofs ENABLE ROW LEVEL SECURITY;
    END IF;
    IF forced_row_security THEN
        ALTER TABLE iam.obo_proofs FORCE ROW LEVEL SECURITY;
    END IF;
END;
$$;

ALTER TABLE iam.obo_proofs
    ALTER COLUMN root_issuer_application_id SET NOT NULL,
    ADD CONSTRAINT obo_proofs_chain_shape CHECK (
        chain_depth BETWEEN 0 AND 10
        AND jsonb_typeof(chain) = 'array'
        AND jsonb_array_length(chain) = chain_depth
        AND (downstream_grant IS NULL OR jsonb_typeof(downstream_grant) = 'array')
        AND (
            (chain_depth = 0
             AND root_issuer_application_id = issuer_application_id
             AND parent_proof_id IS NULL AND root_proof_id IS NULL
             AND chain_not_after IS NULL)
            OR (chain_depth > 0
                AND root_issuer_application_id <> issuer_application_id
                AND downstream_grant IS NULL
                AND chain_not_after IS NOT NULL
                AND expires_at <= chain_not_after)
        )
    );

-- The subject token belongs to the root issuer, not to a chained issuer.
DO $$
BEGIN
    ALTER TABLE iam.obo_proofs DROP CONSTRAINT obo_proofs_parent_token_fk;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute
        WHERE attrelid = 'iam.obo_proofs'::regclass
          AND attname = 'testing_environment_id' AND attnum > 0 AND NOT attisdropped
    ) THEN
        ALTER TABLE iam.obo_proofs ADD CONSTRAINT obo_proofs_parent_token_fk
            FOREIGN KEY (testing_environment_id, parent_access_token_id, subject_principal_id, root_issuer_application_id)
            REFERENCES iam.access_tokens(testing_environment_id, id, subject_principal_id, client_application_id)
            ON DELETE RESTRICT;
    ELSE
        ALTER TABLE iam.obo_proofs ADD CONSTRAINT obo_proofs_parent_token_fk
            FOREIGN KEY (parent_access_token_id, subject_principal_id, root_issuer_application_id)
            REFERENCES iam.access_tokens(id, subject_principal_id, client_application_id)
            ON DELETE RESTRICT;
    END IF;
END;
$$;

CREATE INDEX obo_proofs_parent_proof_idx ON iam.obo_proofs(parent_proof_id)
    WHERE parent_proof_id IS NOT NULL;
CREATE INDEX obo_proofs_root_proof_idx ON iam.obo_proofs(root_proof_id)
    WHERE root_proof_id IS NOT NULL;

CREATE OR REPLACE FUNCTION iam_private.enforce_selected_obo_parent_binding()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.parent_access_token_id, NEW.subject_principal_id,
               NEW.issuer_application_id, NEW.organization_id, NEW.membership_id,
               NEW.root_issuer_application_id, NEW.chain_depth, NEW.parent_proof_id,
               NEW.root_proof_id, NEW.chain, NEW.chain_not_after, NEW.downstream_grant)
           IS DISTINCT FROM
           ROW(OLD.parent_access_token_id, OLD.subject_principal_id,
               OLD.issuer_application_id, OLD.organization_id, OLD.membership_id,
               OLD.root_issuer_application_id, OLD.chain_depth, OLD.parent_proof_id,
               OLD.root_proof_id, OLD.chain, OLD.chain_not_after, OLD.downstream_grant) THEN
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
          AND parent.client_application_id = NEW.root_issuer_application_id
          AND iam_private.application_token_allows_membership(parent.id, member.id)
    ) THEN
        RAISE EXCEPTION 'obo_parent_organization_not_selected' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.enforce_selected_obo_parent_binding() FROM PUBLIC;

DROP TRIGGER obo_proofs_selected_parent_binding ON iam.obo_proofs;
CREATE TRIGGER obo_proofs_selected_parent_binding
BEFORE INSERT OR UPDATE OF parent_access_token_id, subject_principal_id, issuer_application_id,
    organization_id, membership_id, root_issuer_application_id, chain_depth, parent_proof_id,
    root_proof_id, chain, chain_not_after, downstream_grant
ON iam.obo_proofs
FOR EACH ROW EXECUTE FUNCTION iam_private.enforce_selected_obo_parent_binding();

-- 3. Declared closure.
--
-- Edges reachable from one endpoint within ten hops. Cycles are refused when a
-- hop is issued; here they only need to terminate, which the depth bound and
-- UNION's duplicate elimination guarantee. Invoker rights: callers are
-- definer functions and triggers.
CREATE FUNCTION iam_private.application_obo_downstream_edges(
    p_issuer text, p_audience text, p_endpoint text
) RETURNS TABLE(from_app text, from_endpoint text, app text, endpoint text)
LANGUAGE sql
STABLE
SET search_path = pg_catalog, iam, iam_private
AS $$
    WITH RECURSIVE reachable(from_app, from_endpoint, app, endpoint, depth) AS (
        SELECT source.application_id, source.endpoint_id,
               target.application_id, target.endpoint_id, 1
        FROM iam.application_obo_endpoints AS source
        CROSS JOIN LATERAL jsonb_to_recordset(source.downstream) AS item(audience text, endpoint_id text)
        JOIN iam.application_obo_endpoints AS target
          ON target.application_id = item.audience
         AND target.endpoint_id = item.endpoint_id
         AND target.status = 'active'
        WHERE source.application_id = p_audience
          AND source.endpoint_id = p_endpoint
          AND source.status = 'active'
          AND target.application_id <> p_issuer
        UNION
        SELECT source.application_id, source.endpoint_id,
               target.application_id, target.endpoint_id, reachable.depth + 1
        FROM reachable
        JOIN iam.application_obo_endpoints AS source
          ON source.application_id = reachable.app
         AND source.endpoint_id = reachable.endpoint
         AND source.status = 'active'
        CROSS JOIN LATERAL jsonb_to_recordset(source.downstream) AS item(audience text, endpoint_id text)
        JOIN iam.application_obo_endpoints AS target
          ON target.application_id = item.audience
         AND target.endpoint_id = item.endpoint_id
         AND target.status = 'active'
        WHERE reachable.depth < 10
          AND target.application_id <> p_issuer
          AND target.application_id <> p_audience
    )
    SELECT DISTINCT reachable.from_app, reachable.from_endpoint, reachable.app, reachable.endpoint
    FROM reachable;
$$;
REVOKE ALL ON FUNCTION iam_private.application_obo_downstream_edges(text, text, text) FROM PUBLIC;

-- A direct proof's token belongs to its issuer, and a root proof captures its
-- closure at issuance, inside the exchange that the subject's consent
-- authorized. Direct exchange SQL is unchanged. This trigger sorts before
-- obo_proofs_selected_parent_binding, which reads the defaulted root issuer.
CREATE FUNCTION iam_private.prepare_obo_proof_lineage()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
BEGIN
    NEW.root_issuer_application_id := COALESCE(NEW.root_issuer_application_id, NEW.issuer_application_id);
    IF NEW.chain_depth = 0 THEN
        SELECT jsonb_agg(jsonb_build_object(
                   'from_app', edge.from_app, 'from_endpoint', edge.from_endpoint,
                   'app', edge.app, 'endpoint', edge.endpoint)
               ORDER BY edge.from_app, edge.from_endpoint, edge.app, edge.endpoint)
        INTO NEW.downstream_grant
        FROM iam_private.application_obo_downstream_edges(
            NEW.issuer_application_id, NEW.audience_application_id, NEW.endpoint_id
        ) AS edge;
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.prepare_obo_proof_lineage() FROM PUBLIC;

CREATE TRIGGER obo_proofs_lineage
BEFORE INSERT ON iam.obo_proofs
FOR EACH ROW EXECUTE FUNCTION iam_private.prepare_obo_proof_lineage();

-- 4. Chain integrity.
--
-- True when every ancestor of a chained proof still stands: the subject token
-- still carries the consented root delegation, no ancestor was revoked, every
-- application in the chain keeps the auth epoch its hop was issued under,
-- every ancestor endpoint is still active at its pinned version, every chained
-- issuer still holds its approved scope for its hop, and every audience may
-- still act for the subject in this organization. The caller installs the
-- subject context. Invoker rights: callers are definer functions.
CREATE FUNCTION iam_private.application_obo_chain_is_intact(p_proof_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT COALESCE((
        SELECT proof.chain_depth > 0
           AND proof.chain->0->>'issuer_application_id' = proof.root_issuer_application_id
           AND iam_private.application_token_allows_external_scope(
               proof.parent_access_token_id,
               proof.chain->0->>'audience_application_id',
               proof.chain->0->>'endpoint_id')
           AND EXISTS (
               SELECT 1 FROM iam.application_approved_scopes AS approved
               WHERE approved.application_id = proof.issuer_application_id
                 AND approved.scope = 'obo:' || proof.audience_application_id || ':' || proof.endpoint_id
                 AND approved.revoked_at IS NULL)
           AND iam_private.application_allows_subject(
               proof.audience_application_id, proof.subject_principal_id, proof.organization_id)
           AND NOT EXISTS (
               SELECT 1
               FROM jsonb_array_elements(proof.chain) WITH ORDINALITY AS link(value, position)
               LEFT JOIN iam.obo_proofs AS ancestor
                 ON ancestor.id = (link.value->>'proof_id')::uuid
                AND ancestor.revoked_at IS NULL
                AND ancestor.consumed_at IS NOT NULL
                AND ancestor.consumed_by_application_id = link.value->>'audience_application_id'
                AND ancestor.issuer_application_id = link.value->>'issuer_application_id'
                AND ancestor.subject_principal_id = proof.subject_principal_id
                AND ancestor.organization_id = proof.organization_id
                AND ancestor.parent_access_token_id = proof.parent_access_token_id
                AND ancestor.chain_depth = link.position - 1
               LEFT JOIN iam.applications AS issuer_application
                 ON issuer_application.id = link.value->>'issuer_application_id'
                AND issuer_application.review_status = 'verified'
                AND issuer_application.deleted_at IS NULL
               LEFT JOIN iam.principals AS issuer
                 ON issuer.id = issuer_application.id
                AND issuer.kind = 'application' AND issuer.status = 'active'
                AND issuer.auth_epoch = (link.value->>'issuer_auth_epoch')::bigint
               LEFT JOIN iam.applications AS audience_application
                 ON audience_application.id = link.value->>'audience_application_id'
                AND audience_application.review_status = 'verified'
                AND audience_application.deleted_at IS NULL
               LEFT JOIN iam.principals AS audience
                 ON audience.id = audience_application.id
                AND audience.kind = 'application' AND audience.status = 'active'
                AND audience.auth_epoch = (link.value->>'audience_auth_epoch')::bigint
               LEFT JOIN iam.application_obo_endpoints AS endpoint
                 ON endpoint.application_id = audience_application.id
                AND endpoint.endpoint_id = link.value->>'endpoint_id'
                AND endpoint.version = (link.value->>'endpoint_version')::bigint
                AND endpoint.status = 'active'
               WHERE ancestor.id IS NULL OR issuer.id IS NULL OR audience.id IS NULL
                  OR endpoint.application_id IS NULL
                  OR NOT iam_private.application_allows_subject(
                      audience_application.id, proof.subject_principal_id, proof.organization_id)
                  OR (link.position > 1 AND NOT EXISTS (
                      SELECT 1 FROM iam.application_approved_scopes AS approved
                      WHERE approved.application_id = issuer_application.id
                        AND approved.scope = 'obo:' || audience_application.id || ':' || endpoint.endpoint_id
                        AND approved.revoked_at IS NULL))
           )
        FROM iam.obo_proofs AS proof
        WHERE proof.id = p_proof_id
    ), false);
$$;
REVOKE ALL ON FUNCTION iam_private.application_obo_chain_is_intact(uuid) FROM PUBLIC;

-- 5. Chained exchange.
--
-- The caller must be the application that consumed the parent proof, so no
-- new bearer secret exists. Resolution runs in application context and
-- returns only what the caller needs to install the subject context.
CREATE FUNCTION iam_private.resolve_application_obo_chain_parent(p_parent_proof_id uuid)
RETURNS TABLE(organization_id uuid, membership_id uuid, subject_principal_id text, subject_kind text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT proof.organization_id, proof.membership_id,
           proof.subject_principal_id, proof.subject_kind::text
    FROM iam.obo_proofs AS proof
    WHERE proof.id = p_parent_proof_id
      AND proof.consumed_at IS NOT NULL
      AND proof.consumed_by_application_id = iam_private.current_application_id()
      AND iam_private.current_application_id() = iam_private.current_principal_id();
$$;
REVOKE ALL ON FUNCTION iam_private.resolve_application_obo_chain_parent(uuid) FROM PUBLIC;

CREATE FUNCTION iam_private.lock_application_obo_chained_exchange_authority(
    p_caller text,
    p_caller_auth_epoch bigint,
    p_parent_proof_id uuid,
    p_audience_app_id text,
    p_endpoint_id text
)
RETURNS TABLE (
    audience_application_id text,
    endpoint_path text,
    metadata_definition jsonb,
    endpoint_version bigint,
    ttl_seconds integer,
    audience_auth_epoch bigint,
    subject_auth_epoch bigint,
    membership_authz_epoch bigint,
    parent_access_token_id uuid,
    root_issuer_application_id text,
    root_proof_id uuid,
    chain_depth smallint,
    chain jsonb,
    window_ends_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    v_parent iam.obo_proofs%ROWTYPE;
    v_root iam.obo_proofs%ROWTYPE;
    v_root_id uuid;
    v_chain jsonb;
    v_chain_apps text[];
    v_downstream jsonb;
    v_downstream_ttl_seconds integer;
    v_window_ends_at timestamptz;
BEGIN
    IF p_caller IS NULL OR p_parent_proof_id IS NULL OR p_audience_app_id IS NULL
       OR p_endpoint_id IS NULL
       OR p_caller IS DISTINCT FROM iam_private.current_application_id() THEN
        RAISE EXCEPTION 'application_obo_chain_authority_forbidden' USING ERRCODE = '42501';
    END IF;

    -- Lineage is immutable, so an unlocked read may choose the lock order.
    SELECT * INTO v_parent FROM iam.obo_proofs AS proof
    WHERE proof.id = p_parent_proof_id
      AND proof.consumed_at IS NOT NULL
      AND proof.consumed_by_application_id = p_caller;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'obo_subject_proof_not_found' USING ERRCODE = 'P0001';
    END IF;
    IF v_parent.subject_principal_id IS DISTINCT FROM iam_private.current_principal_id()
       OR v_parent.organization_id IS DISTINCT FROM iam_private.current_organization_id() THEN
        RAISE EXCEPTION 'application_obo_chain_authority_forbidden' USING ERRCODE = '42501';
    END IF;
    IF v_parent.chain_depth >= 10 THEN
        RAISE EXCEPTION 'obo_chain_depth_exceeded' USING ERRCODE = 'P0001';
    END IF;
    v_root_id := CASE WHEN v_parent.chain_depth = 0 THEN v_parent.id ELSE v_parent.root_proof_id END;
    IF v_root_id IS NULL THEN
        RAISE EXCEPTION 'obo_proof_revoked' USING ERRCODE = 'P0001';
    END IF;

    v_chain := v_parent.chain || jsonb_build_array(jsonb_build_object(
        'proof_id', v_parent.id,
        'issuer_application_id', v_parent.issuer_application_id,
        'issuer_auth_epoch', v_parent.issuer_auth_epoch,
        'audience_application_id', v_parent.audience_application_id,
        'audience_auth_epoch', v_parent.audience_auth_epoch,
        'endpoint_id', v_parent.endpoint_id,
        'endpoint_version', v_parent.endpoint_version
    ));
    SELECT array_agg(DISTINCT member.application_id) INTO v_chain_apps
    FROM jsonb_array_elements(v_chain) AS link(value)
    CROSS JOIN LATERAL (VALUES
        (link.value->>'issuer_application_id'),
        (link.value->>'audience_application_id')
    ) AS member(application_id);
    IF p_audience_app_id = ANY(v_chain_apps) THEN
        RAISE EXCEPTION 'obo_chain_cycle' USING ERRCODE = 'P0001';
    END IF;

    -- Administration locks applications before scopes, revocations and proofs.
    PERFORM application.id
    FROM iam.applications AS application
    JOIN iam.principals AS principal ON principal.id = application.id
    WHERE application.id = ANY(v_chain_apps || p_audience_app_id)
    ORDER BY application.id
    FOR SHARE OF application, principal;

    -- Every hop of one delegation tree serializes on its root, which makes the
    -- per-parent and per-root budgets exact under concurrency.
    SELECT * INTO v_root FROM iam.obo_proofs AS proof WHERE proof.id = v_root_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'obo_proof_revoked' USING ERRCODE = 'P0001';
    END IF;
    IF v_root_id = v_parent.id THEN
        v_parent := v_root;
    ELSE
        SELECT * INTO STRICT v_parent FROM iam.obo_proofs AS proof
        WHERE proof.id = p_parent_proof_id FOR UPDATE;
    END IF;
    IF v_parent.revoked_at IS NOT NULL OR v_root.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'obo_proof_revoked' USING ERRCODE = 'P0001';
    END IF;

    -- The parent endpoint must still be the version the parent was issued
    -- under; its declaration and the root's captured closure must both name
    -- this exact downstream call.
    SELECT endpoint.downstream, endpoint.downstream_ttl_seconds
    INTO v_downstream, v_downstream_ttl_seconds
    FROM iam.application_obo_endpoints AS endpoint
    WHERE endpoint.application_id = v_parent.audience_application_id
      AND endpoint.endpoint_id = v_parent.endpoint_id
      AND endpoint.path = v_parent.request_path
      AND endpoint.version = v_parent.endpoint_version
      AND endpoint.status = 'active'
    FOR SHARE OF endpoint;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'obo_proof_revoked' USING ERRCODE = 'P0001';
    END IF;
    IF NOT v_downstream @> jsonb_build_array(jsonb_build_object(
           'audience', p_audience_app_id, 'endpoint_id', p_endpoint_id))
       OR v_root.downstream_grant IS NULL
       OR NOT v_root.downstream_grant @> jsonb_build_array(jsonb_build_object(
           'from_app', v_parent.audience_application_id, 'from_endpoint', v_parent.endpoint_id,
           'app', p_audience_app_id, 'endpoint', p_endpoint_id)) THEN
        RAISE EXCEPTION 'obo_chain_endpoint_not_declared' USING ERRCODE = 'P0001';
    END IF;

    -- The window starts when the caller consumed the parent, never outlives an
    -- ancestor's window, and never outlives the subject's token.
    SELECT LEAST(
        v_parent.consumed_at + make_interval(secs => COALESCE(v_downstream_ttl_seconds, 300)),
        COALESCE(v_parent.chain_not_after, 'infinity'::timestamptz),
        token.expires_at
    )
    INTO v_window_ends_at
    FROM iam.access_tokens AS token
    WHERE token.id = v_parent.parent_access_token_id;
    IF v_window_ends_at IS NULL OR v_window_ends_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'obo_chain_window_closed' USING ERRCODE = 'P0001';
    END IF;

    IF (SELECT count(*) FROM iam.obo_proofs AS child WHERE child.parent_proof_id = v_parent.id) >= 8 THEN
        RAISE EXCEPTION 'obo_chain_use_limit' USING ERRCODE = 'P0001';
    END IF;
    IF (SELECT count(*) FROM iam.obo_proofs AS child WHERE child.root_proof_id = v_root.id) >= 32 THEN
        RAISE EXCEPTION 'obo_chain_budget_exhausted' USING ERRCODE = 'P0001';
    END IF;

    -- The caller must hold this downstream call in its own approved scope.
    PERFORM 1
    FROM iam.application_approved_scopes AS approved
    WHERE approved.application_id = p_caller
      AND approved.scope = 'obo:' || p_audience_app_id || ':' || p_endpoint_id
      AND approved.revoked_at IS NULL
    FOR SHARE OF approved;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'obo_chain_scope_not_approved' USING ERRCODE = 'P0001';
    END IF;

    -- Everything the parent stood on must still stand.
    IF v_parent.chain_depth = 0 AND NOT iam_private.application_token_allows_external_scope(
           v_parent.parent_access_token_id, v_parent.audience_application_id, v_parent.endpoint_id) THEN
        RAISE EXCEPTION 'obo_proof_revoked' USING ERRCODE = 'P0001';
    ELSIF v_parent.chain_depth > 0 AND NOT iam_private.application_obo_chain_is_intact(v_parent.id) THEN
        RAISE EXCEPTION 'obo_proof_revoked' USING ERRCODE = 'P0001';
    END IF;

    RETURN QUERY
    WITH wall_clock AS MATERIALIZED (
        SELECT clock_timestamp() AS value
    )
    SELECT audience.id,
           endpoint.path,
           endpoint.metadata_definition,
           endpoint.version,
           endpoint.ttl_seconds,
           audience_principal.auth_epoch,
           subject_principal.auth_epoch,
           membership.authz_epoch,
           parent.id,
           root_issuer.id,
           v_root.id,
           (v_parent.chain_depth + 1)::smallint,
           v_chain,
           v_window_ends_at
    FROM wall_clock
    JOIN iam.organizations AS organization
      ON organization.id = v_parent.organization_id
     AND organization.status = 'active'
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = organization.id
     AND membership.id = v_parent.membership_id
     AND membership.principal_id = v_parent.subject_principal_id
     AND membership.principal_kind = v_parent.subject_kind
     AND membership.status = 'active'
     AND membership.authz_epoch = v_parent.membership_authz_epoch
    JOIN iam.principals AS subject_principal
      ON subject_principal.id = membership.principal_id
     AND subject_principal.kind = membership.principal_kind
     AND subject_principal.status = 'active'
     AND subject_principal.auth_epoch = v_parent.subject_auth_epoch
    JOIN iam.applications AS root_issuer
      ON root_issuer.id = v_parent.root_issuer_application_id
     AND root_issuer.review_status = 'verified'
     AND root_issuer.deleted_at IS NULL
    JOIN iam.principals AS root_issuer_principal
      ON root_issuer_principal.id = root_issuer.id
     AND root_issuer_principal.kind = 'application'
     AND root_issuer_principal.status = 'active'
     AND root_issuer_principal.auth_epoch = v_root.issuer_auth_epoch
    JOIN iam.principals AS parent_issuer_principal
      ON parent_issuer_principal.id = v_parent.issuer_application_id
     AND parent_issuer_principal.kind = 'application'
     AND parent_issuer_principal.status = 'active'
     AND parent_issuer_principal.auth_epoch = v_parent.issuer_auth_epoch
    JOIN iam.access_tokens AS parent
      ON parent.id = v_parent.parent_access_token_id
     AND parent.token_class = 'application_access'
     AND iam_private.application_token_allows_membership(parent.id, membership.id)
     AND parent.client_application_id = root_issuer.id
     AND parent.audience_application_id = root_issuer.id
     AND parent.audience = root_issuer.app_id
     AND parent.subject_principal_id = subject_principal.id
     AND parent.subject_kind = subject_principal.kind
     AND (
         (parent.organization_id = organization.id
          AND parent.membership_id = membership.id
          AND parent.membership_authz_epoch = membership.authz_epoch)
         OR (parent.organization_id IS NULL
             AND parent.membership_id IS NULL
             AND parent.membership_authz_epoch IS NULL)
     )
     AND parent.subject_auth_epoch = subject_principal.auth_epoch
     AND parent.client_auth_epoch = root_issuer_principal.auth_epoch
     AND parent.revoked_at IS NULL
     AND parent.expires_at > wall_clock.value
    JOIN iam.authentication_sessions AS authentication_session
      ON authentication_session.id = parent.authentication_session_id
     AND authentication_session.subject_principal_id = subject_principal.id
     AND authentication_session.subject_kind = subject_principal.kind
     AND authentication_session.subject_auth_epoch = subject_principal.auth_epoch
     AND authentication_session.status = 'active'
     AND authentication_session.idle_expires_at > wall_clock.value
     AND authentication_session.absolute_expires_at > wall_clock.value
    JOIN iam.applications AS caller
      ON caller.id = p_caller
     AND caller.review_status = 'verified'
     AND caller.deleted_at IS NULL
    JOIN iam.principals AS caller_principal
      ON caller_principal.id = caller.id
     AND caller_principal.kind = 'application'
     AND caller_principal.status = 'active'
     AND caller_principal.auth_epoch = p_caller_auth_epoch
     AND caller_principal.auth_epoch = v_parent.audience_auth_epoch
    JOIN iam.applications AS audience
      ON audience.app_id = p_audience_app_id
     AND audience.review_status = 'verified'
     AND audience.deleted_at IS NULL
    JOIN iam.principals AS audience_principal
      ON audience_principal.id = audience.id
     AND audience_principal.kind = 'application'
     AND audience_principal.status = 'active'
    JOIN iam.application_obo_endpoints AS endpoint
      ON endpoint.application_id = audience.id
     AND endpoint.endpoint_id = p_endpoint_id
     AND endpoint.status = 'active'
    WHERE iam_private.application_allows_subject(audience.id, subject_principal.id, organization.id)
    FOR SHARE OF organization, membership, subject_principal, root_issuer,
                 root_issuer_principal, parent_issuer_principal, parent,
                 authentication_session, caller, caller_principal, audience,
                 audience_principal, endpoint;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.lock_application_obo_chained_exchange_authority(text, bigint, uuid, text, text) FROM PUBLIC;

-- An idempotent chained replay is live only while its proof could still be
-- verified: unconsumed, unexpired, and standing on an intact chain. The bound
-- path is returned so the caller can recheck the replayed request signature;
-- NULL means the replay is no longer live.
CREATE FUNCTION iam_private.application_obo_chained_replay_path(uuid, text, uuid)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    WITH wall_clock AS MATERIALIZED (
        SELECT clock_timestamp() AS value
    )
    SELECT (
        SELECT proof.request_path
        FROM wall_clock
        JOIN iam.obo_proofs AS proof ON TRUE
        JOIN iam.applications AS issuer_application
          ON issuer_application.id = proof.issuer_application_id
         AND issuer_application.review_status = 'verified'
         AND issuer_application.deleted_at IS NULL
        JOIN iam.principals AS issuer
          ON issuer.id = issuer_application.id
         AND issuer.kind = 'application'
         AND issuer.status = 'active'
         AND issuer.auth_epoch = proof.issuer_auth_epoch
        JOIN iam.applications AS audience_application
          ON audience_application.id = proof.audience_application_id
         AND audience_application.review_status = 'verified'
         AND audience_application.deleted_at IS NULL
        JOIN iam.principals AS audience
          ON audience.id = audience_application.id
         AND audience.kind = 'application'
         AND audience.status = 'active'
         AND audience.auth_epoch = proof.audience_auth_epoch
        JOIN iam.principals AS subject
          ON subject.id = proof.subject_principal_id
         AND subject.kind = proof.subject_kind
         AND subject.status = 'active'
         AND subject.auth_epoch = proof.subject_auth_epoch
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = proof.organization_id
         AND membership.id = proof.membership_id
         AND membership.principal_id = proof.subject_principal_id
         AND membership.principal_kind = proof.subject_kind
         AND membership.status = 'active'
         AND membership.authz_epoch = proof.membership_authz_epoch
        JOIN iam.principals AS root_issuer
          ON root_issuer.id = proof.root_issuer_application_id
         AND root_issuer.kind = 'application'
         AND root_issuer.status = 'active'
         AND root_issuer.auth_epoch = (proof.chain->0->>'issuer_auth_epoch')::bigint
        JOIN iam.access_tokens AS parent
          ON parent.id = proof.parent_access_token_id
         AND parent.client_application_id = proof.root_issuer_application_id
         AND parent.subject_auth_epoch = subject.auth_epoch
         AND (
             (parent.organization_id = proof.organization_id
              AND parent.membership_id = proof.membership_id
              AND parent.membership_authz_epoch = membership.authz_epoch)
             OR (parent.organization_id IS NULL
                 AND parent.membership_id IS NULL
                 AND parent.membership_authz_epoch IS NULL)
         )
         AND iam_private.application_token_allows_membership(parent.id, membership.id)
         AND parent.client_auth_epoch = root_issuer.auth_epoch
         AND parent.revoked_at IS NULL
         AND parent.expires_at > wall_clock.value
        JOIN iam.authentication_sessions AS session
          ON session.id = parent.authentication_session_id
         AND session.status = 'active'
         AND session.idle_expires_at > wall_clock.value
         AND session.absolute_expires_at > wall_clock.value
        JOIN iam.application_obo_endpoints AS endpoint
          ON endpoint.application_id = proof.audience_application_id
         AND endpoint.endpoint_id = proof.endpoint_id
         AND endpoint.path = proof.request_path
         AND endpoint.version = proof.endpoint_version
         AND endpoint.status = 'active'
        WHERE proof.id = $1
          AND proof.issuer_application_id = $2
          AND proof.organization_id = $3
          AND proof.chain_depth > 0
          AND proof.consumed_at IS NULL
          AND proof.revoked_at IS NULL
          AND proof.expires_at > wall_clock.value
          AND proof.issuer_application_id = iam_private.current_application_id()
          AND iam_private.application_obo_chain_is_intact(proof.id)
    );
$$;
REVOKE ALL ON FUNCTION iam_private.application_obo_chained_replay_path(uuid, text, uuid) FROM PUBLIC;

-- 6. Verification.
--
-- v2 adds lineage to the audience lookup; v1 stays for deployed consumers.
CREATE FUNCTION iam_private.lookup_application_obo_proof_v2(smallint[], bytea[], text)
RETURNS TABLE(id uuid, proof_digest bytea, digest_key_version smallint,
    issuer_application_id text, issuer_app_id text, subject_principal_id text,
    subject_kind text, organization_id uuid, membership_id uuid,
    parent_access_token_id uuid, endpoint_id text, request_method text,
    request_path text, request_body_sha256 bytea, endpoint_version bigint,
    request_metadata jsonb, subject_auth_epoch bigint, membership_authz_epoch bigint,
    issuer_auth_epoch bigint, audience_auth_epoch bigint, expires_at timestamptz,
    checked_at timestamptz, consumed_at timestamptz, revoked_at timestamptz,
    chain_depth smallint, chain jsonb)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    WITH supplied_digest (key_version, digest) AS (
        SELECT * FROM unnest($1::smallint[], $2::bytea[])
    )
    SELECT proof.id, proof.proof_digest, proof.digest_key_version,
           proof.issuer_application_id, issuer.app_id AS issuer_app_id,
           proof.subject_principal_id,
           proof.subject_kind::text AS subject_kind,
           proof.organization_id,
           proof.membership_id, proof.parent_access_token_id, proof.endpoint_id,
           proof.request_method, proof.request_path, proof.request_body_sha256,
           proof.endpoint_version, proof.request_metadata,
           proof.subject_auth_epoch, proof.membership_authz_epoch,
           proof.issuer_auth_epoch, proof.audience_auth_epoch,
           proof.expires_at, clock_timestamp() AS checked_at,
           proof.consumed_at, proof.revoked_at,
           proof.chain_depth, proof.chain
    FROM supplied_digest
    JOIN iam.obo_proofs AS proof
      ON proof.digest_key_version = supplied_digest.key_version
     AND proof.proof_digest = supplied_digest.digest
    JOIN iam.applications AS issuer
      ON issuer.id = proof.issuer_application_id
    JOIN iam.application_obo_endpoints AS endpoint
      ON endpoint.application_id = proof.audience_application_id
     AND endpoint.endpoint_id = proof.endpoint_id
     AND endpoint.path = proof.request_path
    WHERE proof.audience_application_id = $3
      AND $3 = iam_private.current_application_id()
      AND $3 = iam_private.current_principal_id();
$$;
REVOKE ALL ON FUNCTION iam_private.lookup_application_obo_proof_v2(smallint[], bytea[], text) FROM PUBLIC;

-- The chained counterpart of application_obo_load_current_context. The
-- subject token belongs to the root issuer, and the chain must be intact.
CREATE FUNCTION iam_private.application_obo_load_chained_context(p_proof_id uuid)
RETURNS TABLE(org_id text, subject_public_id text, subject_auth_epoch bigint,
    membership_authz_epoch bigint, issuer_auth_epoch bigint, audience_auth_epoch bigint,
    parent_active boolean, endpoint_active boolean)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    WITH wall_clock AS MATERIALIZED (
        SELECT clock_timestamp() AS value
    )
    SELECT organization.org_id,
           COALESCE(carbon.carbon_id, silicon.global_silicon_id) AS subject_public_id,
           subject.auth_epoch AS subject_auth_epoch,
           membership.authz_epoch AS membership_authz_epoch,
           issuer.auth_epoch AS issuer_auth_epoch,
           audience.auth_epoch AS audience_auth_epoch,
           EXISTS (
               SELECT 1
               FROM iam.access_tokens AS parent
               JOIN iam.principals AS root_issuer
                 ON root_issuer.id = parent.client_application_id
                AND root_issuer.kind = 'application'
                AND root_issuer.status = 'active'
               JOIN iam.authentication_sessions AS session
                 ON session.id = parent.authentication_session_id
                AND session.status = 'active'
                AND session.idle_expires_at > wall_clock.value
                AND session.absolute_expires_at > wall_clock.value
               WHERE parent.id = proof.parent_access_token_id
                 AND parent.client_application_id = proof.root_issuer_application_id
                 AND parent.subject_principal_id = proof.subject_principal_id
                 AND parent.subject_auth_epoch = subject.auth_epoch
                 AND (
                     (parent.organization_id = proof.organization_id
                      AND parent.membership_id = proof.membership_id
                      AND parent.membership_authz_epoch = membership.authz_epoch)
                     OR (parent.organization_id IS NULL
                         AND parent.membership_id IS NULL
                         AND parent.membership_authz_epoch IS NULL)
                 )
                 AND parent.client_auth_epoch = root_issuer.auth_epoch
                 AND root_issuer.auth_epoch = (proof.chain->0->>'issuer_auth_epoch')::bigint
                 AND parent.revoked_at IS NULL
                 AND parent.expires_at > wall_clock.value
                 AND iam_private.application_token_allows_membership(parent.id, proof.membership_id)
           ) AND iam_private.application_obo_chain_is_intact(proof.id) AS parent_active,
           (endpoint.path = proof.request_path AND endpoint.version = proof.endpoint_version
            AND endpoint.status = 'active') AS endpoint_active
    FROM wall_clock
    JOIN iam.obo_proofs AS proof
      ON proof.id = p_proof_id
     AND proof.chain_depth > 0
    JOIN iam.organizations AS organization
      ON organization.id = proof.organization_id
     AND organization.status = 'active'
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = organization.id
     AND membership.id = proof.membership_id
     AND membership.principal_id = proof.subject_principal_id
     AND membership.principal_kind = proof.subject_kind
     AND membership.status = 'active'
    JOIN iam.principals AS subject
      ON subject.id = membership.principal_id
     AND subject.kind = membership.principal_kind
     AND subject.status = 'active'
    LEFT JOIN iam.carbons AS carbon
      ON carbon.id = subject.id
     AND subject.kind = 'carbon'
     AND carbon.deleted_at IS NULL
    LEFT JOIN iam.silicons AS silicon
      ON silicon.id = subject.id
     AND subject.kind = 'silicon'
     AND silicon.organization_id = organization.id
     AND silicon.membership_id = membership.id
     AND silicon.provisioning_status = 'active'
     AND silicon.deleted_at IS NULL
    JOIN iam.applications AS issuer_application
      ON issuer_application.id = proof.issuer_application_id
     AND issuer_application.review_status = 'verified'
     AND issuer_application.deleted_at IS NULL
    JOIN iam.principals AS issuer
      ON issuer.id = issuer_application.id
     AND issuer.kind = 'application'
     AND issuer.status = 'active'
    JOIN iam.applications AS audience_application
      ON audience_application.id = proof.audience_application_id
     AND audience_application.review_status = 'verified'
     AND audience_application.deleted_at IS NULL
    JOIN iam.principals AS audience
      ON audience.id = audience_application.id
     AND audience.kind = 'application'
     AND audience.status = 'active'
    JOIN iam.application_obo_endpoints AS endpoint
      ON endpoint.application_id = audience_application.id
     AND endpoint.endpoint_id = proof.endpoint_id
    WHERE proof.audience_application_id = iam_private.current_application_id()
      AND proof.subject_principal_id = iam_private.current_principal_id()
      AND proof.organization_id = iam_private.current_organization_id()
      AND (
          (subject.kind = 'carbon' AND carbon.id IS NOT NULL)
          OR (subject.kind = 'silicon' AND silicon.id IS NOT NULL)
      );
$$;
REVOKE ALL ON FUNCTION iam_private.application_obo_load_chained_context(uuid) FROM PUBLIC;

-- Delegated disclosure for chained proofs. The subject token belongs to the
-- root issuer; the chain must be intact; a self disclosure survives only when
-- every issuer in the chain holds it approved, in addition to the audience's
-- ceiling and the subject's consent to the root issuer. Direct proofs follow
-- exactly the previous path: for them root_issuer_application_id equals
-- issuer_application_id and the chained-issuer set is empty.
CREATE OR REPLACE FUNCTION iam_private.get_current_application_authorization(
    p_access_token_id uuid,
    p_subject_principal_id text,
    p_organization_id uuid,
    p_membership_id uuid,
    p_audience_application_id text,
    p_audience_auth_epoch bigint,
    p_proof_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE
    v_issuer_application_id text;
    v_parent_consent_id uuid;
    v_chain_issuers text[] := ARRAY[]::text[];
    subject_epoch bigint;
    issuer_epoch bigint;
    membership_epoch bigint;
    proof_consumed_at timestamptz;
    authorization_snapshot jsonb;
BEGIN
    IF p_access_token_id IS NULL OR p_subject_principal_id IS NULL
       OR p_organization_id IS NULL OR p_membership_id IS NULL
       OR p_audience_application_id IS NULL OR p_audience_auth_epoch IS NULL
       OR p_subject_principal_id IS DISTINCT FROM iam_private.current_principal_id()
       OR p_organization_id IS DISTINCT FROM iam_private.current_organization_id()
       OR p_audience_application_id IS DISTINCT FROM iam_private.current_application_id() THEN
        RAISE EXCEPTION 'application_authorization_context_forbidden'
            USING ERRCODE = '42501';
    END IF;

    -- Lineage is immutable; read it before locking to fix the lock order.
    IF p_proof_id IS NOT NULL THEN
        SELECT COALESCE(array_agg(hop.issuer ORDER BY hop.position), ARRAY[]::text[])
        INTO v_chain_issuers
        FROM iam.obo_proofs AS proof
        CROSS JOIN LATERAL (
            SELECT link.value->>'issuer_application_id', link.position
            FROM jsonb_array_elements(proof.chain) WITH ORDINALITY AS link(value, position)
            WHERE link.position > 1
            UNION ALL
            SELECT proof.issuer_application_id, 11
            WHERE proof.chain_depth > 0
        ) AS hop(issuer, position)
        WHERE proof.id = p_proof_id;
    END IF;

    -- Resolve only the exact supplied chain. A bound token must name this
    -- organization; an unscoped token reaches every organization it can prove
    -- an active membership in, and the locking read below rechecks that
    -- membership before returning any authority.
    SELECT token.client_application_id INTO v_issuer_application_id
    FROM iam.access_tokens AS token
    WHERE token.id = p_access_token_id
      AND token.subject_principal_id = p_subject_principal_id
      AND (
          (token.organization_id = p_organization_id
           AND token.membership_id = p_membership_id)
          OR (token.organization_id IS NULL AND token.membership_id IS NULL)
      )
      AND iam_private.application_token_allows_membership(token.id, p_membership_id)
      AND token.token_class = 'application_access'
      AND (p_proof_id IS NOT NULL OR token.client_application_id = p_audience_application_id);
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    -- Administration locks applications before scopes and revocations.
    -- Follow that order, sorting every application in a delegated request.
    PERFORM application.id
    FROM iam.applications AS application
    JOIN iam.principals AS principal ON principal.id = application.id
    WHERE application.id = ANY(ARRAY[v_issuer_application_id, p_audience_application_id] || v_chain_issuers)
    ORDER BY application.id
    FOR SHARE OF application, principal;


    WITH approved AS MATERIALIZED (
        SELECT scope
        FROM iam_private.locked_application_approved_scopes(p_audience_application_id)
    ), issuer_disclosures AS MATERIALIZED (
        SELECT approved.scope
        FROM iam.application_approved_scopes AS approved
        WHERE p_proof_id IS NOT NULL
          AND approved.application_id = v_issuer_application_id
          AND approved.revoked_at IS NULL
          AND approved.scope IN ('self.identity.read', 'self.membership.read', 'self.tags.read')
          AND NOT EXISTS (
              SELECT 1 FROM unnest(v_chain_issuers) AS hop(application_id)
              WHERE NOT EXISTS (
                  SELECT 1 FROM iam.application_approved_scopes AS hop_approved
                  WHERE hop_approved.application_id = hop.application_id
                    AND hop_approved.scope = approved.scope
                    AND hop_approved.revoked_at IS NULL
              )
          )
        FOR SHARE OF approved
    )
    SELECT jsonb_build_object(
        'principal_id', subject.id,
        'actor_type', subject.kind::text,
        'public_id', COALESCE(carbon.carbon_id, silicon.global_silicon_id),
        'organization_id', organization.id,
        'org_id', organization.org_id,
        'membership_id', membership.id,
        'membership_version', membership.version,
        'authorization_epoch', membership.authz_epoch,
        'audience', audience.app_id,
        'testing_environment_id', NULLIF(current_setting('iam.testing_environment_id', true), ''),
        'scopes', to_jsonb(effective.scopes),
        'org_role', CASE WHEN 'self.membership.read' = ANY(effective.scopes)
            THEN membership.org_role::text ELSE NULL END,
        'tags', CASE WHEN 'self.tags.read' = ANY(effective.scopes) THEN (
            SELECT COALESCE(jsonb_agg(jsonb_build_object('id', tag.id, 'name', tag.name)
                ORDER BY tag.id), '[]'::jsonb)
            FROM iam.membership_tags AS assignment
            JOIN iam.organization_tags AS tag
              ON tag.organization_id = assignment.organization_id
             AND tag.id = assignment.tag_id AND tag.status = 'active'
            WHERE assignment.organization_id = membership.organization_id
              AND assignment.membership_id = membership.id
        ) ELSE NULL END
    ), subject.auth_epoch, issuer_principal.auth_epoch, membership.authz_epoch
    INTO authorization_snapshot, subject_epoch, issuer_epoch, membership_epoch
    FROM iam.access_tokens AS token
    JOIN iam.principals AS subject
      ON subject.id = token.subject_principal_id AND subject.kind = token.subject_kind
     AND subject.status = 'active' AND subject.auth_epoch = token.subject_auth_epoch
    JOIN iam.authentication_sessions AS session
      ON session.id = token.authentication_session_id
     AND session.subject_principal_id = subject.id AND session.subject_kind = subject.kind
     AND session.subject_auth_epoch = subject.auth_epoch AND session.status = 'active'
     AND session.idle_expires_at > clock_timestamp()
     AND session.absolute_expires_at > clock_timestamp()
    JOIN iam.organization_memberships AS membership
      ON membership.id = p_membership_id AND membership.organization_id = p_organization_id
     AND membership.principal_id = subject.id AND membership.principal_kind = subject.kind
     AND membership.status = 'active'
     AND (
         token.organization_id IS NULL
         OR (membership.id = token.membership_id
             AND membership.organization_id = token.organization_id
             AND membership.authz_epoch = token.membership_authz_epoch)
     )
    JOIN iam.organizations AS organization
      ON organization.id = membership.organization_id AND organization.status = 'active'
    JOIN iam.applications AS issuer
      ON issuer.id = token.client_application_id AND issuer.id = token.audience_application_id
     AND issuer.id = v_issuer_application_id AND issuer.app_id = token.audience
     AND issuer.review_status = 'verified' AND issuer.deleted_at IS NULL
    JOIN iam.principals AS issuer_principal
      ON issuer_principal.id = issuer.id AND issuer_principal.kind = 'application'
     AND issuer_principal.status = 'active' AND issuer_principal.auth_epoch = token.client_auth_epoch
    JOIN iam.applications AS audience
      ON audience.id = p_audience_application_id
     AND audience.review_status = 'verified' AND audience.deleted_at IS NULL
    JOIN iam.principals AS audience_principal
      ON audience_principal.id = audience.id AND audience_principal.kind = 'application'
     AND audience_principal.status = 'active' AND audience_principal.auth_epoch = p_audience_auth_epoch
    LEFT JOIN iam.carbons AS carbon
      ON carbon.id = subject.id AND subject.kind = 'carbon' AND carbon.deleted_at IS NULL
    LEFT JOIN iam.silicons AS silicon
      ON silicon.id = subject.id AND subject.kind = 'silicon'
     AND silicon.organization_id = organization.id AND silicon.membership_id = membership.id
     AND silicon.provisioning_status = 'active' AND silicon.deleted_at IS NULL
    CROSS JOIN LATERAL (
        SELECT ARRAY(
            SELECT token_scope.scope FROM iam.access_token_scopes AS token_scope
            JOIN approved ON approved.scope = token_scope.scope
            WHERE token_scope.access_token_id = token.id
              AND (p_proof_id IS NULL OR (
                  token_scope.scope IN ('self.identity.read', 'self.membership.read', 'self.tags.read')
                  AND EXISTS (
                      SELECT 1 FROM issuer_disclosures
                      WHERE issuer_disclosures.scope = token_scope.scope
                  )
              ))
            ORDER BY token_scope.scope
        ) AS scopes
    ) AS effective
    WHERE token.id = p_access_token_id AND subject.id = p_subject_principal_id
      AND organization.id = p_organization_id AND membership.id = p_membership_id
      AND token.token_class = 'application_access' AND token.revoked_at IS NULL
      AND token.expires_at > clock_timestamp()
      AND (carbon.id IS NOT NULL OR silicon.id IS NOT NULL)
      AND (
          (p_proof_id IS NULL AND issuer.id = audience.id)
          OR (p_proof_id IS NOT NULL)
      )
    FOR SHARE OF token, subject, session, membership, organization,
                 issuer, issuer_principal, audience, audience_principal;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    IF p_proof_id IS NOT NULL THEN
        -- Session revocation locks the parent session/tokens before consent.
        -- Follow that order after the locking read above. Approval replaces scope
        -- rows under this exact consent lock; filter the already bounded candidate
        -- disclosures only after obtaining it and keep it through consumption.
        SELECT consent.id INTO v_parent_consent_id
        FROM iam.access_tokens AS token
        JOIN iam.oauth_consent_grants AS consent
          ON consent.application_id = token.client_application_id
         AND consent.subject_principal_id = token.subject_principal_id
         AND consent.subject_kind = token.subject_kind
         AND consent.parent_authentication_session_id = token.authentication_session_id
         AND consent.organization_id IS NOT DISTINCT FROM token.organization_id
         AND consent.membership_id IS NOT DISTINCT FROM token.membership_id
         AND p_membership_id = ANY(consent.selected_membership_ids)
         AND consent.status = 'active'
        WHERE token.id = p_access_token_id
        FOR SHARE OF consent;
        IF NOT FOUND THEN
            RETURN NULL;
        END IF;
        SELECT jsonb_set(authorization_snapshot, '{scopes}', COALESCE(jsonb_agg(candidate.scope ORDER BY candidate.scope), '[]'::jsonb))
        INTO authorization_snapshot
        FROM jsonb_array_elements_text(authorization_snapshot->'scopes') AS candidate(scope)
        JOIN iam.oauth_consent_grant_scopes AS granted ON granted.scope = candidate.scope
        WHERE granted.consent_grant_id = v_parent_consent_id;
        IF NOT (authorization_snapshot->'scopes' ? 'self.membership.read') THEN
            authorization_snapshot := jsonb_set(authorization_snapshot, '{org_role}', 'null'::jsonb);
        END IF;
        IF NOT (authorization_snapshot->'scopes' ? 'self.tags.read') THEN
            authorization_snapshot := jsonb_set(authorization_snapshot, '{tags}', 'null'::jsonb);
        END IF;
    END IF;

    IF p_proof_id IS NOT NULL THEN
        -- Another application's parent token alone is never sufficient.
        -- Require this audience's exact persisted proof, lock it after its
        -- parent, and lock the endpoint until the caller consumes the proof.
        SELECT proof.consumed_at INTO proof_consumed_at
        FROM iam.obo_proofs AS proof
        JOIN iam.application_obo_endpoints AS endpoint
          ON endpoint.application_id = proof.audience_application_id
         AND endpoint.endpoint_id = proof.endpoint_id
         AND endpoint.path = proof.request_path
         AND endpoint.version = proof.endpoint_version
         AND endpoint.status = 'active'
        WHERE proof.id = p_proof_id
          AND proof.parent_access_token_id = p_access_token_id
          AND proof.subject_principal_id = p_subject_principal_id
          AND proof.subject_kind::text = authorization_snapshot->>'actor_type'
          AND proof.organization_id = p_organization_id
          AND proof.membership_id = p_membership_id
          AND proof.root_issuer_application_id = v_issuer_application_id
          AND proof.audience_application_id = p_audience_application_id
          AND proof.subject_auth_epoch = subject_epoch
          AND CASE WHEN proof.chain_depth = 0 THEN proof.issuer_auth_epoch
                   ELSE (proof.chain->0->>'issuer_auth_epoch')::bigint END = issuer_epoch
          AND proof.membership_authz_epoch = membership_epoch
          AND proof.audience_auth_epoch = p_audience_auth_epoch
          AND CASE WHEN proof.chain_depth = 0
                   THEN iam_private.application_token_allows_external_scope(p_access_token_id, p_audience_application_id, proof.endpoint_id)
                   ELSE iam_private.application_obo_chain_is_intact(proof.id) END
          AND proof.revoked_at IS NULL
          AND proof.expires_at > clock_timestamp()
        FOR UPDATE OF proof FOR SHARE OF endpoint;
        IF NOT FOUND THEN
            RETURN NULL;
        END IF;
        IF proof_consumed_at IS NOT NULL THEN
            RAISE EXCEPTION 'obo_proof_consumed' USING ERRCODE = 'P0001';
        END IF;
    END IF;

    IF p_proof_id IS NOT NULL THEN
        SELECT authorization_snapshot || jsonb_build_object('scopes', jsonb_build_array(
            'obo:' || audience.app_id || ':' || proof.endpoint_id) || (authorization_snapshot->'scopes'))
        INTO authorization_snapshot FROM iam.obo_proofs proof
        JOIN iam.applications audience ON audience.id = proof.audience_application_id
        WHERE proof.id = p_proof_id;
    END IF;
    IF NOT (authorization_snapshot->'scopes' ? 'self.identity.read') THEN
        authorization_snapshot := authorization_snapshot - ARRAY['actor_type','public_id'];
    END IF;
    RETURN authorization_snapshot;
END;
$$;
REVOKE ALL ON FUNCTION iam_private.get_current_application_authorization(uuid, text, uuid, uuid, text, bigint, uuid) FROM PUBLIC;

-- 7. Consent: an OBO scope lists every call its declared closure could make,
-- so consenting to the root delegation is informed consent to the chain.
CREATE OR REPLACE FUNCTION iam_private.application_login_scope_policy(p_app text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
DECLARE snapshot jsonb;
BEGIN
 PERFORM id FROM iam.applications WHERE id=p_app FOR SHARE;
 SELECT jsonb_build_object('scope_version',app.version,
 'consent_required',NOT (org.trusted_org AND org.skip_application_consent),
 'scopes',COALESCE((SELECT jsonb_agg(jsonb_build_object('scope',approved.scope,'description',catalog.description,'critical',catalog.critical,
 'app_id',CASE WHEN approved.scope LIKE 'obo:%' THEN split_part(approved.scope,':',2) END,
 'downstream',CASE WHEN approved.scope LIKE 'obo:%' THEN (
   SELECT jsonb_agg(jsonb_build_object('via_app_id',edge.from_app,'app_id',target.app_id,
     'app_name',target.app_name,'endpoint_id',edge.endpoint,'description',target_catalog.description)
     ORDER BY target.app_id,edge.endpoint,edge.from_app)
   FROM iam_private.application_obo_downstream_edges(app.id,catalog.app_id,
     substr(approved.scope,length('obo:'||catalog.app_id||':')+1)) edge
   JOIN iam.applications target ON target.id=edge.app AND target.review_status='verified' AND target.deleted_at IS NULL
   JOIN iam_private.application_scope_catalog(NULL) target_catalog ON target_catalog.scope='obo:'||target.app_id||':'||edge.endpoint
 ) END) ORDER BY approved.scope)
 FROM iam.application_approved_scopes approved JOIN iam_private.application_scope_catalog(NULL) catalog ON catalog.scope=approved.scope
 WHERE approved.application_id=app.id AND approved.revoked_at IS NULL),'[]'::jsonb))
 INTO snapshot FROM iam.applications app JOIN iam.organizations org ON org.id=app.organization_id
 WHERE app.id=p_app AND app.review_status='verified' AND app.deleted_at IS NULL;
 RETURN snapshot;
END $$;
REVOKE ALL ON FUNCTION iam_private.application_login_scope_policy(text) FROM PUBLIC;

-- 8. Endpoint serialization. Downstream keys are emitted only when declared,
-- so existing configurations serialize, digest and compare exactly as before.
CREATE OR REPLACE FUNCTION iam_private.discover_application_obo_endpoints(p_app_id text)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
    SELECT jsonb_build_object(
        'application', jsonb_build_object('app_id', app.app_id, 'org_id', org.org_id),
        'endpoints', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'endpoint_id', endpoint.endpoint_id, 'path', endpoint.path,
            'metadata', endpoint.metadata_definition, 'critical', endpoint.critical, 'ttl_seconds', endpoint.ttl_seconds
        ) || CASE WHEN endpoint.downstream = '[]'::jsonb THEN '{}'::jsonb
                  ELSE jsonb_build_object('downstream', endpoint.downstream) END
          || CASE WHEN endpoint.downstream_ttl_seconds IS NULL THEN '{}'::jsonb
                  ELSE jsonb_build_object('downstream_ttl_seconds', endpoint.downstream_ttl_seconds) END
        ORDER BY endpoint.endpoint_id)
        FROM iam.application_obo_endpoints endpoint
        WHERE endpoint.application_id = app.id AND endpoint.status = 'active'), '[]'::jsonb)
    )
    FROM iam.applications app
    JOIN iam.principals principal ON principal.id = app.id AND principal.status = 'active'
    JOIN iam.organizations org ON org.id = app.organization_id AND org.status = 'active'
    WHERE app.app_id = p_app_id AND app.review_status = 'verified' AND app.deleted_at IS NULL
      AND iam_private.application_is_discoverable(app.id,NULL)
      AND iam_private.current_application_id() = iam_private.current_principal_id()
      AND EXISTS (SELECT 1 FROM iam.applications caller
        JOIN iam.principals identity ON identity.id = caller.id AND identity.status = 'active'
        WHERE caller.id = iam_private.current_application_id()
          AND caller.review_status = 'verified' AND caller.deleted_at IS NULL);
$$;
REVOKE ALL ON FUNCTION iam_private.discover_application_obo_endpoints(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.honeycomb_application_record(p_service text, p_app_id text)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam, iam_private
AS $$
 SELECT jsonb_build_object('app_id',app.app_id,'application_id',app.id,'org_id',org.org_id,
 'app_name',app.app_name,'app_logo',app.app_logo_uri,'base_url',NULLIF(app.base_url,''),
 'visibility',app.visibility,'availability',app.review_status,'iam_revision',app.version,
 'configuration_revision',app.honeycomb_configuration_revision,
 'publication_request_id',CASE WHEN iam_private.honeycomb_publication_is_current(app.id) THEN app.honeycomb_publication_request_id END,
 'pending_webhook_endpoint_id',(SELECT id FROM iam.application_webhook_endpoints WHERE application_id=app.id AND status='pending_review'),
 'app_scope',app.app_scope,'webhook_scope',app.webhook_scope,'obo_review_message',app.obo_review_message,
 'effective_scopes',COALESCE((SELECT jsonb_agg(jsonb_build_object('scope',approved.scope,'basis',approved.approval_basis) ORDER BY approved.scope)
   FROM iam.application_approved_scopes approved WHERE approved.application_id=app.id AND approved.revoked_at IS NULL),'[]'::jsonb),
 'obo_endpoints',COALESCE((SELECT jsonb_agg(jsonb_build_object('endpoint_id',endpoint_id,'path',path,
   'metadata',metadata_definition,'critical',critical,'ttl_seconds',ttl_seconds)
   || CASE WHEN downstream='[]'::jsonb THEN '{}'::jsonb ELSE jsonb_build_object('downstream',downstream) END
   || CASE WHEN downstream_ttl_seconds IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('downstream_ttl_seconds',downstream_ttl_seconds) END
   ORDER BY endpoint_id)
   FROM iam.application_obo_endpoints WHERE application_id=app.id AND status='active'),'[]'::jsonb),
 'credential_version',(SELECT max(secret_version) FROM iam.application_secrets WHERE application_id=app.id AND status='active'),
 'testing_idle_days',app.testing_idle_days)
 FROM iam.applications app JOIN iam.organizations org ON org.id=app.organization_id
 WHERE app.app_id=p_app_id AND EXISTS(SELECT 1 FROM iam.applications service WHERE service.id=p_service);
$$;
REVOKE ALL ON FUNCTION iam_private.honeycomb_application_record(text, text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam_private.get_testing_application_import_v2(p_app_ids text[])
RETURNS TABLE(source_application_id text, source_webhook_endpoint_id uuid, source_webhook_signing_key_id uuid,
    app_id text, org_id text, organization_name text, organization_logo_uri text, organization_description text,
    app_name text, app_logo_uri text, base_url text, webhook_url_ciphertext bytea, webhook_url_nonce bytea,
    webhook_url_encryption_key_version smallint, webhook_secret_ciphertext bytea, webhook_secret_nonce bytea,
    webhook_secret_encryption_key_version smallint, webhook_secret_version bigint, obo_endpoints jsonb,
    app_scope jsonb, webhook_scope text[], testing_idle_days integer, visibility text, source_revision bigint)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $$
    SELECT
        application.id,
        endpoint.id,
        signing_key.id,
        application.app_id,
        organization.org_id,
        organization.name,
        organization.logo_uri,
        organization.description,
        application.app_name,
        application.app_logo_uri,
        application.base_url,
        endpoint.url_ciphertext,
        endpoint.url_nonce,
        endpoint.encryption_key_version,
        signing_key.secret_ciphertext,
        signing_key.secret_nonce,
        signing_key.encryption_key_version,
        signing_key.secret_version,
        (
            SELECT COALESCE(
                jsonb_agg(
                    jsonb_build_object(
                        'endpoint_id', obo.endpoint_id,
                        'path', obo.path,
                        'metadata', obo.metadata_definition, 'critical', obo.critical, 'ttl_seconds', obo.ttl_seconds
                    ) || CASE WHEN obo.downstream = '[]'::jsonb THEN '{}'::jsonb
                              ELSE jsonb_build_object('downstream', obo.downstream) END
                      || CASE WHEN obo.downstream_ttl_seconds IS NULL THEN '{}'::jsonb
                              ELSE jsonb_build_object('downstream_ttl_seconds', obo.downstream_ttl_seconds) END
                    ORDER BY obo.endpoint_id
                ),
                '[]'::jsonb
            )
            FROM iam.application_obo_endpoints AS obo
            WHERE obo.application_id = application.id
              AND obo.organization_id = application.organization_id
              AND obo.status = 'active'
        ), application.app_scope, application.webhook_scope, application.testing_idle_days, application.visibility, application.version
    FROM iam.applications AS application
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
     AND application_principal.status = 'active'
    JOIN iam.organizations AS organization
      ON organization.id = application.organization_id
     AND organization.status = 'active'
    JOIN LATERAL (
        SELECT candidate.*
        FROM iam.application_webhook_endpoints AS candidate
        WHERE candidate.application_id = application.id
          AND candidate.status IN ('active', 'pending_review')
        ORDER BY
            (candidate.status = 'active') DESC,
            candidate.activated_at DESC NULLS LAST,
            candidate.created_at DESC,
            candidate.id DESC
        LIMIT 1
    ) AS endpoint ON true
    JOIN LATERAL (
        SELECT candidate.*
        FROM iam.application_webhook_signing_keys AS candidate
        WHERE candidate.application_id = application.id
          AND candidate.endpoint_id = endpoint.id
          AND candidate.status = 'active'
        ORDER BY candidate.secret_version DESC, candidate.id DESC
        LIMIT 1
    ) AS signing_key ON true
    WHERE application.app_id = ANY(p_app_ids)
      AND application.review_status = 'verified'
      AND application.deleted_at IS NULL
$$;
REVOKE ALL ON FUNCTION iam_private.get_testing_application_import_v2(text[]) FROM PUBLIC;

-- The two testing importers differ by plane (0111 rewrote their conflict
-- targets), so patch their installed text in place rather than restate it.
DO $$
DECLARE
    function_name text;
    definition text;
    patched text;
BEGIN
    FOREACH function_name IN ARRAY ARRAY[
        'import_testing_application_configuration',
        'honeycomb_configure_testing_application'
    ] LOOP
        SELECT pg_catalog.pg_get_functiondef(procedure.oid) INTO STRICT definition
        FROM pg_catalog.pg_proc AS procedure
        WHERE procedure.pronamespace = 'iam_private'::regnamespace
          AND procedure.proname = function_name;
        patched := replace(definition,
            'INSERT INTO iam.application_obo_endpoints(organization_id,application_id,endpoint_id,path,metadata_definition,critical,ttl_seconds)',
            'INSERT INTO iam.application_obo_endpoints(organization_id,application_id,endpoint_id,path,metadata_definition,critical,ttl_seconds,downstream,downstream_ttl_seconds)');
        patched := replace(patched,
            'COALESCE((item->>''ttl_seconds'')::integer,300))',
            'COALESCE((item->>''ttl_seconds'')::integer,300),COALESCE(item->''downstream'',''[]''::jsonb),(item->>''downstream_ttl_seconds'')::integer)');
        patched := replace(patched,
            'ttl_seconds=EXCLUDED.ttl_seconds,status=''active''',
            'ttl_seconds=EXCLUDED.ttl_seconds,downstream=EXCLUDED.downstream,downstream_ttl_seconds=EXCLUDED.downstream_ttl_seconds,status=''active''');
        IF patched = definition
           OR patched NOT LIKE '%critical,ttl_seconds,downstream,downstream_ttl_seconds)%'
           OR patched NOT LIKE '%COALESCE(item->''downstream'',''[]''::jsonb)%'
           OR patched NOT LIKE '%downstream=EXCLUDED.downstream,%' THEN
            RAISE EXCEPTION 'cannot carry OBO downstream through %', function_name;
        END IF;
        EXECUTE patched;
    END LOOP;
END;
$$;
