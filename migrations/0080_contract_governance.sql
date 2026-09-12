-- Contracts are deployment reference data; customer testing environments use the same protocol.
-- Keep the catalogue outside the customer-data schema so historical testing
-- overlays cannot scope its seeded rows. Access is only through definer helpers.
CREATE TABLE iam_private.contract_versions (
 version text PRIMARY KEY CHECK(version ~ '^v[1-9][0-9]*$'),
 status text NOT NULL CHECK(status IN('current','deprecated','sunset')),
 released_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 deprecated_at timestamptz,last_requested_at timestamptz,sunset_at timestamptz,
 client_compatibility jsonb NOT NULL DEFAULT '{"rust_client":"v1","cli":"v1","frontend":"v1"}',
 CHECK((status='sunset')=(sunset_at IS NOT NULL)),CHECK(status<>'deprecated' OR deprecated_at IS NOT NULL)
);
INSERT INTO iam_private.contract_versions(version,status) VALUES('v1','current');
CREATE FUNCTION iam_private.record_contract_request(p_version text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE current_status text;
BEGIN
 UPDATE iam_private.contract_versions SET last_requested_at=clock_timestamp()
 WHERE version=p_version AND status IN('current','deprecated') AND (last_requested_at IS NULL OR last_requested_at<clock_timestamp()-interval '1 minute');
 SELECT status INTO current_status FROM iam_private.contract_versions WHERE version=p_version FOR SHARE;
 RETURN current_status;
END $$;
REVOKE ALL ON FUNCTION iam_private.record_contract_request(text) FROM PUBLIC;
CREATE FUNCTION iam_private.list_contract_versions()
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object(
 'version',version,'status',status,'released_at',released_at,'deprecated_at',deprecated_at,
 'last_requested_at',last_requested_at,'sunset_at',sunset_at,'compatibility',client_compatibility) ORDER BY released_at DESC),'[]'::jsonb),
 'policy',jsonb_build_object('initial_version','v1','breaking_changes','new_major_version','sunset_after_idle_days',7)) FROM iam_private.contract_versions
$$;
REVOKE ALL ON FUNCTION iam_private.list_contract_versions() FROM PUBLIC;
CREATE FUNCTION iam_private.sunset_idle_contract_versions()
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, iam_private AS $$
DECLARE affected bigint;
BEGIN
 -- One minute compensates for request timestamp coalescing, so no version is retired early.
 UPDATE iam_private.contract_versions SET status='sunset',sunset_at=clock_timestamp()
 WHERE status='deprecated' AND GREATEST(deprecated_at,COALESCE(last_requested_at,deprecated_at))<clock_timestamp()-interval '7 days 1 minute';
 GET DIAGNOSTICS affected=ROW_COUNT; RETURN affected;
END $$;
REVOKE ALL ON FUNCTION iam_private.sunset_idle_contract_versions() FROM PUBLIC;
