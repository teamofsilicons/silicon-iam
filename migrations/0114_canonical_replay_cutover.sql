-- Optional operator-created cutover state survives migration 0111. It is not an
-- identity relation: no authentication path accepts the retained UUIDs.
CREATE TABLE IF NOT EXISTS iam_private.canonical_replay_cutover (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 prepared_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 converted_at timestamptz
);
CREATE TABLE IF NOT EXISTS iam_private.canonical_replay_metadata (
 legacy_id uuid PRIMARY KEY,
 public_id text NOT NULL,
 testing_environment_id uuid,
 actor_type text NOT NULL CHECK(actor_type IN('carbon','silicon','application','service'))
);
REVOKE ALL ON iam_private.canonical_replay_cutover,iam_private.canonical_replay_metadata FROM PUBLIC;
CREATE FUNCTION iam_private.canonical_replay_contexts()
RETURNS TABLE(public_id text,testing_environment_id uuid,legacy_id uuid,expires_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,iam_private AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM iam_private.canonical_replay_cutover WHERE converted_at IS NULL) THEN
  RAISE EXCEPTION 'canonical replay payload conversion is required before API startup' USING ERRCODE='55000';
 END IF;
 RETURN QUERY SELECT metadata.public_id,metadata.testing_environment_id,metadata.legacy_id,cutover.expires_at
 FROM iam_private.canonical_replay_metadata metadata CROSS JOIN iam_private.canonical_replay_cutover cutover
 WHERE cutover.expires_at>clock_timestamp();
END $$;
REVOKE ALL ON FUNCTION iam_private.canonical_replay_contexts() FROM PUBLIC;
DO $$ DECLARE definition text; BEGIN
 -- Reuse the bounded worker maintenance authority. No API can remove metadata
 -- early or extend the deadline captured from the old replay records.
 SELECT pg_get_functiondef('iam_private.run_worker_ephemeral_maintenance(integer)'::regprocedure) INTO definition;
 definition:=replace(definition,'BEGIN',E'BEGIN\n    DELETE FROM iam_private.canonical_replay_metadata WHERE EXISTS (SELECT 1 FROM iam_private.canonical_replay_cutover WHERE converted_at IS NOT NULL AND expires_at <= clock_timestamp());');
 EXECUTE definition;
 IF to_regrole('silicon_iam_testing_definer') IS NOT NULL THEN
  GRANT SELECT ON iam_private.canonical_replay_cutover,iam_private.canonical_replay_metadata TO silicon_iam_testing_definer;
  GRANT DELETE ON iam_private.canonical_replay_metadata TO silicon_iam_testing_definer;
 END IF;
END $$;
