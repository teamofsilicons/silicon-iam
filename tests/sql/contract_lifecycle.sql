-- Run against a migrated disposable database; all fixtures roll back.
BEGIN;
UPDATE iam.contract_versions
SET last_requested_at = clock_timestamp() - interval '30 days'
WHERE version = 'v1';
INSERT INTO iam.contract_versions(version,status,deprecated_at,last_requested_at) VALUES
 ('v991','deprecated',clock_timestamp()-interval '30 days',clock_timestamp()-interval '1 hour'),
 ('v992','deprecated',clock_timestamp()-interval '8 days',NULL),
 ('v993','deprecated',clock_timestamp()-interval '30 days',clock_timestamp()-interval '7 days 30 seconds');
SET LOCAL ROLE silicon_iam_api;
DO $$ BEGIN
 IF iam_private.record_contract_request('v999') IS NOT NULL THEN
  RAISE EXCEPTION 'unknown contract request must not create a contract';
 END IF;
 IF iam_private.record_contract_request('v991') <> 'deprecated' THEN
  RAISE EXCEPTION 'deprecated active contract remains callable';
 END IF;
END $$;
RESET ROLE;
SET LOCAL ROLE silicon_iam_worker;
DO $$ BEGIN
 IF iam_private.sunset_idle_contract_versions() <> 1 THEN
  RAISE EXCEPTION 'only the deprecated idle contract should sunset';
 END IF;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF (SELECT status FROM iam.contract_versions WHERE version='v1') <> 'current' THEN
  RAISE EXCEPTION 'current contract must never sunset from inactivity';
 END IF;
 IF (SELECT status FROM iam.contract_versions WHERE version='v991') <> 'deprecated' THEN
  RAISE EXCEPTION 'active deprecated contract must remain available';
 END IF;
 IF (SELECT status FROM iam.contract_versions WHERE version='v992') <> 'sunset' THEN
  RAISE EXCEPTION 'deprecated contract idle longer than seven days must sunset';
 END IF;
 IF (SELECT status FROM iam.contract_versions WHERE version='v993') <> 'deprecated' THEN
  RAISE EXCEPTION 'coalesced request timestamp must not cause early retirement';
 END IF;
END $$;
ROLLBACK;
