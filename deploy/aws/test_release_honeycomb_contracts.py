"""Read-only release configuration regressions; no AWS or service operations."""
import importlib.util
import base64
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("release_contracts", Path(__file__).with_name("release-honeycomb-contracts.py"))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)


class PreservedFlags(unittest.TestCase):
    def test_existing_scheduled_testing_remains_enabled(self):
        environment = ["IAM_HONEYCOMB_SCHEDULED_TESTING=true", "IAM_HONEYCOMB_RETIRE_LEGACY_WRITERS=false", "UNRELATED_SECRET=not-reported"]
        self.assertEqual(RELEASE.cutover_flags(environment), {
            "IAM_HONEYCOMB_SCHEDULED_TESTING": "true", "IAM_HONEYCOMB_RETIRE_LEGACY_WRITERS": "false"})
        self.assertEqual(environment[0], "IAM_HONEYCOMB_SCHEDULED_TESTING=true")

    def test_disabled_and_absent_flags_keep_runtime_defaults(self):
        self.assertEqual(RELEASE.cutover_flags([]), {name: "false" for name in RELEASE.FLAGS})
        self.assertEqual(RELEASE.cutover_flags([name + "=false" for name in RELEASE.FLAGS]), RELEASE.cutover_flags([]))

    def test_unknown_policy_value_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "requires operator review"):
            RELEASE.cutover_flags(["IAM_HONEYCOMB_SCHEDULED_TESTING=unexpected"])


class RecoveryReceipt(unittest.TestCase):
    def test_exact_versioned_encrypted_checksum_and_size_are_required(self):
        checksum = "a" * 64
        response = {"VersionId": "immutable-version", "ContentLength": 456,
                    "ChecksumSHA256": base64.b64encode(bytes.fromhex(checksum)).decode(),
                    "ServerSideEncryption": "AES256"}
        self.assertEqual(RELEASE.backup_receipt(response, checksum, 456), "immutable-version")
        for field, value in (("VersionId", "null"), ("VersionId", ""), ("ContentLength", 455),
                             ("ChecksumSHA256", "wrong"), ("ServerSideEncryption", None)):
            with self.assertRaisesRegex(RuntimeError, "receipt mismatch"):
                RELEASE.backup_receipt(dict(response, **{field: value}), checksum, 456)

    def test_missing_testing_dump_cannot_upload_recovery_bundle(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            release = object.__new__(RELEASE.Release)
            release.root = Path(directory)
            release.upload_verified = lambda *_: self.fail("Cannot upload an incomplete pair")
            with self.assertRaisesRegex(RuntimeError, "Missing paired recovery component"):
                release.upload_quiesced_backup()


if __name__ == "__main__":
    unittest.main()
