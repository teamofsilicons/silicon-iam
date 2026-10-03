"""Local synthetic-key tests; never access provider or runtime credentials."""

import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

SCRIPT = Path(__file__).with_name("apple-client-secret.py")
SPEC = importlib.util.spec_from_file_location("apple_client_secret", SCRIPT)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
NOW = 1791043200


def decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


class AppleClientSecretTests(unittest.TestCase):
    def setUp(self):
        # Resolve the platform temp root once; the helper itself must reject symlinks.
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.key_path = self.root / "AuthKey_SYNTHETIC.p8"
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.write_key(self.key)
        self.original_key = self.key_path.read_bytes()
        self.output = self.root / "candidate.json"
        self.arguments = dict(key_path=self.key_path, team_id="TESTTEAM01", key_id="TESTKEY001", services_id="com.example.synthetic", output=self.output, now=NOW)

    def tearDown(self):
        self.temporary.cleanup()

    def write_key(self, key, encryption=serialization.NoEncryption()):
        self.key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption))
        self.key_path.chmod(0o600)

    def generate(self, **overrides):
        return HELPER.generate_candidate(**(self.arguments | overrides))

    def assert_no_outputs(self):
        self.assertFalse(self.output.exists())
        self.assertFalse(self.output.with_name(self.output.name + ".receipt.json").exists())
        self.assertFalse(list(self.root.glob(".apple-client-secret-*.tmp")))

    def test_exact_claims_signature_permissions_and_unmodified_key(self):
        result = self.generate()
        candidate = json.loads(self.output.read_text())
        self.assertEqual(set(candidate), {"IAM_APPLE_CLIENT_ID", "IAM_APPLE_CLIENT_SECRET"})
        self.assertEqual(candidate["IAM_APPLE_CLIENT_ID"], "com.example.synthetic")
        token = candidate["IAM_APPLE_CLIENT_SECRET"]
        header_segment, payload_segment, signature_segment = token.split(".")
        self.assertEqual(json.loads(decode(header_segment)), {"alg": "ES256", "kid": "TESTKEY001"})
        claims = {"iss": "TESTTEAM01", "sub": "com.example.synthetic", "aud": "https://appleid.apple.com", "iat": NOW, "exp": NOW + 90 * 86400}
        self.assertEqual(json.loads(decode(payload_segment)), claims)
        raw = decode(signature_segment)
        self.assertEqual(len(raw), 64)
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        signed = f"{header_segment}.{payload_segment}".encode("ascii")
        self.key.public_key().verify(der, signed, ec.ECDSA(hashes.SHA256()))
        with self.assertRaises(InvalidSignature):
            self.key.public_key().verify(der, signed + b"x", ec.ECDSA(hashes.SHA256()))
        receipt_path = Path(result["receipt_path"])
        receipt = json.loads(receipt_path.read_text())
        self.assertEqual(receipt["claims"], claims)
        self.assertEqual(receipt["rotation_due_at"], HELPER._utc(NOW + 76 * 86400))
        self.assertTrue(receipt["signature_verified"])
        self.assertFalse(receipt["runtime_configuration_changed"])
        self.assertNotIn(token, receipt_path.read_text())
        self.assertNotIn("PRIVATE KEY", receipt_path.read_text())
        for path in (self.output, receipt_path):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(self.key_path.read_bytes(), self.original_key)
        self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), 0o600)

    def test_rotation_is_fresh_candidate_and_preserves_previous(self):
        self.generate()
        original = self.output.read_bytes()
        newer = self.root / "rotated.json"
        result = self.generate(operation="rotate", output=newer, now=NOW + 3600)
        self.assertEqual(self.output.read_bytes(), original)
        self.assertEqual(json.loads(Path(result["receipt_path"]).read_text())["operation"], "rotate")
        self.assertEqual(json.loads(Path(result["receipt_path"]).read_text())["claims"]["iat"], NOW + 3600)

    def test_maximum_lifetime_and_short_rotation_window(self):
        for days in (1, 180):
            with self.subTest(days=days):
                result = self.generate(lifetime_days=days, output=self.root / f"{days}.json")
                receipt = json.loads(Path(result["receipt_path"]).read_text())
                self.assertEqual(receipt["claims"]["exp"], NOW + days * 86400)
                self.assertLessEqual(receipt["claims"]["exp"] - NOW, 15777000)
                self.assertGreater(receipt["rotation_due_at"], receipt["generated_at"])
                self.assertLess(receipt["rotation_due_at"], receipt["expires_at"])

    def test_invalid_lifetimes_identifiers_and_operation_fail_before_output(self):
        for values in ({"lifetime_days": 0}, {"lifetime_days": 181}, {"lifetime_days": True}, {"lifetime_days": 1.5}, {"team_id": "bad"}, {"key_id": "lowercase1"}, {"services_id": ""}, {"services_id": "com.example\nsecret"}, {"services_id": "../secret"}, {"operation": "activate"}, {"now": 0}):
            with self.subTest(values=values), self.assertRaises(HELPER.CandidateError):
                self.generate(**values)
            self.assert_no_outputs()

    def test_rejects_wrong_curve_and_rsa(self):
        for key in (ec.generate_private_key(ec.SECP384R1()), rsa.generate_private_key(public_exponent=65537, key_size=2048)):
            self.write_key(key)
            with self.assertRaisesRegex(HELPER.CandidateError, "P-256"):
                self.generate()
            self.assert_no_outputs()

    def test_rejects_encrypted_and_malformed_key(self):
        self.write_key(self.key, serialization.BestAvailableEncryption(b"synthetic-only"))
        with self.assertRaisesRegex(HELPER.CandidateError, "unencrypted"):
            self.generate()
        self.key_path.write_bytes(b"not a key")
        with self.assertRaisesRegex(HELPER.CandidateError, "PKCS#8"):
            self.generate()
        self.assert_no_outputs()

    def test_rejects_insecure_key(self):
        self.key_path.chmod(0o640)
        with self.assertRaisesRegex(HELPER.CandidateError, "private permissions"):
            self.generate()
        self.assert_no_outputs()

    def test_rejects_key_hardlink(self):
        os.link(self.key_path, self.root / "duplicate.p8")
        with self.assertRaisesRegex(HELPER.CandidateError, "hard links"):
            self.generate()
        self.assert_no_outputs()

    def test_rejects_key_symlink_without_reading_target(self):
        alias = self.root / "link.p8"
        alias.symlink_to(self.key_path)
        with self.assertRaises(OSError):
            self.generate(key_path=alias)
        self.assert_no_outputs()

    def test_rejects_nonregular_key_without_blocking(self):
        self.key_path.unlink()
        os.mkfifo(self.key_path, 0o600)
        with self.assertRaisesRegex(HELPER.CandidateError, "regular file"):
            self.generate()
        self.assert_no_outputs()

    def test_rejects_insecure_output_and_key_directory(self):
        for category in ("output", "key"):
            directory = self.root / category
            directory.mkdir(mode=0o750)
            arguments = {"output": directory / "candidate.json"}
            if category == "key":
                new_key = directory / "key.p8"
                new_key.write_bytes(self.original_key)
                new_key.chmod(0o600)
                arguments = {"key_path": new_key}
            with self.subTest(category=category), self.assertRaisesRegex(HELPER.CandidateError, "directories"):
                self.generate(**arguments)
        self.assert_no_outputs()

    def test_rejects_symlink_parent_for_key_and_output(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for arguments in ({"output": alias / "candidate.json"}, {"key_path": alias / self.key_path.name}):
            with self.subTest(arguments=arguments), self.assertRaises(OSError):
                self.generate(**arguments)
        self.assert_no_outputs()

    def test_refuses_existing_candidate_and_preserves_contents(self):
        self.output.write_text("keep")
        with self.assertRaisesRegex(HELPER.CandidateError, "already exist"):
            self.generate()
        self.assertEqual(self.output.read_text(), "keep")
        self.assertFalse(self.output.with_name(self.output.name + ".receipt.json").exists())

    def test_refuses_existing_receipt_before_candidate_publication(self):
        receipt = self.output.with_name(self.output.name + ".receipt.json")
        receipt.write_text("keep")
        with self.assertRaisesRegex(HELPER.CandidateError, "already exist"):
            self.generate()
        self.assertFalse(self.output.exists())
        self.assertEqual(receipt.read_text(), "keep")

    def test_refuses_dangling_output_symlinks(self):
        for name in ("candidate.json", "candidate.json.receipt.json"):
            alias = self.root / name
            alias.symlink_to(self.root / "missing")
            with self.subTest(name=name), self.assertRaisesRegex(HELPER.CandidateError, "already exist"):
                self.generate()
            self.assertTrue(alias.is_symlink())
            alias.unlink()
        self.assert_no_outputs()

    def test_no_clobber_if_destination_appears_during_publication(self):
        original_link = os.link

        def race(source, destination, **kwargs):
            if destination == self.output.name:
                self.output.write_text("another writer")
            return original_link(source, destination, **kwargs)

        with patch.object(HELPER.os, "link", side_effect=race), self.assertRaises(FileExistsError):
            self.generate()
        self.assertEqual(self.output.read_text(), "another writer")
        self.assertFalse(list(self.root.glob(".apple-client-secret-*.tmp")))

    def test_second_publication_failure_cleans_only_our_candidate(self):
        original_link = os.link

        def fail_second(source, destination, **kwargs):
            if destination.endswith(".receipt.json"):
                raise OSError("synthetic failure")
            return original_link(source, destination, **kwargs)

        with patch.object(HELPER.os, "link", side_effect=fail_second), self.assertRaises(OSError):
            self.generate()
        self.assert_no_outputs()

    def test_cli_prints_only_nonsecret_summary(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = HELPER.main(["generate", "--key", str(self.key_path), "--team-id", "TESTTEAM01", "--key-id", "TESTKEY001", "--services-id", "com.example.synthetic", "--output", str(self.output)])
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        summary = json.loads(stdout.getvalue())
        self.assertEqual(set(summary), {"candidate_path", "receipt_path", "expires_at", "rotation_due_at"})
        token = json.loads(self.output.read_text())["IAM_APPLE_CLIENT_SECRET"]
        self.assertNotIn(token, stdout.getvalue())
        self.assertNotIn("PRIVATE KEY", stdout.getvalue())
        self.assertNotIn(str(self.key_path), stdout.getvalue())

    def test_cli_failure_does_not_print_key_or_traceback(self):
        self.key_path.write_bytes(b"SYNTHETIC_PRIVATE_INPUT_MUST_NOT_APPEAR")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = HELPER.main(["rotate", "--key", str(self.key_path), "--team-id", "TESTTEAM01", "--key-id", "TESTKEY001", "--services-id", "com.example.synthetic", "--output", str(self.output)])
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("SYNTHETIC_PRIVATE_INPUT", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assert_no_outputs()


if __name__ == "__main__":
    unittest.main()
