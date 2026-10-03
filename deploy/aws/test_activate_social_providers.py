import argparse
import base64
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import time
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("activation", Path(__file__).with_name("activate-social-providers.py"))
activation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(activation)


def candidate(header=None, claims=None):
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    header = header if header is not None else {"alg": "ES256", "kid": "RB4CTQPLR5"}
    claims = claims if claims is not None else {"iss": "LTBSK59BJ2", "sub": "com.teamofsilicons.iam.web",
        "aud": "https://appleid.apple.com", "iat": int(time.time()), "exp": int(time.time()) + 90 * 86400}
    return {"IAM_GOOGLE_CLIENT_ID": "test.apps.googleusercontent.com", "IAM_GOOGLE_CLIENT_SECRET": "test-secret",
            "IAM_APPLE_CLIENT_ID": "com.teamofsilicons.iam.web",
            "IAM_APPLE_CLIENT_SECRET": encode(header) + "." + encode(claims) + "." + base64.urlsafe_b64encode(b"x" * 64).decode().rstrip("=")}


class ActivationTests(unittest.TestCase):
    def test_provider_discovery_respects_full_and_scoped_router_boundary(self):
        enabled = {"providers": [{"id": p, "enabled": True, "login_enabled": True} for p in ("google", "apple")]}
        scoped404 = activation.urllib.error.HTTPError("http://localhost", 404, "Not found", None, None)
        with patch.object(activation, "get", side_effect=[enabled, scoped404]):
            activation.verify_provider_discovery()
        with patch.object(activation, "get", side_effect=[enabled, enabled]):
            with self.assertRaises(RuntimeError): activation.verify_provider_discovery()
        with patch.object(activation, "get", return_value={"providers": []}):
            with self.assertRaises(RuntimeError): activation.verify_provider_discovery()

    def test_explicit_disable_removes_exact_apple_pair_and_preserves_google(self):
        previous = dict(candidate(), IAM_COOKIE_KEY="unchanged", nested={"keep": [1, 2]})
        disabled = {key: value for key, value in previous.items() if key not in activation.APPLE_FIELDS}
        values = activation.provider_values(previous, disabled, disable_apple=True)
        self.assertEqual(set(values), activation.GOOGLE_FIELDS)
        raw = b"# Keep this comment\r\nIAM_COOKIE_KEY=unchanged=padding\r\n" + "".join(f"{k}={v}\n" for k, v in candidate().items()).encode()
        updated = activation.updated_environment(raw, values)
        self.assertTrue(updated.startswith(b"# Keep this comment\r\nIAM_COOKIE_KEY=unchanged=padding\r\n"))
        self.assertFalse(any(key in activation.environment(updated) for key in activation.APPLE_FIELDS))
        for key in activation.GOOGLE_FIELDS:
            self.assertEqual(activation.environment(updated)[key], previous[key])
        with self.assertRaises(RuntimeError):
            activation.provider_values(previous, disabled)
        with self.assertRaises(RuntimeError):
            activation.provider_values(previous, previous, disable_apple=True)

    def test_disable_is_byte_exact_except_apple_lines_and_rejects_runtime_google_drift(self):
        values = {key: value for key, value in candidate().items() if key in activation.GOOGLE_FIELDS}
        preserved = b"# comment\r\nIAM_GOOGLE_CLIENT_ID=test.apps.googleusercontent.com\r\nIAM_GOOGLE_CLIENT_SECRET=test-secret\nLAST=no-newline"
        raw = b"IAM_APPLE_CLIENT_ID=old\n" + preserved + b"\nIAM_APPLE_CLIENT_SECRET=old-secret\r\n"
        self.assertEqual(activation.updated_environment(raw, values), preserved + b"\n")
        self.assertEqual(activation.updated_environment(preserved, values), preserved)
        for broken in (raw.replace(b"test-secret", b"drifted-secret"), raw.replace(b"IAM_GOOGLE_CLIENT_ID=", b"OLD_GOOGLE_CLIENT_ID=")):
            with self.assertRaisesRegex(RuntimeError, "runtime Google credentials differ"):
                activation.updated_environment(broken, values)

    def test_disable_rejects_partial_empty_google_rotation_and_unrelated_changes(self):
        previous = dict(candidate(), keep="unchanged")
        disabled = {key: value for key, value in previous.items() if key not in activation.APPLE_FIELDS}
        bad_cases = [dict(disabled, IAM_APPLE_CLIENT_ID=None), dict(disabled, IAM_APPLE_CLIENT_SECRET=""),
                     dict(disabled, IAM_GOOGLE_CLIENT_SECRET="rotated"), dict(disabled, keep="changed")]
        missing_google = dict(disabled); missing_google.pop("IAM_GOOGLE_CLIENT_ID")
        bad_cases.append(missing_google)
        for bad in bad_cases:
            with self.subTest(keys=list(bad)), self.assertRaises(RuntimeError):
                activation.provider_values(previous, bad, disable_apple=True)

    def test_disabled_discovery_requires_google_on_and_apple_fully_off(self):
        def rows(apple_enabled=False, apple_login=False):
            return {"providers": [{"id": "google", "enabled": True, "login_enabled": True},
                                  {"id": "apple", "enabled": apple_enabled, "login_enabled": apple_login}]}
        scoped404 = activation.urllib.error.HTTPError("http://localhost", 404, "Not found", None, None)
        self.addCleanup(scoped404.close)
        with patch.object(activation, "get", side_effect=[rows(), scoped404]):
            activation.verify_provider_discovery(disable_apple=True)
        for response in (rows(True, True), rows(True, False), rows(False, True),
                         {"providers": [{"id": "google", "enabled": True, "login_enabled": True}]}):
            with self.subTest(response=response), patch.object(activation, "get", return_value=response), self.assertRaises(RuntimeError):
                activation.verify_provider_discovery(disable_apple=True)

    def test_apply_rejects_mode_mismatch_before_secret_or_service_access(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            state = {"revision": "source", "previous_version": "old", "secret_arn": "arn", "disable_apple": False}
            (directory / "plan.json").write_text(json.dumps(state))
            args = argparse.Namespace(directory=directory, revision="source", previous_version="old", secret_arn="arn", disable_apple=True)
            with patch.object(activation, "secret") as secret, patch.object(activation, "stop") as stop, self.assertRaisesRegex(RuntimeError, "plan mismatch"):
                activation.apply(args)
            secret.assert_not_called()
            stop.assert_not_called()

    def test_runtime_uri_becomes_libpq_environment_without_losing_escaping(self):
        value = activation.postgres_environment("postgresql://runtime%40iam:p%3Ass%2Fword@db.example:5433/iam%2Dprod?sslmode=verify-full&sslrootcert=" + activation.CERT)
        self.assertEqual(value, {"PGHOST": "db.example", "PGPORT": "5433", "PGDATABASE": "iam-prod",
            "PGUSER": "runtime@iam", "PGPASSWORD": "p:ss/word", "PGSSLMODE": "verify-full", "PGSSLROOTCERT": activation.CERT})

    def test_runtime_uri_rejects_weaker_or_unexpected_tls_options(self):
        for query in ("sslmode=disable", "sslmode=verify-full&sslrootcert=/unreviewed.pem",
                      "sslmode=verify-full&sslmode=disable&sslrootcert=" + activation.CERT):
            with self.assertRaises(RuntimeError):
                activation.postgres_environment("postgresql://runtime:password@db.example/iam?" + query)

    def test_preserves_unrelated_environment_bytes(self):
        raw = b"# Shared keys remain byte-for-byte\nIAM_COOKIE_KEY=unchanged=padding\nIAM_GOOGLE_CLIENT_ID=old\nOTHER=last"
        updated = activation.updated_environment(raw, candidate())
        self.assertTrue(updated.startswith(b"# Shared keys remain byte-for-byte\nIAM_COOKIE_KEY=unchanged=padding\nOTHER=last\n"))
        self.assertEqual(activation.environment(updated)["IAM_COOKIE_KEY"], "unchanged=padding")
        self.assertEqual(updated.count(b"IAM_GOOGLE_CLIENT_ID="), 1)

    def test_rejects_env_injection_and_partial_pairs(self):
        for value in ("a\nIAM_COOKIE_KEY=evil", "a\rb", "a\x00b", None, ""):
            with self.subTest(value_type=type(value).__name__):
                values = candidate(); values["IAM_GOOGLE_CLIENT_SECRET"] = value
                with self.assertRaises(RuntimeError): activation.updated_environment(b"", values)
        values = candidate(); values.pop("IAM_APPLE_CLIENT_ID")
        with self.assertRaises(RuntimeError): activation.updated_environment(b"", values)

    def test_rejects_duplicate_existing_keys(self):
        with self.assertRaises(RuntimeError):
            activation.updated_environment(b"KEEP=a\nKEEP=b\n", candidate())

    def test_rejects_unrelated_secret_change(self):
        with self.assertRaises(RuntimeError):
            activation.provider_values({"IAM_COOKIE_KEY": "original"}, dict(candidate(), IAM_COOKIE_KEY="changed"))
        with self.assertRaises(RuntimeError):
            activation.provider_values({"IAM_COOKIE_KEY": "original"}, candidate())

    def test_accepts_reviewed_helper_header_with_optional_typ(self):
        for header in ({"alg": "ES256", "kid": "RB4CTQPLR5"}, {"alg": "ES256", "kid": "RB4CTQPLR5", "typ": "JWT"}):
            self.assertEqual(activation.provider_values({}, candidate(header))["IAM_APPLE_CLIENT_ID"], "com.teamofsilicons.iam.web")

    def test_rejects_wrong_apple_key_algorithm_and_audience(self):
        for header in ({"alg": "none", "kid": "RB4CTQPLR5"}, {"alg": "ES256", "kid": "wrong"}, {"alg": "ES256", "kid": "RB4CTQPLR5", "jku": "https://invalid.example"}):
            with self.assertRaises(RuntimeError): activation.provider_values({}, candidate(header))
        claims = {"iss": "LTBSK59BJ2", "sub": "com.teamofsilicons.iam.web", "aud": "wrong",
                  "iat": int(time.time()), "exp": int(time.time()) + 90 * 86400}
        with self.assertRaises(RuntimeError): activation.provider_values({}, candidate(claims=claims))

    def test_never_restarts_worker_for_auth_credentials(self):
        with patch.object(activation, "run", return_value=b""), patch.object(activation, "ready"):
            activation.start(None)
            first = activation.run.call_args_list[0].args[0]
            self.assertEqual(first, ["systemctl", "start", "silicon-iam-api", "silicon-iam-scoped-api"])

    def test_bootstrap_optional_credentials_and_newline_rejection(self):
        script = Path(__file__).with_name("bootstrap-production.sh").read_text()
        source = re.search(r"SOCIAL_PROVIDER_ENV=.*?jq -er '(.*?)'\)", script, re.S).group(1)
        for secret, expected in (({}, ""), ({"IAM_APPLE_CLIENT_ID": None}, ""),
                ({"IAM_GOOGLE_CLIENT_ID": "g", "IAM_GOOGLE_CLIENT_SECRET": "s"}, "IAM_GOOGLE_CLIENT_ID=g\nIAM_GOOGLE_CLIENT_SECRET=s\n")):
            result = subprocess.run(["jq", "-er", source], input=json.dumps(secret), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, expected or "\n")
        for bad in ("value\nIAM_COOKIE_KEY=evil", "value\rreturn", "value\x00null", 7):
            result = subprocess.run(["jq", "-er", source], input=json.dumps({"IAM_APPLE_CLIENT_SECRET": bad}), capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
        lines = [line for line in script.splitlines() if '"$SOCIAL_PROVIDER_ENV" >>' in line]
        self.assertEqual(len(lines), 1)
        self.assertIn("/api.env", lines[0])


if __name__ == "__main__":
    unittest.main()
