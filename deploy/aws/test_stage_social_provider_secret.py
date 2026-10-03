import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("staging", Path(__file__).with_name("stage-social-provider-secret.py"))
staging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(staging)


class SecretCAS(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.previous = {"keep": "must-not-change"}
        self.candidate = dict(self.previous, IAM_GOOGLE_CLIENT_ID="sample")
        self.args = argparse.Namespace(action="promote", secret_arn="test-arn", receipt=self.root / "receipt.json",
                                       host_plan=self.root / "host-plan.json")
        self.state = {"previous_version": "old", "candidate_version": "new", "secret_arn": "test-arn",
                      "candidate_sha256": hashlib.sha256(staging.serialized(self.candidate)).hexdigest(), "stage": "staged"}
        self.args.receipt.write_text(json.dumps(self.state))
        self.args.host_plan.write_text(json.dumps({"prepared": True, "previous_version": "old", "secret_arn": "test-arn",
                                                  "revision": "45a3fdf90c32c9e35b61cb3bed789ebff71d800e"}))

    def perform(self, current, final="new", aws_error=None):
        calls = iter([(current, self.previous), ("old", self.previous), ("new", self.candidate), (final, self.candidate)])
        with patch.object(staging, "get", side_effect=lambda *_: next(calls)), \
             patch.object(staging.activation, "provider_values"), \
             patch.object(staging, "aws", side_effect=aws_error) as mock, contextlib.redirect_stdout(io.StringIO()):
            staging.move(self.args)
            return mock

    def test_promotion_has_expected_version_compare_and_swap(self):
        mock = self.perform("old")
        args = mock.call_args.args
        self.assertEqual(args[1], "update-secret-version-stage")
        self.assertEqual(args[args.index("--remove-from-version-id") + 1], "old")
        self.assertEqual(args[args.index("--move-to-version-id") + 1], "new")

    def test_external_concurrent_version_cannot_be_overwritten(self):
        with self.assertRaises(RuntimeError): self.perform("somebody-elses-new-version")
        self.assertEqual(json.loads(self.args.receipt.read_text())["stage"], "staged")

    def test_lost_response_recovers_without_second_mutation(self):
        mock = self.perform("new")
        mock.assert_not_called()
        self.assertEqual(json.loads(self.args.receipt.read_text())["stage"], "promoted")

    def test_atomic_race_failure_does_not_record_success(self):
        with self.assertRaises(RuntimeError): self.perform("old", aws_error=RuntimeError("CAS failed"))
        self.assertEqual(json.loads(self.args.receipt.read_text())["stage"], "staged")

    def test_requires_successful_source_bound_host_plan(self):
        self.args.host_plan.write_text(json.dumps({"prepared": False}))
        with self.assertRaises(RuntimeError): self.perform("old")

    def test_promotion_rejects_host_plan_with_different_apple_mode(self):
        state = dict(self.state, disable_apple=True)
        self.args.receipt.write_text(json.dumps(state))
        with self.assertRaisesRegex(RuntimeError, "plan does not match"):
            self.perform("old")
        self.assertEqual(json.loads(self.args.receipt.read_text())["stage"], "staged")

    def test_rollback_uses_reverse_compare_and_swap(self):
        self.args.action = "rollback"
        mock = self.perform("new", final="old")
        args = mock.call_args.args
        self.assertEqual(args[args.index("--remove-from-version-id") + 1], "new")
        self.assertEqual(args[args.index("--move-to-version-id") + 1], "old")


class DisableAppleStage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.google = {"IAM_GOOGLE_CLIENT_ID": "test.apps.googleusercontent.com", "IAM_GOOGLE_CLIENT_SECRET": "synthetic-google-secret"}
        self.previous = dict(self.google, IAM_APPLE_CLIENT_ID="com.teamofsilicons.iam.web", IAM_APPLE_CLIENT_SECRET="retained-previous-apple-secret", keep={"nested": ["untouched"]})
        self.google_path = self.root / "google.json"
        self.google_path.write_text(json.dumps(self.google)); self.google_path.chmod(0o600)
        self.args = argparse.Namespace(action="stage", google=self.google_path, apple=None, disable_apple=True,
                                       previous_version="old", secret_arn="arn", receipt=self.root / "receipt.json")
        self.stored = None

    def run_stage(self):
        def get(_args, version=None):
            if version:
                return version, self.stored
            return "old", self.previous
        def aws(_args, *parts):
            self.assertEqual(parts[0], "put-secret-value")
            path = Path(parts[parts.index("--secret-string") + 1].removeprefix("file://"))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.stored = json.loads(path.read_text())
            self.assertNotEqual(parts[parts.index("--version-stages") + 1], "AWSCURRENT")
            return {"VersionId": parts[parts.index("--client-request-token") + 1]}
        output = io.StringIO()
        with patch.object(staging, "get", side_effect=get), patch.object(staging, "aws", side_effect=aws) as calls, contextlib.redirect_stdout(output):
            staging.stage(self.args)
        return calls, output.getvalue()

    def test_stage_removes_only_apple_preserves_everything_else_and_redacts_output(self):
        calls, output = self.run_stage()
        expected = {key: value for key, value in self.previous.items() if key not in staging.activation.APPLE_FIELDS}
        self.assertEqual(self.stored, expected)
        self.assertEqual(calls.call_count, 1)
        state = json.loads(self.args.receipt.read_text())
        self.assertTrue(state["disable_apple"])
        self.assertEqual(state["changed_fields"], sorted(staging.activation.APPLE_FIELDS))
        self.assertEqual(state["stage"], "staged")
        self.assertNotIn(self.google["IAM_GOOGLE_CLIENT_SECRET"], output)
        self.assertNotIn(self.previous["IAM_APPLE_CLIENT_SECRET"], output)
        self.assertFalse(list(self.root.glob(".secret-*")))
        version = state["candidate_version"]
        self.run_stage()
        self.assertEqual(json.loads(self.args.receipt.read_text())["candidate_version"], version)

    def test_stage_rejects_accidental_google_rotation_before_any_write(self):
        changed = dict(self.google, IAM_GOOGLE_CLIENT_SECRET="different")
        self.google_path.write_text(json.dumps(changed))
        with patch.object(staging, "get", return_value=("old", self.previous)), patch.object(staging, "aws") as aws, self.assertRaisesRegex(RuntimeError, "preserve"):
            staging.stage(self.args)
        aws.assert_not_called()
        self.assertFalse(self.args.receipt.exists())

    def test_disable_and_apple_candidate_are_mutually_exclusive_at_cli_boundary(self):
        command = [sys.executable, str(Path(staging.__file__)), "stage", "--secret-arn", "arn", "--receipt", str(self.args.receipt), "--apple", "ignored.json", "--disable-apple"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not allowed with argument", result.stderr)
        self.assertFalse(self.args.receipt.exists())


if __name__ == "__main__":
    unittest.main()
