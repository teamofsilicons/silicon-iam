import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
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

    def test_rollback_uses_reverse_compare_and_swap(self):
        self.args.action = "rollback"
        mock = self.perform("new", final="old")
        args = mock.call_args.args
        self.assertEqual(args[args.index("--remove-from-version-id") + 1], "new")
        self.assertEqual(args[args.index("--move-to-version-id") + 1], "old")


if __name__ == "__main__":
    unittest.main()
