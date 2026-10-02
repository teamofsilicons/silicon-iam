"""Read-only release configuration regressions; no AWS or service operations."""
import importlib.util
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


if __name__ == "__main__":
    unittest.main()
