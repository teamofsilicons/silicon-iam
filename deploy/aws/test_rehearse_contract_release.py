"""Safety guards for the isolated release operator. No AWS/DB operations."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("rehearsal", Path(__file__).with_name("rehearse-contract-release.py"))
REHEARSAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REHEARSAL)


class IsolatedRehearsal(unittest.TestCase):
    def test_only_pinned_subset_is_accepted_before_migration(self):
        inventory = [{"version": 1, "checksum": "a"}, {"version": 2, "checksum": "b"}]
        self.assertEqual(REHEARSAL.validate_ledger("1|a|t", inventory), {1: "a"})
        for output in ("1|drift|t", "3|c|t", "1|a|f", "1|a|t\n1|a|t", ""):
            with self.assertRaises(RuntimeError):
                REHEARSAL.validate_ledger(output, inventory)
        with self.assertRaisesRegex(RuntimeError, "Incomplete"):
            REHEARSAL.validate_ledger("1|a|t", inventory, complete=True)
        self.assertEqual(REHEARSAL.validate_ledger("1|a|t\n2|b|t", inventory, complete=True), {1: "a", 2: "b"})

    def test_restore_has_no_external_network_or_published_ports_and_bounded_resources(self):
        command = REHEARSAL.restore_command("iam-contract-rehearsal-123", "postgres@sha256:" + "a" * 64)
        for option, value in (("--network", "none"), ("--memory", "512m"), ("--cpus", "1")):
            self.assertEqual(command[command.index(option) + 1], value)
        self.assertNotIn("--publish", command)
        self.assertNotIn("--privileged", command)
        self.assertNotIn("--volume", command)
        with self.assertRaises(RuntimeError):
            REHEARSAL.restore_command("silicon-iam-api", "postgres@sha256:" + "a" * 64)
        with self.assertRaises(RuntimeError):
            REHEARSAL.restore_command("iam-contract-rehearsal-123", "postgres:17")

    def test_database_role_names_are_quoted(self):
        self.assertEqual(REHEARSAL.quote_identifier('role"with-quote'), '"role""with-quote"')


if __name__ == "__main__":
    unittest.main()
