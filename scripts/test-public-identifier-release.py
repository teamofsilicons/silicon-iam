#!/usr/bin/env python3
"""Test the public-ID operator without contacting or modifying production."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit, urlunsplit
import uuid

path = Path(__file__).resolve().parents[1] / 'deploy/aws/release-public-identifiers.py'
spec = importlib.util.spec_from_file_location('public_id_release', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ConfigurationTests(unittest.TestCase):
    def test_coordinator_gate_is_bound_to_exact_rehearsed_release(self):
        with tempfile.TemporaryDirectory() as directory:
            release = object.__new__(module.Release)
            release.root = Path(directory)
            gate = release.root / 'go.json'
            release.args = SimpleNamespace(await_cutover_file=gate, revision='a' * 40, image='example@sha256:' + 'b' * 64)
            release.state = {}
            expected = {'release_directory': str(release.root), 'revision': release.args.revision, 'image': release.args.image}
            gate.write_text(json.dumps({**expected, 'release_directory': '/stale-release'}))
            gate.chmod(0o600)
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)):
                with self.assertRaisesRegex(RuntimeError, 'does not match'):
                    release.consume_cutover_gate()
                self.assertTrue(gate.exists())
                gate.write_text(json.dumps(expected))
                release.consume_cutover_gate()
            self.assertFalse(gate.exists())
            self.assertEqual(release.state['coordinator_gate_consumed'], expected)

    def test_coordinator_gate_rejects_nonprivate_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            release = object.__new__(module.Release)
            release.root = Path(directory)
            gate = release.root / 'go.json'
            gate.write_text('{}')
            release.args = SimpleNamespace(await_cutover_file=gate)
            release.state = {}
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=0, st_mode=0o100644)):
                with self.assertRaisesRegex(RuntimeError, 'private root-owned'):
                    release.consume_cutover_gate()
            self.assertTrue(gate.exists())

    def test_only_mapped_field_changes_and_secret_bytes_stay_identical(self):
        original = '# retained\r\nIAM_HONEYCOMB_APP_ID=tos>honeycomb\r\nKEY=contains-tos>honeycomb=secret\r\nOTHER=value\n'
        expected = original.replace('IAM_HONEYCOMB_APP_ID=tos>honeycomb', 'IAM_HONEYCOMB_APP_ID=honeycomb')
        self.assertEqual(module.rewrite_runtime_configuration(original, {'tos>honeycomb': 'honeycomb'}), expected)

    def test_unknown_or_duplicate_identity_fails(self):
        for text in ['IAM_HONEYCOMB_APP_ID=other>app\n', 'IAM_HONEYCOMB_APP_ID=tos>honeycomb\nIAM_HONEYCOMB_APP_ID=tos>honeycomb\n']:
            with self.assertRaises(RuntimeError):
                module.rewrite_runtime_configuration(text, {'tos>honeycomb': 'honeycomb'})

    def test_expiry_sql_refuses_ambiguous_or_injected_ids(self):
        for ids in [[], ['not-a-uuid'], ['00000000-0000-0000-0000-000000000001'] * 2]:
            with self.assertRaises((RuntimeError, ValueError)):
                module.replay_expiry_sql(ids)

    def test_operator_never_invokes_previous_uuid_conversion(self):
        source = path.read_text()
        self.assertNotIn('iam-canonical-cutover', source)
        self.assertNotIn('canonical_replay_cutover', source)


@unittest.skipUnless(os.getenv('IAM_OPERATOR_TEST_ADMIN_URL'), 'requires explicit disposable loopback PostgreSQL')
class PostgreSQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin = os.environ['IAM_OPERATOR_TEST_ADMIN_URL']
        parsed = urlsplit(cls.admin)
        if parsed.hostname not in ('localhost', '127.0.0.1', '::1'):
            raise RuntimeError('Operator test database must be loopback')
        cls.name = 'iam_operator_' + uuid.uuid4().hex[:12]
        cls.psql = os.getenv('IAM_OPERATOR_TEST_PSQL', 'psql')
        cls.command(cls.admin, 'CREATE DATABASE ' + cls.name)
        cls.url = urlunsplit(parsed._replace(path='/' + cls.name))
        cls.command(cls.url, '''CREATE SCHEMA iam; CREATE SCHEMA iam_private;
          CREATE TABLE iam.idempotency_records(id uuid PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now()-interval '1 hour', expires_at timestamptz NOT NULL DEFAULT now()+interval '1 day', updated_at timestamptz NOT NULL DEFAULT now(), response_ciphertext bytea NOT NULL DEFAULT decode('abcdef','hex'), response_status integer NOT NULL DEFAULT 200, lease_owner uuid, CHECK(expires_at>created_at));
          CREATE TABLE iam.honeycomb_operations(completed boolean, response_expires_at timestamptz);
          CREATE TABLE iam_private.organization_action_approvals(status text, expires_at timestamptz);''')

    @classmethod
    def command(cls, url, query, check=True):
        result = subprocess.run([cls.psql, '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-d', url, '-c', query], text=True, capture_output=True)
        if check and result.returncode:
            raise AssertionError(result.stderr)
        return result

    @classmethod
    def tearDownClass(cls):
        cls.command(cls.admin, 'DROP DATABASE ' + cls.name + ' WITH (FORCE)')

    def sql(self, query):
        return self.command(self.url, query).stdout.strip()

    def setUp(self):
        self.sql('TRUNCATE iam.idempotency_records,iam.honeycomb_operations,iam_private.organization_action_approvals')
        self.ids = [str(uuid.uuid4()), str(uuid.uuid4())]
        for value in self.ids:
            self.sql("INSERT INTO iam.idempotency_records(id) VALUES('" + value + "')")
        self.directory = tempfile.TemporaryDirectory()
        self.release = object.__new__(module.Release)
        self.release.root = Path(self.directory.name)
        self.release.args = SimpleNamespace(expire_live_replays=False)
        self.release.state = {'services_stopped': False}

    def tearDown(self):
        self.directory.cleanup()

    def test_default_live_mode_cannot_expire_records(self):
        with self.assertRaisesRegex(RuntimeError, 'Live replay windows remain'):
            self.release.prepare_public_ids('production', self.sql)
        self.assertEqual(self.sql('SELECT count(*) FROM iam.idempotency_records WHERE expires_at>now()'), '2')

    def test_live_expiry_rejects_active_writer_even_with_authorization(self):
        self.release.args.expire_live_replays = True
        self.release.state['services_stopped'] = True
        self.release.run = lambda command: b'active\n'
        with self.assertRaisesRegex(RuntimeError, 'not fully stopped'):
            self.release.prepare_public_ids('production', self.sql)
        self.assertEqual(self.sql('SELECT count(*) FROM iam.idempotency_records WHERE expires_at>now()'), '2')

    def test_live_expiry_requires_both_verified_backups(self):
        self.release.args.expire_live_replays = True
        self.release.writers_stopped = lambda: None
        archive = self.release.root / 'backup.dump'
        archive.write_bytes(b'isolated test backup')
        (self.release.root / 'backups.json').write_text(json.dumps({'production': {'path': str(archive), 'sha256': module.digest(archive)}}))
        with self.assertRaisesRegex(RuntimeError, 'Both quiesced'):
            self.release.prepare_public_ids('production', self.sql)
        (self.release.root / 'backups.json').write_text(json.dumps({label: {'path': str(archive), 'sha256': 'incorrect'} for label in ('production', 'testing')}))
        with self.assertRaisesRegex(RuntimeError, 'digest changed'):
            self.release.prepare_public_ids('production', self.sql)
        self.assertEqual(self.sql('SELECT count(*) FROM iam.idempotency_records WHERE expires_at>now()'), '2')

    def test_missing_private_receipt_archive_prevents_expiry(self):
        with patch.object(module, 'atomic_json', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(OSError, 'disk full'):
                self.release.prepare_public_ids('production', self.sql, isolated=True)
        self.assertEqual(self.sql('SELECT count(*) FROM iam.idempotency_records WHERE expires_at>now()'), '2')

    def test_copy_expiry_retains_every_receipt_and_lease_byte(self):
        self.release.prepare_public_ids('production', self.sql, isolated=True)
        self.assertEqual(self.sql('SELECT count(*) FROM iam.idempotency_records WHERE expires_at>now()'), '0')
        self.assertEqual(self.sql("SELECT count(*) FROM iam.idempotency_records WHERE response_ciphertext=decode('abcdef','hex') AND response_status=200 AND lease_owner IS NULL"), '2')
        before = json.loads((self.release.root / 'rehearsal-production-replay-records-before.json').read_text())
        self.assertEqual({row['id'] for row in before}, set(self.ids))

    def test_unlisted_live_record_rolls_back(self):
        result = self.command(self.url, module.replay_expiry_sql(self.ids[:1]), check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Replay set changed', result.stderr)
        self.assertEqual(self.sql('SELECT count(*) FROM iam.idempotency_records WHERE expires_at>now()'), '2')

    def test_pending_approval_and_honeycomb_operation_are_never_cancelled(self):
        self.sql("INSERT INTO iam_private.organization_action_approvals VALUES('approved',now()+interval '1 day')")
        with self.assertRaisesRegex(RuntimeError, 'Pending approval'):
            self.release.prepare_public_ids('testing', self.sql, isolated=True)
        self.sql('TRUNCATE iam_private.organization_action_approvals; INSERT INTO iam.honeycomb_operations VALUES(false,NULL)')
        with self.assertRaisesRegex(RuntimeError, 'Pending approval'):
            self.release.prepare_public_ids('testing', self.sql, isolated=True)
        self.assertEqual(self.sql('SELECT count(*) FROM iam.idempotency_records WHERE expires_at>now()'), '2')

    def test_receipt_mutation_trigger_aborts_whole_expiry(self):
        self.sql("CREATE FUNCTION iam.change_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.response_ciphertext:=decode('00','hex'); RETURN NEW; END $$; CREATE TRIGGER changed BEFORE UPDATE ON iam.idempotency_records FOR EACH ROW EXECUTE FUNCTION iam.change_receipt()")
        try:
            result = self.command(self.url, module.replay_expiry_sql(self.ids), check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Expiry altered retained receipt bytes', result.stderr)
            self.assertEqual(self.sql('SELECT count(*) FROM iam.idempotency_records WHERE expires_at>now()'), '2')
        finally:
            self.sql('DROP TRIGGER changed ON iam.idempotency_records; DROP FUNCTION iam.change_receipt()')


if __name__ == '__main__':
    unittest.main()
