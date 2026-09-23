#!/usr/bin/env python3
"""Validate release archive boundaries without compiling or downloading binaries."""
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('package_honeycomb', Path(__file__).with_name('package-honeycomb.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ArchiveTest(unittest.TestCase):
    def test_complete_deterministic_archive_excludes_workspace_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for target in module.TARGETS:
                binary = root / target / ('iam.exe' if target.startswith('windows-') else 'iam')
                binary.parent.mkdir()
                binary.write_bytes(b'synthetic-' + target.encode())
            (root / '.env').write_text('do-not-package')
            first, second = root / 'first.tar.gz', root / 'second.tar.gz'
            module.package(root, first, 'iam', '1.10.0')
            module.package(root, second, 'iam', '1.10.0')
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first) as archive:
                self.assertEqual(len(archive.getmembers()), 13)
                self.assertTrue(all(member.isfile() for member in archive.getmembers()))
                manifest = json.load(archive.extractfile('honeycomb.yaml'))
                self.assertEqual(set(manifest['targets']), set(module.TARGETS))
                self.assertEqual(manifest['app_id'], 'iam')
                self.assertNotIn('.env', archive.getnames())
                cli_license = (Path(__file__).resolve().parents[1] / 'crates/cli/LICENSE').read_bytes()
                self.assertIn(b'Apache License', cli_license)
                self.assertIn(b'Version 2.0, January 2004', cli_license)
                for target in module.TARGETS:
                    self.assertEqual(archive.extractfile(f'targets/{target}/LICENSE').read(), cli_license)
            with self.assertRaises(FileExistsError):
                module.package(root, first, 'iam', '1.10.0')

    def test_legacy_qualified_application_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "bare application identifier"):
                module.package(root, root / 'out.tar.gz', 'tos>iam', '4.0.0')
            self.assertFalse((root / 'out.tar.gz').exists())

    def test_missing_or_linked_binary_cannot_be_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                module.package(root, root / 'out.tar.gz', 'iam', '1.10.0')
            self.assertFalse((root / 'out.tar.gz').exists())
            directory = root / module.TARGETS[0]
            directory.mkdir()
            (root / 'secret').write_bytes(b'not-a-binary')
            (directory / 'iam').symlink_to(root / 'secret')
            with self.assertRaises(ValueError):
                module.package(root, root / 'out.tar.gz', 'iam', '1.10.0')


if __name__ == '__main__':
    unittest.main()
