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
            module.package(root, first, 'tos>iam', '1.10.0')
            module.package(root, second, 'tos>iam', '1.10.0')
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first) as archive:
                self.assertEqual(len(archive.getmembers()), 13)
                self.assertTrue(all(member.isfile() for member in archive.getmembers()))
                manifest = json.load(archive.extractfile('honeycomb.yaml'))
                self.assertEqual(set(manifest['targets']), set(module.TARGETS))
                self.assertNotIn('.env', archive.getnames())
            with self.assertRaises(FileExistsError):
                module.package(root, first, 'tos>iam', '1.10.0')

    def test_missing_or_linked_binary_cannot_be_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                module.package(root, root / 'out.tar.gz', 'tos>iam', '1.10.0')
            self.assertFalse((root / 'out.tar.gz').exists())
            directory = root / module.TARGETS[0]
            directory.mkdir()
            (root / 'secret').write_bytes(b'not-a-binary')
            (directory / 'iam').symlink_to(root / 'secret')
            with self.assertRaises(ValueError):
                module.package(root, root / 'out.tar.gz', 'tos>iam', '1.10.0')


if __name__ == '__main__':
    unittest.main()
