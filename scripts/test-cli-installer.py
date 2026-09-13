#!/usr/bin/env python3
"""Verify installation/startup ordering with local command doubles; no downloads."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().with_name("install.sh")


class InstallerTest(unittest.TestCase):
    def run_installer(self, fail=False):
        with tempfile.TemporaryDirectory(prefix="iam installer ") as temporary:
            root = Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            programs = {
                "uname": "echo Linux\n",
                "curl": "echo unexpected-download >&2; exit 1\n",
                "rustup": "printf 'rustup %s\\n' \"$*\" >> \"$CALLS\"\n",
                "cargo": """printf 'cargo %s\\n' "$*" >> "$CALLS"
[ "$FAIL_INSTALL" = no ] || exit 42
mkdir -p "$CARGO_INSTALL_ROOT/bin"
cat > "$CARGO_INSTALL_ROOT/bin/iam" <<'BIN'
#!/bin/sh
printf 'iam %s\\n' "$*" >> "$CALLS"
BIN
chmod +x "$CARGO_INSTALL_ROOT/bin/iam"
""",
            }
            for name, body in programs.items():
                path = tools / name
                path.write_text("#!/bin/sh\nset -eu\n" + body)
                path.chmod(0o700)
            env = {
                "PATH": f"{tools}:/usr/bin:/bin",
                "HOME": str(root / "user"),
                "CARGO_INSTALL_ROOT": str(root / "custom install"),
                "CALLS": str(root / "calls"),
                "FAIL_INSTALL": "yes" if fail else "no",
            }
            result = subprocess.run(["sh", str(INSTALLER)], env=env, text=True,
                                    capture_output=True, check=False)
            calls = (root / "calls").read_text()
            return result, calls

    def test_starts_daemon_after_installing_into_custom_root(self):
        result, calls = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--version >=1.9.0 --locked --force --root", calls)
        self.assertIn("custom install", calls)
        self.assertTrue(calls.rstrip().endswith("iam daemon install"))
        self.assertNotIn("auth", calls)

    def test_failed_install_does_not_register_a_service(self):
        result, calls = self.run_installer(fail=True)
        self.assertEqual(result.returncode, 42)
        self.assertNotIn("iam daemon install", calls)


if __name__ == "__main__":
    unittest.main()
