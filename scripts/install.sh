#!/bin/sh
# Install the CLI and start its per-user updater. No authentication is performed.
set -eu
case "$(uname -s)" in
  Darwin|Linux) ;;
  *) echo 'This installer supports macOS and Linux. Install silicon-iam-cli with Cargo and supervise `iam daemon run` on other platforms.' >&2; exit 1 ;;
esac
command -v curl >/dev/null 2>&1 || { echo 'Install curl first.' >&2; exit 1; }
if ! command -v cargo >/dev/null 2>&1; then
  rustup_script=$(mktemp)
  trap 'rm -f "$rustup_script"' EXIT HUP INT TERM
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error https://sh.rustup.rs -o "$rustup_script"
  sh "$rustup_script" -y --profile minimal --default-toolchain stable
  . "${CARGO_HOME:-$HOME/.cargo}/env"
  rm -f "$rustup_script"
  trap - EXIT HUP INT TERM
fi
if command -v rustup >/dev/null 2>&1; then
  rustup update stable --no-self-update
  export RUSTUP_TOOLCHAIN=stable
fi
# This path is shared by the worker and explicit updates, including custom roots.
iam_install_root=${CARGO_INSTALL_ROOT:-${CARGO_HOME:-$HOME/.cargo}}
if command -v rustup >/dev/null 2>&1; then
  cargo +stable install silicon-iam-cli --version ">=1.9.0" --locked --force --root "$iam_install_root"
else
  cargo install silicon-iam-cli --version ">=1.9.0" --locked --force --root "$iam_install_root"
fi
export PATH="$iam_install_root/bin:$PATH"
"$iam_install_root/bin/iam" daemon install
printf '\nInstalled IAM. Add %s/bin to PATH if needed.\n' "$iam_install_root"
printf 'Start with: iam --help\nVerify updater: iam daemon status --json\nNo IAM login was performed.\n'
