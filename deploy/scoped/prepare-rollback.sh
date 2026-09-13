#!/usr/bin/env bash
# Prepare old application code with a new, additive schema for readiness-safe
# rollback. This creates files only; it never builds, pushes, or deploys an image.
set -euo pipefail
umask 077

ROLLBACK_BASE=""
ROLLBACK_SCHEMA=""
ROLLBACK_OUTPUT=""
ROLLBACK_ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
while (($#)); do
  case "$1" in
    --base) ROLLBACK_BASE="${2:?missing base commit}"; shift 2 ;;
    --schema) ROLLBACK_SCHEMA="${2:?missing schema commit}"; shift 2 ;;
    --output) ROLLBACK_OUTPUT="${2:?missing output directory}"; shift 2 ;;
    -h|--help)
      echo 'Usage: prepare-rollback.sh --base <old-commit> --schema <tested-release-commit> --output <new-directory>'
      exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 64 ;;
  esac
done
[[ -n "$ROLLBACK_BASE" && -n "$ROLLBACK_SCHEMA" && -n "$ROLLBACK_OUTPUT" ]] || { echo 'Supply --base, --schema and --output.' >&2; exit 64; }
ROLLBACK_BASE=$(git -C "$ROLLBACK_ROOT" rev-parse --verify "$ROLLBACK_BASE^{commit}")
ROLLBACK_SCHEMA=$(git -C "$ROLLBACK_ROOT" rev-parse --verify "$ROLLBACK_SCHEMA^{commit}")
git -C "$ROLLBACK_ROOT" merge-base --is-ancestor "$ROLLBACK_BASE" "$ROLLBACK_SCHEMA"
[[ ! -e "$ROLLBACK_OUTPUT" ]] || { echo 'Output directory must not exist.' >&2; exit 1; }

# A compatibility rollback must never rewrite an already-applied migration.
# Additive DDL alone is not proof of behavioral compatibility; review the SQL
# and test the old code against the upgraded schema before production use.
if git -C "$ROLLBACK_ROOT" diff --name-status "$ROLLBACK_BASE" "$ROLLBACK_SCHEMA" -- migrations \
  | awk '$1 != "A" { failed = 1 } END { exit !failed }'; then
  echo 'Existing migrations changed; refusing automatic compatibility preparation.' >&2
  exit 1
fi
mkdir -m 0700 -p "$ROLLBACK_OUTPUT"
ROLLBACK_OUTPUT=$(cd "$ROLLBACK_OUTPUT" && pwd)
git -C "$ROLLBACK_ROOT" archive "$ROLLBACK_BASE" | tar -x -C "$ROLLBACK_OUTPUT"
git -C "$ROLLBACK_ROOT" archive "$ROLLBACK_SCHEMA" migrations deploy/postgres/runtime-grants.sql \
  | tar -x -C "$ROLLBACK_OUTPUT"
python3 - "$ROLLBACK_OUTPUT" "$ROLLBACK_BASE" "$ROLLBACK_SCHEMA" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
paths = sorted(root.joinpath('migrations').rglob('*.sql'))
paths.append(root / 'deploy/postgres/runtime-grants.sql')
manifest = {
    'application_revision': sys.argv[2],
    'schema_revision': sys.argv[3],
    'build_revision': sys.argv[2] + '+schema-' + sys.argv[3][:12],
    'schema_sha256': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
    'purpose': 'Rollback application code while retaining the upgraded schema and exact readiness checks',
}
(root / 'rollback-source.json').write_text(json.dumps(manifest, indent=2) + '\n')
print('Prepared compatibility source:', root)
print('Build revision:', manifest['build_revision'])
PY
