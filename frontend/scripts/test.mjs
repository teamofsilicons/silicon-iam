import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { build } from "esbuild";
const directory = await mkdtemp(join(tmpdir(), "iam-frontend-tests-"));
try {
  const outfile = join(directory, "tests.mjs");
  await build({
    entryPoints: ["tests/login-flow.test.ts"],
    outfile,
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node24",
  });
  const result = spawnSync(process.execPath, ["--test", outfile], {
    stdio: "inherit",
  });
  process.exitCode = result.status ?? 1;
} finally {
  await rm(directory, { recursive: true, force: true });
}
