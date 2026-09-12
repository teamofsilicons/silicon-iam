import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { build } from "esbuild";
const directory = await mkdtemp(join(tmpdir(), "iam-frontend-tests-"));
try {
  const entries = (await readdir("tests")).filter((name) =>
    name.endsWith(".test.ts"),
  );
  await build({
    entryPoints: entries.map((name) => join("tests", name)),
    outdir: directory,
    outExtension: { ".js": ".mjs" },
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node24",
  });
  const result = spawnSync(
    process.execPath,
    [
      "--test",
      ...entries.map((name) => join(directory, name.replace(/\.ts$/, ".mjs"))),
    ],
    {
      stdio: "inherit",
    },
  );
  process.exitCode = result.status ?? 1;
} finally {
  await rm(directory, { recursive: true, force: true });
}
