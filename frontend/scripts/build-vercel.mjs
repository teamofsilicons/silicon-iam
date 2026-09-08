import { build } from "esbuild";
import { cp, mkdir, writeFile } from "node:fs/promises";

const output = ".vercel/output";
const fn = `${output}/functions/gateway.func`;
await mkdir(fn, { recursive: true });
await build({
  entryPoints: ["server/vercel.ts"],
  outfile: `${fn}/index.mjs`,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node24",
});
await cp("dist/client", `${fn}/client`, { recursive: true });
await writeFile(
  `${fn}/.vc-config.json`,
  JSON.stringify({
    runtime: "nodejs24.x",
    handler: "index.mjs",
    launcherType: "Nodejs",
    shouldAddHelpers: false,
    maxDuration: 60,
    regions: ["iad1"],
  }),
);
await writeFile(
  `${output}/config.json`,
  JSON.stringify({
    version: 3,
    routes: [{ src: "/(.*)", dest: "/gateway" }],
  }),
);
