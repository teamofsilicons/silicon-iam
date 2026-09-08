import { build } from "esbuild";
await build({
  entryPoints: ["server/gateway.ts"],
  outfile: "dist/server/index.js",
  bundle: true,
  platform: "browser",
  format: "esm",
  target: "es2022",
});
await build({
  entryPoints: ["server/node.ts"],
  outfile: "dist/server/node.js",
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
});
