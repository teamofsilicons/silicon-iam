import { readFileSync, lstatSync } from "node:fs";

export function loadTelemetryKey(
  env: Record<string, string | undefined>,
): string | undefined {
  if (/^(off|false|0|no)$/i.test(env.IAM_TELEMETRY?.trim() || ""))
    return undefined;
  if (env.IAM_TELEMETRY_KEY?.trim()) return env.IAM_TELEMETRY_KEY.trim();
  const root = `${env.SILICON_HOME || env.HOME}/.silicon-iam`;
  let home = env.SILICON_IAM_HOME || root;
  if (!env.SILICON_IAM_HOME) {
    try {
      home = readFileSync(`${root}/.silicon-iam-home`, "utf8").trim() || root;
    } catch {
      /* No saved home override. */
    }
  }
  const path = env.IAM_TELEMETRY_KEY_FILE || `${home}/telemetry.key`;
  try {
    const stat = lstatSync(path);
    if (
      !stat.isFile() ||
      stat.size > 256 ||
      (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    )
      return undefined;
    return readFileSync(path, "utf8").trim();
  } catch {
    return undefined;
  }
}
