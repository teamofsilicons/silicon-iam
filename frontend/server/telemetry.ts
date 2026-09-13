import { toIngestBatch } from "@teamofsilicons/space-station-web";
import { safeBatch, TELEMETRY_TABLE } from "../src/telemetry-policy.ts";
import type { Environment } from "./session.ts";
const MAX_BODY = 65536;
let windowStart = 0,
  requests = 0;
export function deploymentTelemetryEnabled(env: Environment): boolean {
  return (
    !/^(0|false|off|no)$/i.test(env.IAM_TELEMETRY?.trim() || "") &&
    /^table-siliconiam-[0-9a-f]{32}$/i.test(env.IAM_TELEMETRY_KEY || "")
  );
}
async function boundedJson(
  request: Pick<Request, "headers" | "body">,
): Promise<unknown> {
  if (Number(request.headers.get("content-length")) > MAX_BODY)
    throw new Error("too_large");
  let length = 0;
  const chunks: Uint8Array[] = [];
  const reader = request.body?.getReader();
  if (!reader) throw new Error("invalid");
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > MAX_BODY) {
        await reader.cancel();
        throw new Error("too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return JSON.parse(new TextDecoder().decode(bytes));
}
export async function collectTelemetry(
  request: Request,
  env: Environment,
  transport: typeof fetch = fetch,
): Promise<Response> {
  const reply = (status: number, code: string) =>
    Response.json(
      { code },
      { status, headers: { "Cache-Control": "no-store" } },
    );
  const origin = new URL(request.url).origin;
  if (request.method !== "POST") return reply(405, "method_not_allowed");
  if (
    request.headers.get("origin") !== origin ||
    request.headers.get("x-iam-frontend") !== "1" ||
    request.headers.get("sec-fetch-site") === "cross-site"
  )
    return reply(403, "origin_rejected");
  if (
    !deploymentTelemetryEnabled(env) ||
    request.headers.get("x-iam-telemetry") === "off" ||
    /(?:^|;\s*)iam_telemetry=off(?:;|$)/.test(
      request.headers.get("cookie") || "",
    )
  )
    return new Response(null, { status: 204 });
  if (!request.headers.get("content-type")?.startsWith("application/json"))
    return reply(415, "json_required");
  const now = Date.now();
  if (now - windowStart >= 60000) {
    windowStart = now;
    requests = 0;
  }
  if (++requests > 120) return reply(429, "telemetry_rate_limit");
  let batch;
  try {
    batch = safeBatch(await boundedJson(request));
  } catch (error) {
    return reply(
      error instanceof Error && error.message === "too_large" ? 413 : 400,
      "invalid_telemetry_batch",
    );
  }
  const ingest = toIngestBatch({ ...batch, key: env.IAM_TELEMETRY_KEY! });
  for (let index = 0; index < ingest.records.length; index++) {
    const event = batch.events[index];
    Object.assign(ingest.records[index], {
      record: {
        schema_version: 1,
        service: "silicon-iam",
        version: "1.9.0",
        source: "iam-web",
        step: event.type.startsWith("iam.") ? "interaction" : "analytics",
        event: event.type,
        progress: event.type.endsWith("started") ? 0 : 1,
        environment:
          env.DISPLAY_ENVIRONMENT === "Production" ? "production" : "web",
        context: { ...event.data, ...event.metadata, client_reported: true },
      },
    });
  }
  try {
    const target = new URL(
      env.IAM_TELEMETRY_URL ||
        "https://backend.spacestation.teamofsilicons.com",
    );
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(
      target.hostname,
    );
    if (
      (target.protocol !== "https:" &&
        !(target.protocol === "http:" && loopback)) ||
      target.username ||
      target.password ||
      target.pathname !== "/" ||
      target.search ||
      target.hash
    )
      return reply(503, "telemetry_configuration");
    const response = await transport(new URL("/api/ingest", target), {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(3000),
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(ingest),
    });
    if (!response.ok) return reply(503, "telemetry_unavailable");
    const ack = (await boundedJson(response)) as {
      status?: string;
      batch_id?: string;
      rejected?: { code?: string }[];
      code?: string;
    };
    const rejected = ack.rejected ?? [];
    if (
      ack.batch_id !== ingest.batch_id ||
      !["ok", "rejected"].includes(ack.status || "") ||
      ack.code ||
      !Array.isArray(rejected) ||
      rejected.some((item) => item.code !== "duplicate") ||
      (ack.status === "rejected" && rejected.length === 0)
    )
      return reply(503, "telemetry_rejected");
    // Never relay table keys or upstream error bodies to browsers.
    return Response.json(
      { accepted: batch.events.length, table: TELEMETRY_TABLE },
      { status: 202, headers: { "Cache-Control": "no-store" } },
    );
  } catch {
    return reply(503, "telemetry_unavailable");
  }
}
