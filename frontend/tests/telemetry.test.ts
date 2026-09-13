import test from "node:test";
import assert from "node:assert/strict";
import { safeBatch, safeRoute, preference } from "../src/telemetry-policy";
import { collectTelemetry } from "../server/telemetry";
import { apiHeaders } from "../server/session";
const key = "table-siliconiam-0123456789abcdef0123456789abcdef";
const env = {
  API_UPSTREAM: "https://backend.example.test",
  CONSOLE_ORIGIN: "https://iam.example.test",
  AUTH_ORIGIN: "https://iam.example.test",
  SESSION_COOKIE_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  IAM_TELEMETRY_KEY: key,
};
const batch = {
  table: "siliconiam",
  events: [
    {
      id: "00000000-0000-0000-0000-000000000001",
      type: "network",
      data: {
        url: "/api/v1/carbon-ids/alice@example.com/availability?code=123456",
        status: 200,
        method: "GET",
        message: "slt_private",
        authorization: "Bearer secret",
        form: { code: "123456" },
      },
      metadata: {
        path: "/login?token=slt_private",
        session_id: "00000000-0000-0000-0000-000000000002",
        occurred_at: "2026-09-13T00:00:00Z",
        referrer: "https://other.example/secret",
        user_agent: "private",
      },
    },
  ],
};
const request = (body: unknown = batch, headers: Record<string, string> = {}) =>
  new Request("https://iam.example.test/api/web/telemetry", {
    method: "POST",
    headers: {
      origin: env.CONSOLE_ORIGIN,
      "content-type": "application/json",
      "x-iam-frontend": "1",
      ...headers,
    },
    body: JSON.stringify(body),
  });

test("automatic and explicit web records remove credentials, contacts, inputs, queries and error messages", () => {
  const clean = safeBatch(batch),
    text = JSON.stringify(clean);
  for (const secret of [
    "alice",
    "123456",
    "slt_private",
    "Bearer",
    "private",
    "other.example",
  ])
    assert.ok(!text.includes(secret), secret);
  assert.equal(
    clean.events[0].data.route,
    "/api/v1/carbon-ids/{carbon_id}/availability",
  );
  assert.equal(clean.events[0].metadata.path, "/login");
  assert.equal(safeRoute("/some/secret"), "<unmatched>");
  assert.throws(() => safeBatch({ ...batch, table: "other" }));
  assert.throws(() =>
    safeBatch({
      ...batch,
      events: [{ ...batch.events[0], type: "slt_private" }],
    }),
  );
});

test("collector acknowledges normal Space Station success, deduplicates IDs and never exposes its write key", async () => {
  const transport: typeof fetch = async (url, init) => {
    assert.equal(
      String(url),
      "https://backend.spacestation.teamofsilicons.com/api/ingest",
    );
    assert.equal(init?.redirect, "error");
    const ingest = JSON.parse(String(init?.body));
    assert.equal(ingest.records[0].key, key);
    assert.equal(ingest.records[0].metadata.record_id, batch.events[0].id);
    assert.equal(ingest.records[0].record.source, "iam-web");
    assert.equal(ingest.records[0].record.context.client_reported, true);
    assert.ok(!JSON.stringify(ingest).includes("slt_private"));
    return Response.json({ status: "ok", batch_id: ingest.batch_id }); // empty rejected is omitted by SS
  };
  const response = await collectTelemetry(request(), env, transport);
  assert.equal(response.status, 202);
  assert.ok(!(await response.text()).includes(key));
});

test("opt-out, cross-origin, oversized and wrong-table batches never reach ingestion", async () => {
  let sent = 0;
  const transport: typeof fetch = async () => {
    sent++;
    throw new Error("must not send");
  };
  assert.equal(
    (
      await collectTelemetry(
        request(),
        { ...env, IAM_TELEMETRY: "off" },
        transport,
      )
    ).status,
    204,
  );
  assert.equal(
    (
      await collectTelemetry(
        request(batch, { "x-iam-telemetry": "off" }),
        env,
        transport,
      )
    ).status,
    204,
  );
  assert.equal(
    (
      await collectTelemetry(
        request(batch, { cookie: "iam_telemetry=off" }),
        env,
        transport,
      )
    ).status,
    204,
  );
  assert.equal(
    (
      await collectTelemetry(
        request(batch, { origin: "https://other.example" }),
        env,
        transport,
      )
    ).status,
    403,
  );
  assert.equal(
    (
      await collectTelemetry(
        request({ ...batch, table: "other" }),
        env,
        transport,
      )
    ).status,
    400,
  );
  assert.equal(
    (
      await collectTelemetry(
        request({ ...batch, ignored: "x".repeat(65536) }),
        env,
        transport,
      )
    ).status,
    413,
  );
  assert.equal(
    (
      await collectTelemetry(
        request({ ...batch, events: Array(41).fill(batch.events[0]) }),
        env,
        transport,
      )
    ).status,
    400,
  );
  assert.equal(sent, 0);
});

test("rejected or mismatched acknowledgements remain retryable and never echo upstream data", async () => {
  for (const mode of ["rejected", "mismatch", "unavailable"]) {
    const response = await collectTelemetry(
      request(),
      env,
      async (_url, init) => {
        const ingest = JSON.parse(String(init?.body));
        return Response.json(
          {
            status: mode === "rejected" ? "rejected" : "ok",
            batch_id: mode === "mismatch" ? "wrong" : ingest.batch_id,
            rejected: [{ code: "unauthorized", reason: key }],
          },
          { status: mode === "unavailable" ? 503 : 200 },
        );
      },
    );
    assert.equal(response.status, 503);
    assert.ok(!(await response.text()).includes(key));
  }
});

test("browser preference defaults on, persists off, and reaches native request diagnostics", () => {
  assert.equal(preference({ getItem: () => null }), true);
  assert.equal(preference({ getItem: () => "off" }), false);
  const headers = apiHeaders(
    request(batch, { "x-iam-telemetry": "off" }),
    null,
  );
  assert.equal(headers.get("x-iam-telemetry"), "off");
  assert.equal(headers.get("cookie"), null);
});
