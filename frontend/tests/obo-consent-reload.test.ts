import assert from "node:assert/strict";
import test from "node:test";
import { ApiError, mutation, request } from "../src/api";
import { consentDetail, decisionResult } from "../src/obo-consent-model";

const id = "3c098598-d890-4b12-823f-55777f4b8986";
const path = `/api/v1/obo-access/consents/${id}`;
const endpoint = (audience: string) => ({
  audience,
  app_name: audience,
  endpoint_id: `${audience}.read`,
  description: `Read from ${audience}`,
  critical: false,
  downstream: [],
});
const original = {
  id,
  app_id: "caller",
  app_name: "Caller",
  actor: { type: "carbon", public_id: "c:person" },
  org_id: "work",
  status: "pending",
  version: 1,
  expires_at: "2099-01-01T00:00:00Z",
  endpoints: [endpoint("speech")],
};

test("a stale consent decision surfaces 412 without retrying and reload preserves the changed graph for a fresh approval", async () => {
  const calls: {
    method: string;
    path: string;
    body?: any;
    key: string | null;
  }[] = [];
  const changed = {
    ...original,
    version: 2,
    endpoints: [
      {
        ...endpoint("speech"),
        downstream: [endpoint("files"), endpoint("audit")],
      },
    ],
  };
  const approved = {
    request_id: id,
    status: "approved",
    authorization_code: "oac_fixture_only",
    expires_at: original.expires_at,
  };
  const transport = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const call = {
      method: init?.method || "GET",
      path: String(url),
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
      key: new Headers(init?.headers).get("Idempotency-Key"),
    };
    calls.push(call);
    if (call.method === "GET") {
      assert.equal(call.path, path);
      return Response.json(changed);
    }
    assert.equal(call.path, `${path}/decision`);
    if (call.body.version === 1)
      return Response.json(
        {
          error: {
            code: "obo_consent_changed",
            message: "Review the changed permissions",
          },
        },
        { status: 412 },
      );
    assert.deepEqual(call.body, { decision: "approve", version: 2 });
    return Response.json(approved);
  };
  try {
    const send = mutation();
    const displayed = consentDetail(original, id);
    await assert.rejects(
      send("POST", `${path}/decision`, {
        decision: "approve",
        version: displayed.version,
      }),
      (error: unknown) => error instanceof ApiError && error.status === 412,
    );
    // A rejected decision must not retry, reload, or approve a changed graph implicitly.
    assert.equal(calls.length, 1);
    const reloaded = consentDetail(await request(path), id);
    assert.equal(reloaded.version, 2);
    assert.deepEqual(
      reloaded.endpoints[0].downstream.map((node) => node.audience),
      ["files", "audit"],
    );
    assert.equal(calls.length, 2);
    const result = decisionResult(
      await send("POST", `${path}/decision`, {
        decision: "approve",
        version: reloaded.version,
      }),
      id,
      "approve",
    );
    assert.equal(result.authorization_code, approved.authorization_code);
    assert.deepEqual(
      calls.map((call) => call.method),
      ["POST", "GET", "POST"],
    );
    assert.ok(calls[0].key);
    assert.ok(calls[2].key);
    assert.notEqual(calls[0].key, calls[2].key);
  } finally {
    globalThis.fetch = transport;
  }
});
