import assert from "node:assert/strict";
import test from "node:test";
import {
  finish,
  fromTokens,
  readAccounts,
  readSession,
  settings,
  type Session,
} from "../server/session.ts";
import { gateway } from "../server/gateway.ts";
const env = {
  API_UPSTREAM: "https://api.example.test",
  CONSOLE_ORIGIN: "https://iam.example.test",
  AUTH_ORIGIN: "https://iam.example.test",
  SESSION_COOKIE_KEY: "A".repeat(43),
};
const config = settings(env);
const session = (id: string, silicon = false): Session => ({
  sessionId: id,
  actorType: silicon ? "silicon" : "carbon",
  access: `${silicon ? "sat" : "cat"}_${id}`,
  refresh: `rft_${id}`,
  browserCookie: silicon ? "" : `iam_session=${id}`,
  expires: Date.now() + 3600000,
  deadline: Date.now() + 86400000,
});
async function cookies() {
  const first = await finish(new Response(), config, session("first"));
  const second = await finish(new Response(), config, session("second", true));
  const saved = first.headers
    .getSetCookie()
    .filter((cookie) => cookie.startsWith(config.cookieName + "_account_"));
  return [...saved, ...second.headers.getSetCookie()]
    .map((cookie) => cookie.split(";")[0])
    .join("; ");
}
const req = (cookie: string, path: string, account?: string, body?: unknown) =>
  new Request(env.AUTH_ORIGIN + path, {
    method: body ? "POST" : "GET",
    headers: {
      cookie,
      origin: env.AUTH_ORIGIN,
      "x-iam-frontend": "1",
      ...(account ? { "x-iam-account": account } : {}),
      ...(body
        ? {
            "content-type": "application/json",
            "idempotency-key": "same-action",
          }
        : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
test("saved accounts remain encrypted and selected account resolves only matching session", async () => {
  const cookie = await cookies();
  assert.ok(!cookie.includes("cat_first") && !cookie.includes("rft_first"));
  const request = req(cookie, "/api/session");
  assert.equal((await readAccounts(request, config)).length, 2);
  assert.equal(
    (await readSession(request, { ...config, selectedAccount: "first" }))
      ?.access,
    "cat_first",
  );
  assert.equal(
    await readSession(request, { ...config, selectedAccount: "unknown" }),
    null,
  );
  assert.equal(
    (await readSession(request, { ...config }))?.access,
    "sat_second",
  );
});
test("Silicon tokens are accepted without a Carbon browser session", () => {
  const value = fromTokens(
    {
      actor: { type: "silicon" },
      access_token: "sat_machine",
      refresh_token: "rft_machine",
      expires_in: 1800,
      refresh_expires_at: new Date(Date.now() + 86400000).toISOString(),
      session_id: "machine",
    },
    new Response(),
  );
  assert.equal(value.actorType, "silicon");
  assert.equal(value.browserCookie, "");
});
test("adding an account makes the new account active while preserving the previous account", async () => {
  const original = globalThis.fetch;
  const previous = await finish(new Response(), config, session("previous"));
  const cookie = previous.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .join("; ");
  globalThis.fetch = async () =>
    Response.json({
      actor: { type: "silicon", public_id: "si:added" },
      access_token: "sat_added",
      refresh_token: "rft_added",
      expires_in: 1800,
      refresh_expires_at: new Date(Date.now() + 86400000).toISOString(),
      session_id: "added",
    });
  try {
    const response = await gateway(
      req(cookie, "/api/v1/silicon-auth/token", undefined, {
        silicon_id: "si:added",
        silicon_token: "Synthetic!Password",
      }),
      env,
    );
    assert.equal(response.status, 200);
    const resultCookies = response.headers.getSetCookie();
    assert.equal(
      resultCookies.filter((value) => value.startsWith(config.cookieName + "="))
        .length,
      1,
    );
    const next = req(
      resultCookies.map((value) => value.split(";")[0]).join("; "),
      "/api/session",
    );
    assert.equal((await readSession(next, { ...config }))?.access, "sat_added");
    assert.deepEqual(
      (await readAccounts(next, { ...config }))
        .map((value) => value.sessionId)
        .sort(),
      ["added", "previous"],
    );
  } finally {
    globalThis.fetch = original;
  }
});
test("Silicon action confirmation requires a saved session and forwards its selected account", async () => {
  const original = globalThis.fetch;
  const cookie = await cookies();
  let calls = 0;
  globalThis.fetch = async (_url, init) => {
    calls++;
    assert.equal(
      new Headers(init?.headers).get("authorization"),
      "Bearer sat_second",
    );
    const body = JSON.parse(new TextDecoder().decode(init?.body as Uint8Array));
    assert.equal(body.silicon_token, "Synthetic!Password");
    return Response.json({ step_up_token: "sup_synthetic", expires_in: 300 });
  };
  const path = "/api/v1/silicon-auth/step-up";
  const body = {
    silicon_token: "Synthetic!Password",
    action: "organization.authorization_change",
    resource_id: "11111111-1111-4111-8111-111111111111",
  };
  try {
    assert.equal(
      (await gateway(req("", path, undefined, body), env)).status,
      401,
    );
    assert.equal(calls, 0);
    assert.equal(
      (await gateway(req(cookie, path, "second", body), env)).status,
      200,
    );
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = original;
  }
});
test("OBO gateway injects verified configured-account credentials and rejects client bearer injection", async () => {
  const original = globalThis.fetch;
  const cookie = await cookies();
  let forwarded: any;
  globalThis.fetch = async (_url, init) => {
    forwarded = JSON.parse(new TextDecoder().decode(init?.body as Uint8Array));
    return Response.json({ status: "approved" });
  };
  const path =
    "/api/v1/obo-access/consents/11111111-1111-4111-8111-111111111111/decision";
  try {
    const response = await gateway(
      req(cookie, path, "second", {
        decision: "approve",
        version: 1,
        contexts: [
          { app_id: "briefcase", account_id: "first", org_id: "work" },
        ],
      }),
      env,
    );
    assert.equal(response.status, 200);
    assert.deepEqual(forwarded.contexts, [
      { app_id: "briefcase", org_id: "work", account_token: "cat_first" },
    ]);
    for (const context of [
      {
        app_id: "briefcase",
        account_id: "first",
        org_id: "work",
        account_token: "cat_stolen",
      },
      { app_id: "briefcase", account_id: "not-configured", org_id: "work" },
    ]) {
      forwarded = undefined;
      assert.notEqual(
        (
          await gateway(
            req(cookie, path, "second", {
              decision: "approve",
              version: 1,
              contexts: [context],
            }),
            env,
          )
        ).status,
        200,
      );
      assert.equal(forwarded, undefined);
    }
  } finally {
    globalThis.fetch = original;
  }
});
test("signing out a selected account preserves the other account", async () => {
  const response = await finish(
    new Response(),
    { ...config, selectedAccount: "first", activeSessionId: "second" },
    null,
  );
  const removed = response.headers.getSetCookie();
  assert.equal(removed.length, 1);
  assert.ok(removed[0].startsWith(config.cookieName + "_account_first="));
});
test("Silicon signup polling forwards a secret only to the fixed status endpoint", async () => {
  const original = globalThis.fetch;
  const requestId = "11111111-1111-4111-8111-111111111111";
  const pollToken = "poll_" + "a".repeat(48);
  let calls = 0;
  globalThis.fetch = async (url, init) => {
    calls++;
    assert.equal(
      String(url),
      `${env.API_UPSTREAM}/api/v1/silicon-signup/requests/${requestId}`,
    );
    assert.equal(
      new Headers(init?.headers).get("authorization"),
      `Bearer ${pollToken}`,
    );
    return Response.json({ status: "pending" });
  };
  try {
    const response = await gateway(
      req("", "/api/silicon-signup/status", undefined, {
        request_id: requestId,
        poll_token: pollToken,
      }),
      env,
    );
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: "pending" });
    const malformed = await gateway(
      req("", "/api/silicon-signup/status", undefined, {
        request_id: "../../me",
        poll_token: pollToken,
      }),
      env,
    );
    assert.equal(malformed.status, 400);
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = original;
  }
});
test("custodian continuation preserves only the validated request identifier", async () => {
  const requestId = "11111111-1111-4111-8111-111111111111";
  const response = await gateway(
    new Request(
      `${env.AUTH_ORIGIN}/auth/continue?next=silicon-custody&request=${requestId}`,
      { headers: { cookie: await cookies() } },
    ),
    env,
  );
  assert.equal(response.status, 303);
  assert.equal(
    response.headers.get("location"),
    `${env.CONSOLE_ORIGIN}/silicon-custody?request=${requestId}`,
  );
});
