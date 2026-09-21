import assert from "node:assert/strict";
import test from "node:test";
import { gateway } from "../server/gateway.ts";
import {
  finish,
  readSession,
  refreshed,
  settings,
  type Session,
} from "../server/session.ts";
const env = {
  API_UPSTREAM: "https://backend.example.test",
  CONSOLE_ORIGIN: "https://iam.example.test",
  AUTH_ORIGIN: "https://iam.example.test",
  SESSION_COOKIE_KEY: "A".repeat(43),
};
const config = settings(env);
function session(): Session {
  return {
    access: "cat_old",
    refresh: "rft_" + crypto.randomUUID(),
    expires: Date.now() + 3600000,
    deadline: Date.now() + 86400000,
    browserCookie: "iam_session=old",
    sessionId: "test",
  };
}
function tokens() {
  return {
    access_token: "cat_new",
    refresh_token: "rft_new",
    expires_in: 1800,
    refresh_expires_at: new Date(Date.now() + 86400000).toISOString(),
    actor: { type: "carbon" },
    session_id: "test",
  };
}
async function request(s: Session, path = "/api/session", method = "GET") {
  const cookie = (await finish(new Response(), config, s)).headers
    .get("set-cookie")!
    .split(";")[0];
  return new Request(env.CONSOLE_ORIGIN + path, {
    method,
    headers: {
      cookie,
      origin: env.CONSOLE_ORIGIN,
      "x-iam-frontend": "1",
      "idempotency-key": "original-mutation",
    },
    ...(method === "POST" ? { body: '{"original":true}' } : {}),
  });
}
test("stale access refreshes once and preserves mutation bytes/key", async () => {
  const original = globalThis.fetch;
  for (const [path, method] of [
    ["/api/session", "GET"],
    ["/api/v1/organizations", "POST"],
  ]) {
    let refreshes = 0,
      requests = 0;
    const bodies: unknown[] = [];
    globalThis.fetch = async (url, init) => {
      if (String(url).endsWith("/auth/tokens/refresh")) {
        refreshes++;
        return Response.json(tokens());
      }
      requests++;
      bodies.push(init?.body);
      if (method === "POST")
        assert.equal(
          new Headers(init?.headers).get("idempotency-key"),
          "original-mutation",
        );
      return new Headers(init?.headers).get("authorization") ===
        "Bearer cat_old"
        ? new Response(null, { status: 401 })
        : Response.json({ id: "actor" });
    };
    try {
      const result = await gateway(await request(session(), path, method), env);
      assert.equal(result.status, 200);
      assert.equal(refreshes, 1);
      assert.equal(requests, 2);
      assert.deepEqual(bodies[0], bodies[1]);
      assert.ok(
        result.headers.get("set-cookie") &&
          !result.headers.get("set-cookie")!.includes("Max-Age=0"),
      );
    } finally {
      globalThis.fetch = original;
    }
  }
});
test("only rejected refresh clears a cookie; outages retain it", async () => {
  const original = globalThis.fetch;
  try {
    for (const [status, expected] of [
      [503, 503],
      [401, 401],
      [409, 503],
    ]) {
      const s = session();
      s.expires = 0;
      globalThis.fetch = async () => new Response(null, { status });
      const result = await gateway(await request(s), env);
      assert.equal(result.status, expected);
      assert.equal(
        result.headers.get("set-cookie")?.includes("Max-Age=0") || false,
        status === 401,
      );
    }
  } finally {
    globalThis.fetch = original;
  }
});
test("cached replies cannot extend access lifetime and retries reuse identity", async () => {
  const original = globalThis.fetch,
    date = Date.now;
  const s = session();
  s.expires = 0;
  const keys: string[] = [];
  const started = date();
  globalThis.fetch = async (_url, init) => {
    keys.push(new Headers(init?.headers).get("idempotency-key")!);
    return Response.json(tokens());
  };
  try {
    const first = await refreshed(s, config);
    Date.now = () => started + 5 * 60000;
    const replayed = await refreshed(s, config);
    assert.equal(keys.length, 2);
    assert.equal(keys[0], keys[1]);
    assert.ok(first.expires <= started + 1200000 + 1000);
    assert.ok(replayed.expires <= started + 1800000);
    const cookie = (await finish(new Response(), config, replayed)).headers
      .get("set-cookie")!
      .split(";")[0];
    assert.equal(
      (
        await readSession(
          new Request(env.CONSOLE_ORIGIN, { headers: { cookie } }),
          config,
        )
      )?.refresh,
      "rft_new",
    );
  } finally {
    globalThis.fetch = original;
    Date.now = date;
  }
});

test("malformed successful refresh cannot overwrite a saved login", async () => {
  const original = globalThis.fetch;
  try {
    for (const invalid of [
      { access_token: "" },
      { refresh_token: "" },
      { expires_in: 0 },
      { expires_in: Number.MAX_SAFE_INTEGER },
    ]) {
      const s = session();
      s.expires = 0;
      globalThis.fetch = async () => Response.json({ ...tokens(), ...invalid });
      const response = await gateway(await request(s), env);
      assert.equal(response.status, 503);
      assert.equal(response.headers.get("set-cookie"), null);
    }
  } finally {
    globalThis.fetch = original;
  }
});
