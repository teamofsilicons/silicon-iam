import assert from "node:assert/strict";
import test from "node:test";
import { gateway } from "../server/gateway.ts";
import { readSession, settings } from "../server/session.ts";
const env = {
  API_UPSTREAM: "https://backend.example.test",
  CONSOLE_ORIGIN: "https://iam.example.test",
  AUTH_ORIGIN: "https://iam.example.test",
  SESSION_COOKIE_KEY: "A".repeat(43),
};
const request = (path: string, cookie = "", origin = env.AUTH_ORIGIN) =>
  new Request(env.AUTH_ORIGIN + path, {
    method: "POST",
    headers: {
      cookie,
      origin,
      "x-iam-frontend": "1",
      "idempotency-key": "social-proof-completion",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      request_id: "78a549b3-15f1-4fbc-a12c-0f99dc2fcbde",
      poll_token: "synthetic-provider-proof",
    }),
  });
test("provider completion stores credentials in the encrypted wallet, never browser JSON", async () => {
  const original = globalThis.fetch;
  let forwarded = 0;
  globalThis.fetch = async (url, init) => {
    forwarded++;
    assert.equal(
      String(url),
      env.API_UPSTREAM + "/api/v1/login/social/google/complete",
    );
    assert.equal(
      new Headers(init?.headers).get("idempotency-key"),
      "social-proof-completion",
    );
    return Response.json(
      {
        actor: { type: "carbon", public_id: "c:provider" },
        access_token: "cat_provider",
        refresh_token: "rft_provider",
        session_id: "provider-session",
        expires_in: 1800,
        refresh_expires_at: new Date(Date.now() + 86400000).toISOString(),
      },
      {
        headers: {
          "set-cookie": "iam_session=provider; HttpOnly; Secure; Path=/",
        },
      },
    );
  };
  try {
    const response = await gateway(
      request("/api/v1/login/social/google/complete"),
      env,
    );
    assert.equal(response.status, 200);
    const value = await response.json();
    assert.equal(value.authenticated, true);
    assert.equal(value.access_token, undefined);
    assert.equal(value.refresh_token, undefined);
    assert.equal(forwarded, 1);
    const cookies = response.headers
      .getSetCookie()
      .map((value) => value.split(";")[0])
      .join("; ");
    const saved = await readSession(
      new Request(env.AUTH_ORIGIN, { headers: { cookie: cookies } }),
      settings(env),
    );
    assert.equal(saved?.actorType, "carbon");
    assert.equal(saved?.actorId, "c:provider");
    assert.equal(saved?.access, "cat_provider");
    assert.equal(saved?.refresh, "rft_provider");
  } finally {
    globalThis.fetch = original;
  }
});
test("provider linking needs a direct session and all provider mutations need same-origin CSRF protection", async () => {
  const original = globalThis.fetch;
  let forwarded = 0;
  globalThis.fetch = async () => {
    forwarded++;
    return Response.json({ linked: true });
  };
  try {
    assert.equal(
      (await gateway(request("/api/v1/login/social/google/link"), env)).status,
      401,
    );
    assert.equal(
      (
        await gateway(
          request(
            "/api/v1/login/social/google/complete",
            "",
            "https://evil.example",
          ),
          env,
        )
      ).status,
      403,
    );
    assert.equal(forwarded, 0);
  } finally {
    globalThis.fetch = original;
  }
});
