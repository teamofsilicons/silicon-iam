import assert from "node:assert/strict";
import test from "node:test";
import { gateway } from "../server/gateway.ts";
import { finish, settings } from "../server/session.ts";

const id = "3c098598-d890-4b12-823f-55777f4b8986";
const env = {
  API_UPSTREAM: "https://backend.example.test",
  CONSOLE_ORIGIN: "https://iam.example.test",
  AUTH_ORIGIN: "https://auth.iam.example.test",
  COOKIE_DOMAIN: ".iam.example.test",
  SESSION_COOKIE_KEY: "A".repeat(43),
};
async function cookie() {
  const response = await finish(new Response(), settings(env), {
    access: "cat_user",
    refresh: "rft_user",
    browserCookie: "iam_session=user",
    expires: Date.now() + 3600000,
    deadline: Date.now() + 86400000,
    sessionId: "test",
  });
  return response.headers.get("set-cookie")!.split(";")[0];
}
const browserRequest = (
  path: string,
  method: string,
  cookie: string,
  overrides: Record<string, string> = {},
) =>
  new Request(env.AUTH_ORIGIN + path, {
    method,
    headers: {
      cookie,
      origin: env.AUTH_ORIGIN,
      "x-iam-frontend": "1",
      "idempotency-key": "same-request",
      "content-type": "application/json",
      ...overrides,
    },
    ...(method === "POST"
      ? { body: JSON.stringify({ decision: "approve", version: 2 }) }
      : {}),
  });

test("browser exposes only direct-user OBO consent and grant methods", async () => {
  const original = globalThis.fetch;
  const session = await cookie();
  const forwarded: {
    url: string;
    method: string;
    authorization: string | null;
  }[] = [];
  globalThis.fetch = async (url, init) => {
    forwarded.push({
      url: String(url),
      method: init?.method || "GET",
      authorization: new Headers(init?.headers).get("authorization"),
    });
    return Response.json({ items: [] });
  };
  try {
    for (const [path, method] of [
      [`/api/v1/obo-access/consents/${id}`, "GET"],
      [`/api/v1/obo-access/consents/${id}/decision`, "POST"],
      ["/api/v1/obo-access/grants", "GET"],
      ["/api/v1/obo-access/grants?limit=10&cursor=next%2Fpage", "GET"],
      [`/api/v1/obo-access/grants/${id}/revoke`, "POST"],
    ])
      assert.equal(
        (await gateway(browserRequest(path, method, session), env)).status,
        200,
      );
    assert.equal(forwarded.length, 5);
    assert.equal(
      forwarded[3].url,
      `${env.API_UPSTREAM}/api/v1/obo-access/grants?limit=10&cursor=next%2Fpage`,
    );
    assert.ok(
      forwarded.every((item) => item.authorization === "Bearer cat_user"),
    );
    for (const [path, method] of [
      ["/api/v1/obo-access/authorizations", "POST"],
      [`/api/v1/obo-access/authorizations/${id}`, "GET"],
      ["/api/v1/obo-access/tokens", "POST"],
      ["/api/v1/obo-access/delegations", "POST"],
      ["/api/v1/obo-access/token-verifications", "POST"],
      ["/api/v1/obo-access/exchanges", "POST"],
      [`/api/v1/obo-access/consents/${id}/decision`, "GET"],
      [`/api/v1/obo-access/consents/${id}`, "DELETE"],
      [`/api/v1/obo-access/grants/${id}/revoke`, "GET"],
    ])
      assert.equal(
        (await gateway(browserRequest(path, method, session), env)).status,
        404,
        `${method} ${path}`,
      );
    assert.equal(forwarded.length, 5);
  } finally {
    globalThis.fetch = original;
  }
});

test("OBO decisions require frontend CSRF protection, a user session, and a mutation key", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("must not forward");
  };
  try {
    const session = await cookie();
    const path = `/api/v1/obo-access/consents/${id}/decision`;
    assert.equal(
      (await gateway(browserRequest(path, "POST", ""), env)).status,
      401,
    );
    assert.equal(
      (
        await gateway(
          browserRequest(path, "POST", session, {
            origin: "https://outside.example",
          }),
          env,
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await gateway(
          browserRequest(path, "POST", session, {
            "sec-fetch-site": "cross-site",
          }),
          env,
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await gateway(
          browserRequest(path, "POST", session, { "x-iam-frontend": "" }),
          env,
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await gateway(
          browserRequest(path, "POST", session, { "idempotency-key": "" }),
          env,
        )
      ).status,
      400,
    );
  } finally {
    globalThis.fetch = original;
  }
});
