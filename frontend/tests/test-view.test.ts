import test from "node:test";
import assert from "node:assert/strict";
import { testApplicationView } from "../server/test-view";
import { settings } from "../server/session";
import { gateway } from "../server/gateway";
const env = {
  API_UPSTREAM: "https://backend.example.test",
  CONSOLE_ORIGIN: "https://iam.example.test",
  AUTH_ORIGIN: "https://iam.example.test",
  SESSION_COOKIE_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
};
const config = settings(env);
const credentials = {
  app_id: "tos>sample",
  app_secret: "ask_test_secret_not_production",
  iam_test_key: "abcdefghijklmnopABCDEFGHIJKLMNOP",
};
const encode = (value: unknown) =>
  new TextEncoder().encode(JSON.stringify(value));

test("test-view sends only test credentials to the fixed read-only API", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    assert.equal(
      String(url),
      "https://backend.example.test/api/v1/application/testing-context",
    );
    assert.equal(init?.method, "GET");
    assert.equal(init?.redirect, "error");
    assert.equal(init?.body, undefined);
    const headers = new Headers(init?.headers);
    assert.equal(
      headers.get("authorization"),
      `Basic ${btoa(`${credentials.app_id}:${credentials.app_secret}`)}`,
    );
    assert.equal(
      headers.get("x-testing-environment-key"),
      credentials.iam_test_key,
    );
    assert.equal(headers.get("silicon-iam-supported-api-versions"), "v1");
    assert.equal(headers.get("cookie"), null);
    return Response.json(
      {
        environment_id: "test-id",
        application: { app_id: credentials.app_id },
      },
      { headers: { "Set-Cookie": "unwanted=1" } },
    );
  };
  try {
    const result = await testApplicationView(
      encode({
        ...credentials,
        url: "https://attacker.test",
        method: "DELETE",
      }),
      config,
    );
    assert.equal(result.status, 200);
    assert.equal(result.headers.get("cache-control"), "no-store");
    assert.equal(result.headers.get("set-cookie"), null);
    assert.equal((await result.json()).environment_id, "test-id");
  } finally {
    globalThis.fetch = original;
  }
});

test("rejected test credentials never trigger a production fallback or echo secrets", async () => {
  const original = globalThis.fetch;
  let requests = 0;
  globalThis.fetch = async () => {
    requests++;
    return Response.json(credentials, { status: 401 });
  };
  try {
    const result = await testApplicationView(encode(credentials), config);
    assert.equal(result.status, 422);
    const body = await result.text();
    assert.ok(!body.includes(credentials.app_secret));
    assert.ok(!body.includes(credentials.iam_test_key));
    assert.equal(requests, 1);
  } finally {
    globalThis.fetch = original;
  }
});

test("malformed input cannot inject authentication headers or a destination", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("must not make a request");
  };
  try {
    for (const input of [
      null,
      [],
      {},
      { ...credentials, app_id: "https://attacker.test" },
      { ...credentials, iam_test_key: "abc\r\nCookie: injected" },
    ])
      assert.equal(
        (await testApplicationView(encode(input), config)).status,
        400,
      );
  } finally {
    globalThis.fetch = original;
  }
});

test("browser test-view requires same-origin CSRF checks and a signed-in session", async () => {
  const make = (origin: string) =>
    new Request("https://iam.example.test/api/test-application-view", {
      method: "POST",
      headers: { Origin: origin, "X-IAM-Frontend": "1" },
      body: JSON.stringify(credentials),
    });
  assert.equal((await gateway(make("https://attacker.test"), env)).status, 403);
  assert.equal((await gateway(make(env.CONSOLE_ORIGIN), env)).status, 401);
});
