import assert from "node:assert/strict";
import test from "node:test";
import { gateway } from "../server/gateway.ts";
import { finish, settings } from "../server/session.ts";
import {
  authDestination,
  continueDestination,
  type Configuration,
} from "../src/api.ts";

const id = "3c098598-d890-4b12-823f-55777f4b8986";
const env = {
  API_UPSTREAM: "http://127.0.0.1:58080",
  CONSOLE_ORIGIN: "http://127.0.0.1:4310",
  AUTH_ORIGIN: "http://127.0.0.1:4311",
  SESSION_COOKIE_KEY: "A".repeat(43),
};
test("scope notice links open the exact thread on the console host", async () => {
  for (const origin of [env.AUTH_ORIGIN, env.CONSOLE_ORIGIN]) {
    const response = await gateway(
      new Request(`${origin}/applications?scope_request=${id}`),
      env,
    );
    assert.equal(response.status, 303);
    assert.equal(
      response.headers.get("location"),
      `${env.CONSOLE_ORIGIN}/scope-reviews?request=${id}`,
    );
  }
});

test("scope review survives signed-out continuation, login and signup", async () => {
  const href = `${env.CONSOLE_ORIGIN}/scope-reviews?request=${id}&next=scope-reviews`;
  const previous = Object.getOwnPropertyDescriptor(globalThis, "location");
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: new URL(href),
  });
  try {
    const config = { authOrigin: env.AUTH_ORIGIN } as Configuration;
    for (const signup of [false, true]) {
      const destination = new URL(authDestination(config, signup));
      assert.equal(destination.pathname, signup ? "/signup" : "/login");
      assert.equal(destination.searchParams.get("request"), id);
      assert.equal(destination.searchParams.get("next"), "scope-reviews");
    }
    const response = await gateway(
      new Request(new URL(continueDestination(), env.CONSOLE_ORIGIN)),
      env,
    );
    const destination = new URL(response.headers.get("location")!);
    assert.equal(destination.origin, env.AUTH_ORIGIN);
    assert.equal(destination.searchParams.get("request"), id);
    assert.equal(destination.searchParams.get("next"), "scope-reviews");
  } finally {
    if (previous) Object.defineProperty(globalThis, "location", previous);
    else Reflect.deleteProperty(globalThis, "location");
  }
});

test("signed-in continuation uses only the configured console and a valid request id", async () => {
  const response = await finish(new Response(), settings(env), {
    access: "cat_test-access",
    refresh: "test-refresh",
    browserCookie: "iam_session=test",
    expires: Date.now() + 300000,
    deadline: Date.now() + 600000,
    sessionId: "test",
  });
  const cookie = response.headers.get("set-cookie")!.split(";")[0];
  for (const [query, expected] of [
    [`next=scope-reviews&request=${id}`, `/scope-reviews?request=${id}`],
    ["next=scope-reviews&request=https://outside.example", "/"],
    [`next=https://outside.example&request=${id}`, "/"],
    [`next=scope-reviews&request=${id}&request=${id}`, "/"],
  ]) {
    const result = await gateway(
      new Request(`${env.AUTH_ORIGIN}/auth/continue?${query}`, {
        headers: { cookie },
      }),
      env,
    );
    assert.equal(result.headers.get("location"), env.CONSOLE_ORIGIN + expected);
  }
});
