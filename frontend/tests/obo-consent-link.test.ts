import assert from "node:assert/strict";
import test from "node:test";
import { gateway } from "../server/gateway.ts";
import { finish, settings } from "../server/session.ts";
import {
  authDestination,
  continueDestination,
  type Configuration,
} from "../src/api.ts";
import { oboConsentRequest } from "../src/obo-consent-link.ts";
import { validateLoginConsent } from "../src/login-flow.ts";

const id = "3c098598-d890-4b12-823f-55777f4b8986";
const env = {
  API_UPSTREAM: "http://127.0.0.1:58080",
  CONSOLE_ORIGIN: "http://127.0.0.1:4310",
  AUTH_ORIGIN: "http://127.0.0.1:4311",
  SESSION_COOKIE_KEY: "A".repeat(43),
};

test("OBO links accept one request pointer without ordinary login selectors", () => {
  assert.equal(
    oboConsentRequest(new URL(`${env.AUTH_ORIGIN}/obo/consent?request=${id}`)),
    id,
  );
  for (const query of [
    `request=${id}&request=${id}`,
    "request=https://outside.example",
    `request=${id}&app_id=drive`,
    `request=${id}&bundle_id=tos>workspace`,
  ])
    assert.equal(
      oboConsentRequest(new URL(`${env.AUTH_ORIGIN}/obo/consent?${query}`)),
      undefined,
    );
  assert.equal(
    oboConsentRequest(new URL(`${env.AUTH_ORIGIN}/login?request=${id}`)),
    undefined,
  );
});

test("OBO consent uses the auth host and survives sign-in or signup", async () => {
  const href = `${env.CONSOLE_ORIGIN}/obo/consent?request=${id}&display=popup`;
  const response = await gateway(new Request(href), env);
  assert.equal(
    response.headers.get("location"),
    `${env.AUTH_ORIGIN}/obo/consent?request=${id}&display=popup`,
  );
  const previous = Object.getOwnPropertyDescriptor(globalThis, "location");
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: new URL(href),
  });
  try {
    for (const signup of [false, true]) {
      const destination = new URL(
        authDestination(
          { authOrigin: env.AUTH_ORIGIN } as Configuration,
          signup,
        ),
      );
      assert.equal(destination.pathname, signup ? "/signup" : "/login");
      assert.equal(destination.searchParams.get("request"), id);
      assert.equal(destination.searchParams.get("next"), "obo-consent");
      assert.equal(destination.searchParams.get("display"), "popup");
    }
    const next = await gateway(
      new Request(new URL(continueDestination(), env.CONSOLE_ORIGIN)),
      env,
    );
    const destination = new URL(next.headers.get("location")!);
    assert.equal(destination.origin, env.AUTH_ORIGIN);
    assert.equal(destination.searchParams.get("request"), id);
    assert.equal(destination.searchParams.get("next"), "obo-consent");
    assert.equal(destination.searchParams.get("display"), "popup");
  } finally {
    if (previous) Object.defineProperty(globalThis, "location", previous);
    else Reflect.deleteProperty(globalThis, "location");
  }
});

test("signed-in OBO continuation cannot follow a supplied external URL", async () => {
  const response = await finish(new Response(), settings(env), {
    access: "cat_test-access",
    refresh: "test-refresh",
    browserCookie: "iam_session=test",
    expires: Date.now() + 300000,
    deadline: Date.now() + 600000,
    sessionId: "test",
  });
  const cookie = response.headers.get("set-cookie")!.split(";")[0];
  for (const [query, destination, status] of [
    [
      `next=obo-consent&request=${id}`,
      `${env.AUTH_ORIGIN}/obo/consent?request=${id}`,
      303,
    ],
    [
      `next=obo-consent&request=${id}&display=popup&redirect_uri=https://outside.example`,
      `${env.AUTH_ORIGIN}/obo/consent?request=${id}&display=popup`,
      303,
    ],
    ["next=obo-consent&request=https://outside.example", null, 400],
    [`next=obo-consent&request=${id}&request=${id}`, null, 400],
    ["next=obo-grants", `${env.CONSOLE_ORIGIN}/obo-grants`, 303],
    ["next=https://outside.example", `${env.CONSOLE_ORIGIN}/`, 303],
  ] as const) {
    const result = await gateway(
      new Request(`${env.AUTH_ORIGIN}/auth/continue?${query}`, {
        headers: { cookie },
      }),
      env,
    );
    assert.equal(result.status, status);
    assert.equal(result.headers.get("location"), destination);
  }
});

test("ordinary login cannot approve an external OBO permission from a stale policy", () => {
  const iam = {
    scope: "self.profile.read",
    app_id: null,
    description: "Profile",
    critical: false,
  };
  const obo = {
    scope: "obo:drive:files.read",
    app_id: "drive",
    description: "Read files",
    critical: true,
  };
  validateLoginConsent([{ scope_version: 1, scopes: [iam] }]);
  validateLoginConsent([{ scope_version: 1, scopes: [] }]);
  assert.throws(
    () => validateLoginConsent([{ scope_version: 1, scopes: [iam, obo] }]),
    /separate approval/,
  );
  assert.throws(
    () =>
      validateLoginConsent([
        { scope_version: 1, scopes: [{ ...obo, app_id: null }] },
      ]),
    /separate approval/,
  );
});
