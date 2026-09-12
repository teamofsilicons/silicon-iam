import assert from "node:assert/strict";
import test from "node:test";
import {
  loginApplications,
  loginCallback,
  tokenDestination,
} from "../src/login-flow.ts";
import { selectedScope, scopeNames, validateConsent } from "../src/scope-model.ts";
import { gateway } from "../server/gateway.ts";

test("single and 100-app URLs are unambiguous and bounded", () => {
  assert.deepEqual(
    loginApplications(new URLSearchParams({ app_id: "tos>briefcase" })),
    { ids: ["tos>briefcase"], batch: false },
  );
  const ids = Array.from({ length: 100 }, (_, i) => `tos>app-${i}`);
  assert.deepEqual(
    loginApplications(new URLSearchParams({ app_ids: ids.join(",") })),
    { ids, batch: true },
  );
  for (const query of [
    "app_ids=",
    "app_ids=tos>a,tos>a",
    "app_ids=tos>a,",
    "app_id=tos>a&app_ids=tos>b",
    "app_ids=tos>a&app_ids=tos>b",
    "app_ids=tos>a&org_ids=tos",
    `app_ids=${[...ids, "tos>extra"].join(",")}`,
  ])
    assert.throws(() => loginApplications(new URLSearchParams(query)), query);
});
test("callbacks preserve state and carry batch credentials only in the fragment", () => {
  const url = loginCallback(
    "https://frontend.example/callback?state=opaque&slt=old",
  )!;
  const items = [
    { app_id: "tos>a", slt: "token-a", expires_in: 120 },
    { app_id: "other>b", slt: "token-b", expires_in: 120 },
  ];
  const result = new URL(tokenDestination(url, items, true));
  assert.equal(result.searchParams.get("state"), "opaque");
  assert.equal(result.searchParams.has("slt"), false);
  assert.equal(result.searchParams.has("slts"), false);
  assert.deepEqual(
    JSON.parse(new URLSearchParams(result.hash.slice(1)).get("slts")!),
    items,
  );
  assert.equal(
    new URL(tokenDestination(url, [items[0]], false)).searchParams.get("slt"),
    "token-a",
  );
  for (const value of [
    "javascript:alert(1)",
    "https://user:secret@example.com/",
    "https://example.com/#existing",
    "http://example.com/",
  ])
    assert.throws(() => loginCallback(value));
});
test("signed-out continuation preserves the entire batch and callback", async () => {
  const env = {
    API_UPSTREAM: "http://127.0.0.1:58080",
    CONSOLE_ORIGIN: "http://127.0.0.1:4310",
    AUTH_ORIGIN: "http://127.0.0.1:4311",
    SESSION_COOKIE_KEY: "A".repeat(43),
  };
  for (const path of ["/auth/continue", "/api/v1/login"]) {
    const url = new URL(path, env.AUTH_ORIGIN);
    url.searchParams.set("app_ids", "tos>a,tos>b");
    url.searchParams.set(
      "redirect_uri",
      "https://frontend.example/callback?state=original",
    );
    const response = await gateway(new Request(url), env);
    assert.equal(response.status, 303);
    const target = new URL(response.headers.get("location")!);
    assert.equal(target.pathname, "/login");
    assert.equal(target.searchParams.get("app_ids"), "tos>a,tos>b");
    assert.equal(
      target.searchParams.get("redirect_uri"),
      "https://frontend.example/callback?state=original",
    );
  }
});
test("batch mutations still require IAM frontend CSRF protection", async () => {
  const response = await gateway(
    new Request(
      "http://127.0.0.1:4311/api/v1/app-auth/batch/short-lived-tokens",
      {
        method: "POST",
        headers: { Origin: "https://outside.example" },
        body: "{}",
      },
    ),
    {
      API_UPSTREAM: "http://127.0.0.1:58080",
      CONSOLE_ORIGIN: "http://127.0.0.1:4310",
      AUTH_ORIGIN: "http://127.0.0.1:4311",
      SESSION_COOKIE_KEY: "A".repeat(43),
    },
  );
  assert.equal(response.status, 403);
  assert.equal((await response.json()).error.code, "frontend_csrf");
});

test("continuation preserves invalid duplicates and empty selections for rejection", async () => {
  const env = {
    API_UPSTREAM: "http://127.0.0.1:58080",
    CONSOLE_ORIGIN: "http://127.0.0.1:4310",
    AUTH_ORIGIN: "http://127.0.0.1:4311",
    SESSION_COOKIE_KEY: "A".repeat(43),
  };
  for (const path of ["/auth/continue", "/api/v1/login"]) {
    const response = await gateway(
      new Request(
        `${env.AUTH_ORIGIN}${path}?app_ids=tos>a&app_ids=tos>b&org_ids=`,
      ),
      env,
    );
    const target = new URL(response.headers.get("location")!);
    assert.deepEqual(target.searchParams.getAll("app_ids"), ["tos>a", "tos>b"]);
    assert.equal(target.searchParams.get("org_ids"), "");
    assert.throws(() => loginApplications(target.searchParams));
  }
});


test("bundle URLs are exclusive and survive session continuation", async () => {
  assert.deepEqual(loginApplications(new URLSearchParams({ bundle_id: "tos>workspace" })), { ids: [], batch: true, bundleId: "tos>workspace" });
  for (const query of ["bundle_id=", "bundle_id=tos>suite&app_id=tos>app", "bundle_id=tos>suite&app_ids=tos>a", "bundle_id=tos>a&bundle_id=tos>b", "bundle_id=tos>a&org_id=tos"])
    assert.throws(() => loginApplications(new URLSearchParams(query)));
  const response = await gateway(new Request("http://127.0.0.1:4311/auth/continue?bundle_id=tos%3Eworkspace"), {
    API_UPSTREAM: "http://127.0.0.1:58080", CONSOLE_ORIGIN: "http://127.0.0.1:4310", AUTH_ORIGIN: "http://127.0.0.1:4311", SESSION_COOKIE_KEY: "A".repeat(43),
  });
  assert.equal(new URL(response.headers.get("location")!).searchParams.get("bundle_id"), "tos>workspace");
});

test("permission approval preserves exact published scopes and rejects incomplete policy", () => {
  const catalog = [
    { scope: "self.identity.read", description: "Identity", critical: false, app_id: null },
    { scope: "obo:outside>drive:files.read", description: "Read files", critical: true, app_id: "outside>drive" },
  ];
  const selected = selectedScope(catalog.map((item) => item.scope), catalog);
  assert.deepEqual(selected, { iam: ["self.identity.read"], external: [{ app_id: "outside>drive", endpoint_id: "files.read" }] });
  assert.deepEqual(scopeNames(selected), catalog.map((item) => item.scope));
  assert.throws(() => selectedScope(["self.email.read"], catalog));
  validateConsent([{ scope_version: 2, scopes: catalog }]);
  assert.throws(() => validateConsent([{ scope_version: 0, scopes: catalog }]));
  assert.throws(() => validateConsent([{ scope_version: 2, scopes: [catalog[0], catalog[0]] }]));
  assert.throws(() => validateConsent([{ scope_version: 2, scopes: undefined as any }]));
});
