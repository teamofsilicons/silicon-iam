import assert from "node:assert/strict";
import test from "node:test";
import {
  bundleAccessAllowed,
  bundleFormPayload,
  bundleLogoUrl,
  displayLogoUrl,
} from "../src/bundle-model.ts";
import { gateway } from "../server/gateway.ts";

test("bundle controls require a successful exact-organization availability result", () => {
  const eligible = { orgId: "eligible", available: true };
  assert.equal(
    bundleAccessAllowed("eligible", eligible, false, undefined),
    true,
  );
  for (const result of [
    undefined,
    { orgId: "eligible", available: false },
    { orgId: "other", available: true },
  ])
    assert.equal(
      bundleAccessAllowed("eligible", result, false, undefined),
      false,
    );
  assert.equal(
    bundleAccessAllowed("eligible", eligible, true, undefined),
    false,
  );
  assert.equal(
    bundleAccessAllowed("eligible", eligible, false, new Error("Unavailable")),
    false,
  );
  assert.equal(bundleAccessAllowed("", eligible, false, undefined), false);
  assert.equal(
    bundleAccessAllowed(
      "eligible",
      { ...eligible, available: "true" as any },
      false,
      undefined,
    ),
    false,
  );
});

test("switching organizations immediately rejects stale available results and failures stay closed", () => {
  const previous = { orgId: "first", available: true };
  assert.equal(bundleAccessAllowed("first", previous, false, undefined), true);
  assert.equal(
    bundleAccessAllowed("second", previous, false, undefined),
    false,
  );
  assert.equal(bundleAccessAllowed("second", previous, true, undefined), false);
  assert.equal(
    bundleAccessAllowed(
      "second",
      previous,
      false,
      new Error("Network failure"),
    ),
    false,
  );
  assert.equal(
    bundleAccessAllowed(
      "second",
      { orgId: "second", available: true },
      false,
      undefined,
    ),
    true,
  );
});

test("bundle logo URLs accept HTTPS image paths and queries and reject unsafe schemes and credentials", () => {
  const url =
    "https://cdn.example.com/logos/workspace.svg?size=96&theme=light#icon";
  assert.equal(bundleLogoUrl(` ${url} `), url);
  assert.equal(displayLogoUrl(url), url);
  assert.equal(bundleLogoUrl("  "), null);
  assert.equal(displayLogoUrl(null), undefined);
  for (const invalid of [
    "http://example.com/logo.png",
    "javascript:alert(1)",
    "data:image/svg+xml,test",
    "//example.com/logo.png",
    "https://user:secret@example.com/logo.png",
    "not a URL",
    `https://example.com/${"x".repeat(2048)}`,
    `https://example.com/${"é".repeat(1024)}`,
  ]) {
    assert.throws(() => bundleLogoUrl(invalid));
    assert.equal(displayLogoUrl(invalid), undefined);
  }
});

test("new bundle payload includes its logo and unique selected member applications", () => {
  assert.deepEqual(
    bundleFormPayload({
      name: " Workspace ",
      logo: "https://example.com/logo.png",
      appIds: ["a", "a", "b"],
    }),
    {
      app_name: "Workspace",
      app_logo: "https://example.com/logo.png",
      app_ids: ["a", "b"],
    },
  );
  assert.throws(() =>
    bundleFormPayload({ name: "Workspace", logo: "", appIds: [] }),
  );
});

test("bundle edit preserves untouched logo and members, updates URLs and clears with explicit null", () => {
  const original = {
    app_name: "Workspace",
    app_logo: "https://example.com/old.png",
    app_ids: ["a", "b"],
  };
  const draft = {
    name: "Workspace",
    logo: original.app_logo,
    appIds: [...original.app_ids],
  };
  assert.deepEqual(bundleFormPayload(draft, original), {});
  assert.deepEqual(
    bundleFormPayload({ ...draft, name: "New name" }, original),
    { app_name: "New name" },
  );
  assert.deepEqual(
    bundleFormPayload(
      { ...draft, logo: "https://example.com/new.png?size=48" },
      original,
    ),
    { app_logo: "https://example.com/new.png?size=48" },
  );
  assert.deepEqual(bundleFormPayload({ ...draft, logo: "" }, original), {
    app_logo: null,
  });
  assert.deepEqual(
    bundleFormPayload({ ...draft, appIds: ["b"] }, original),
    { app_ids: ["b"] },
  );
  assert.deepEqual(original, {
    app_name: "Workspace",
    app_logo: "https://example.com/old.png",
    app_ids: ["a", "b"],
  });
});

test("logo previews allow HTTPS images while scripts and API connections stay same-origin", async () => {
  const response = await gateway(new Request("http://127.0.0.1:4310/"), {
    API_UPSTREAM: "http://127.0.0.1:58080",
    CONSOLE_ORIGIN: "http://127.0.0.1:4310",
    AUTH_ORIGIN: "http://127.0.0.1:4311",
    SESSION_COOKIE_KEY: "A".repeat(43),
    ASSETS: {
      fetch: async () =>
        new Response("<!doctype html>", {
          headers: { "Content-Type": "text/html" },
        }),
    },
  });
  assert.equal(response.status, 200);
  const csp = response.headers.get("Content-Security-Policy")!;
  assert.match(csp, /img-src 'self' https:;/);
  assert.match(csp, /script-src 'self';/);
  assert.match(csp, /connect-src 'self';/);
  assert.equal(response.headers.get("Referrer-Policy"), "no-referrer");
});
