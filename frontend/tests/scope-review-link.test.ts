import assert from "node:assert/strict";
import test from "node:test";
import { gateway } from "../server/gateway.ts";
import { scopeReviewRequest } from "../src/scope-review-link.ts";

const id = "3c098598-d890-4b12-823f-55777f4b8986";
const env = {
  API_UPSTREAM: "http://127.0.0.1:58080",
  CONSOLE_ORIGIN: "http://127.0.0.1:4310",
  AUTH_ORIGIN: "http://127.0.0.1:4311",
  SESSION_COOKIE_KEY: "A".repeat(43),
};
test("old approval links go straight to Honeycomb with their exact request ID", async () => {
  for (const origin of [env.AUTH_ORIGIN, env.CONSOLE_ORIGIN]) {
    for (const path of [
      `/applications?scope_request=${id}`,
      `/scope-reviews?request=${id}`,
      `/auth/continue?next=scope-reviews&request=${id}`,
    ]) {
      const response = await gateway(new Request(origin + path), env);
      assert.equal(response.status, 303);
      assert.equal(
        response.headers.get("location"),
        `https://console.honeycomb.teamofsilicons.com/requests?legacy_request=${id}`,
      );
    }
  }
});
test("legacy redirect does not forward credentials or caller-selected destinations", async () => {
  const response = await gateway(
    new Request(
      `${env.AUTH_ORIGIN}/applications?scope_request=${id}&access_token=private&redirect_uri=https://outside.example`,
      {
        headers: {
          cookie: "iam_session=private",
          authorization: "Bearer private",
        },
      },
    ),
    env,
  );
  assert.equal(response.status, 303);
  assert.equal(
    response.headers.get("location"),
    `https://console.honeycomb.teamofsilicons.com/requests?legacy_request=${id}`,
  );
});
test("invalid and ambiguous legacy request IDs cannot become a redirect target", () => {
  for (const query of [
    "request=https://outside.example",
    `request=${id}&request=${id}`,
    "request=../../admin",
    "request=",
    "scope_request=not-a-uuid",
  ]) {
    const path = query.startsWith("scope_request")
      ? "/applications"
      : "/scope-reviews";
    assert.equal(
      scopeReviewRequest(new URL(`https://iam.example${path}?${query}`)),
      undefined,
    );
  }
});
