import test from "node:test";
import assert from "node:assert/strict";
import { invitationLocation } from "../src/invitation-flow.ts";

test("email invitation preserves the organization through signup", () => {
  const result = invitationLocation("https://auth.iam.example/join/tos");
  assert.equal(result.pathname, "/join");
  assert.equal(result.searchParams.get("org_id"), "tos");
  assert.equal(result.searchParams.get("next"), "join");
});
test("other routes and malformed handles do not become invitation continuations", () => {
  for (const path of ["/signup", "/join", "/join/tos/extra", "/join/%2Fother", "/join/a"])
    assert.equal(invitationLocation(`https://auth.iam.example${path}`), undefined);
});
test("the organization in an invitation path overrides a stale query", () => {
  const result = invitationLocation("https://auth.iam.example/join/tos/?org_id=other&next=elsewhere");
  assert.equal(result.searchParams.get("org_id"), "tos");
  assert.equal(result.searchParams.get("next"), "join");
});
