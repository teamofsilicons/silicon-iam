import test from "node:test";
import assert from "node:assert/strict";
import { bodyLimit } from "../server/gateway";

test("only verified image upload routes may exceed the JSON body limit", () => {
  assert.equal(bodyLimit("/api/v1/me/photo", "PUT"), 532480);
  const json = bodyLimit("/api/v1/organizations/acme", "PATCH");
  assert.equal(json, 262144);
  assert.ok(bodyLimit("/api/v1/organizations/acme/logo", "PUT") >= 512 * 1024);
  assert.equal(bodyLimit("/api/v1/organizations/acme/logo", "POST"), json);
  assert.equal(bodyLimit("/api/v1/organizations/a/b/logo", "PUT"), json);
  assert.equal(bodyLimit("/api/v1/me", "PUT"), json);
});
