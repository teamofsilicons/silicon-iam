import assert from "node:assert/strict";
import test from "node:test";
import {
  socialAttempt,
  socialContinuation,
  type SocialProof,
} from "../src/social-flow.ts";

const proof = { request_id: "request", poll_token: "private-proof" };
test("existing verified email completes directly for Google and Apple without any OTP or link route", async () => {
  for (const provider of ["google", "apple"] as const) {
    const calls: { path: string; proof: SocialProof }[] = [];
    const attempt = socialAttempt(provider, proof, async (path, body) => {
      calls.push({ path, proof: body });
      return path.endsWith("/status")
        ? { status: "login_ready", email: "existing@example.test" }
        : { authenticated: true };
    });
    assert.deepEqual(await attempt(), { status: "signed_in" });
    assert.deepEqual(
      calls.map(({ path }) => path),
      [
        `/api/v1/login/social/${provider}/status`,
        `/api/v1/login/social/${provider}/complete`,
      ],
    );
    assert.ok(calls.every(({ proof: value }) => value === proof));
  }
});
test("new provider email remains an explicit verified signup without requesting an email code", async () => {
  const value = {
    status: "verified",
    email: "new@example.test",
    signup_session_id: "signup",
    display_name: "New",
  };
  const paths: string[] = [];
  const attempt = socialAttempt("apple", proof, async (path) => {
    paths.push(path);
    return value;
  });
  assert.deepEqual(await attempt(), value);
  assert.deepEqual(paths, ["/api/v1/login/social/apple/status"]);
  for (const invalid of [
    { status: "verified" },
    { status: "verified", email: "new@example.test" },
    { status: "verified", signup_session_id: "signup" },
  ] as const)
    assert.throws(() => socialContinuation(invalid));
});
test("lost completion response retries the exact proof and completion without repolling or asking for OTP", async () => {
  const paths: string[] = [];
  const bodies: SocialProof[] = [];
  let first = true;
  const attempt = socialAttempt("google", proof, async (path, body) => {
    paths.push(path);
    bodies.push(body);
    if (path.endsWith("/status")) return { status: "login_ready" };
    if (first) {
      first = false;
      throw new Error("interrupted response");
    }
    return { authenticated: true };
  });
  await assert.rejects(attempt(), /interrupted/);
  assert.deepEqual(await attempt(), { status: "signed_in" });
  assert.deepEqual(paths, [
    "/api/v1/login/social/google/status",
    "/api/v1/login/social/google/complete",
    "/api/v1/login/social/google/complete",
  ]);
  assert.ok(bodies.every((body) => body === proof));
});
test("pending stays pending and retired or invalid statuses never request completion", async () => {
  assert.equal(socialContinuation({ status: "pending" }), "wait");
  for (const status of [
    "link_required",
    "already_registered",
    "failed",
    "expired",
  ] as const) {
    let calls = 0;
    const attempt = socialAttempt("google", proof, async () => {
      calls++;
      return { status, email: "known@example.test" };
    });
    await assert.rejects(attempt());
    assert.equal(calls, 1);
  }
});
