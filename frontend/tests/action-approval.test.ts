import assert from "node:assert/strict";
import test from "node:test";
import { ApiError, mutation } from "../src/api";
import { operationAllowed } from "../src/permissions";

test("an approved mutation retries the exact pending request key and body", async () => {
  const original = globalThis.fetch;
  const calls: RequestInit[] = [];
  globalThis.fetch = async (_url, init) => {
    calls.push(init || {});
    if (calls.length < 3)
      return new Response(
        JSON.stringify({
          error: {
            code: "approval_required",
            message: "Approval required",
            details: { approval_request_id: "approval-1" },
          },
        }),
        { status: 428 },
      );
    return new Response(JSON.stringify({ version: 2 }));
  };
  try {
    const send = mutation();
    const body = { job_description: "Engineer" };
    const options = { version: 1 };
    await assert.rejects(
      send(
        "PUT",
        "/api/v1/organizations/acme/members/person[acme]/job-role",
        body,
        options,
      ),
      (error: unknown) =>
        error instanceof ApiError && error.code === "approval_required",
    );
    await assert.rejects(
      send(
        "PUT",
        "/api/v1/organizations/acme/members/person[acme]/job-role",
        body,
        options,
      ),
    );
    await send(
      "PUT",
      "/api/v1/organizations/acme/members/person[acme]/job-role",
      body,
      options,
    );
    assert.equal(
      new Set(
        calls.map(
          (call) => (call.headers as Record<string, string>)["Idempotency-Key"],
        ),
      ).size,
      1,
    );
    assert.equal(new Set(calls.map((call) => call.body)).size, 1);
    await send(
      "PUT",
      "/api/v1/organizations/acme/members/person[acme]/job-role",
      { job_description: "Manager" },
      { version: 2 },
    );
    assert.notEqual(
      (calls[3].headers as Record<string, string>)["Idempotency-Key"],
      (calls[0].headers as Record<string, string>)["Idempotency-Key"],
    );
  } finally {
    globalThis.fetch = original;
  }
});

test("configurable action permissions reach the server while owner-only operations stay blocked", () => {
  const member = { org_role: "member", capabilities: [] };
  for (const suffix of [
    "/members/person[acme]/job-role",
    "/members/person[acme]/tags",
    "/tags",
  ]) {
    assert.equal(
      operationAllowed(
        {
          title: "Change",
          path: `/api/v1/organizations/acme${suffix}`,
          method: "PUT",
        },
        member,
      ),
      undefined,
    );
  }
  assert.match(
    operationAllowed(
      {
        title: "Transfer",
        path: "/api/v1/organizations/acme/ownership-transfers",
      },
      member,
    ) || "",
    /Only the current organization owner/,
  );
  assert.match(
    operationAllowed(
      {
        title: "Promote",
        path: "/api/v1/organizations/acme/members/person[acme]/admin-promotions",
      },
      member,
    ) || "",
    /admins.create/,
  );
});

test("approval retries survive form recreation without storing request contents", async () => {
  const originalFetch = globalThis.fetch;
  const originalWindow = globalThis.window;
  const saved = new Map<string, string>();
  globalThis.window = {
    sessionStorage: {
      getItem: (key: string) => saved.get(key) || null,
      setItem: (key: string, value: string) => saved.set(key, value),
      removeItem: (key: string) => saved.delete(key),
    },
  } as unknown as Window & typeof globalThis;
  const calls: RequestInit[] = [];
  globalThis.fetch = async (_url, init) => {
    calls.push(init || {});
    if (calls.length < 3)
      return new Response(
        JSON.stringify({
          error: { code: "approval_required", message: "Pending" },
        }),
        { status: 428 },
      );
    return new Response(JSON.stringify({ version: 2 }));
  };
  try {
    const body = { job_description: "Private proposed description" };
    await assert.rejects(
      mutation()(
        "PUT",
        "/api/v1/organizations/acme/members/person[acme]/job-role",
        body,
        { version: 1 },
      ),
    );
    assert.equal(saved.size, 1);
    assert.ok(
      ![...saved.values()].join().includes("Private proposed description"),
    );
    await assert.rejects(
      mutation()(
        "PUT",
        "/api/v1/organizations/acme/members/person[acme]/job-role",
        body,
        { version: 1 },
      ),
    );
    assert.equal(
      (calls[0].headers as Record<string, string>)["Idempotency-Key"],
      (calls[1].headers as Record<string, string>)["Idempotency-Key"],
    );
    await mutation()(
      "PUT",
      "/api/v1/organizations/acme/members/person[acme]/job-role",
      body,
      { version: 1 },
    );
    assert.deepEqual(JSON.parse([...saved.values()][0]), {});
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.window = originalWindow;
  }
});
