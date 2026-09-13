import assert from "node:assert/strict";
import test from "node:test";
import { matchesScopeReview, scopeReviewPage } from "../src/scope-review-page";
import type { Page } from "../src/api";

test("Briefcase incoming approvals use the target app, not the requesting app", () => {
  const incoming = {
    app_id: "outside>caller",
    target_app_id: "tos>briefcase",
    can_decide: true,
  };
  const sent = {
    app_id: "tos>briefcase",
    target_app_id: null,
    can_decide: false,
  };
  assert.equal(matchesScopeReview(incoming, "tos>briefcase", "incoming"), true);
  assert.equal(matchesScopeReview(sent, "tos>briefcase", "incoming"), false);
  assert.equal(matchesScopeReview(sent, "tos>briefcase", "outgoing"), true);
  assert.equal(
    matchesScopeReview(incoming, "tos>briefcase", "outgoing"),
    false,
  );
  assert.equal(matchesScopeReview(incoming, undefined, "incoming"), true);
  assert.equal(matchesScopeReview(sent, undefined, "incoming"), false);
});

test("an incoming request on a later shared-inbox page is not hidden", async () => {
  const calls: string[] = [];
  const pages: Page[] = [
    {
      items: [{ app_id: "tos>briefcase", target_app_id: null }],
      page: { has_more: true, next_cursor: "next+page" },
    },
    {
      items: [
        {
          id: "incoming",
          app_id: "outside>caller",
          target_app_id: "tos>briefcase",
        },
      ],
      page: { has_more: true, next_cursor: "remaining" },
    },
  ];
  const result = await scopeReviewPage(
    "/api/v1/application-scope-requests?status=pending&limit=30",
    "tos>briefcase",
    "incoming",
    async (url) => {
      calls.push(url);
      return pages.shift()!;
    },
  );
  assert.equal(calls.length, 2);
  const next = new URL(calls[1], "https://iam.invalid");
  assert.equal(next.searchParams.get("status"), "pending");
  assert.equal(next.searchParams.get("cursor"), "next+page");
  assert.equal(result.items[0].id, "incoming");
  assert.equal(result.page.next_cursor, "remaining");
});

test("empty results exhaust all pages and a stalled cursor fails visibly", async () => {
  const empty = await scopeReviewPage(
    "/reviews",
    "tos>briefcase",
    "incoming",
    async () => ({ items: [], page: { has_more: false } }),
  );
  assert.deepEqual(empty.items, []);
  await assert.rejects(
    scopeReviewPage("/reviews", "tos>briefcase", "incoming", async () => ({
      items: [],
      page: { has_more: true, next_cursor: "stuck" },
    })),
    /pagination stalled/,
  );
});
