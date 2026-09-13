import type { Page, RecordValue } from "./api";

export type ReviewDirection = "all" | "incoming" | "outgoing";

export function matchesScopeReview(
  review: RecordValue,
  appId: string | undefined,
  direction: ReviewDirection,
) {
  if (direction === "incoming")
    return appId ? review.target_app_id === appId : review.can_decide === true;
  if (direction === "outgoing") return review.app_id === appId;
  return !appId || review.app_id === appId || review.target_app_id === appId;
}

// The API paginates the authorized shared inbox. Keep advancing past pages
// belonging to other apps so an empty first page never hides incoming requests.
export async function scopeReviewPage(
  url: string,
  appId: string | undefined,
  direction: ReviewDirection,
  read: (url: string) => Promise<Page>,
): Promise<Page> {
  const next = new URL(url, "https://iam.invalid");
  const seen = new Set<string>();
  for (;;) {
    const page = await read(next.pathname + next.search);
    const items = page.items.filter((review) =>
      matchesScopeReview(review, appId, direction),
    );
    if (items.length || !page.page.has_more) return { ...page, items };
    const cursor = page.page.next_cursor;
    if (!cursor || seen.has(cursor))
      throw new Error("Scope review pagination stalled. Refresh to try again.");
    seen.add(cursor);
    next.searchParams.set("cursor", cursor);
  }
}
