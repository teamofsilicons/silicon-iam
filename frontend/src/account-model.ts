import { request, type RecordValue } from "./api";
export type BrowserAccount = {
  account_id: string;
  type: "carbon" | "silicon";
  user?: RecordValue;
  unavailable?: boolean;
  expired?: boolean;
};
export type AccountPage = {
  items: BrowserAccount[];
  active_account_id?: string;
  maximum_accounts: number;
};
export type AccountOrganization = { org_id: string; name: string };
export const accountLabel = (account: BrowserAccount): string =>
  account.user?.carbon_id ||
  account.user?.silicon_id ||
  account.user?.public_id ||
  "Account unavailable";
export const accountHeaders = (id: string) => ({ "X-IAM-Account": id });
export async function configuredAccounts(): Promise<AccountPage> {
  return request<AccountPage>("/api/accounts");
}
export async function accountOrganizations(
  id: string,
): Promise<AccountOrganization[]> {
  const items: AccountOrganization[] = [];
  let cursor: string | undefined;
  const cursors = new Set<string>();
  do {
    const page = await request<{
      items: AccountOrganization[];
      page: { has_more: boolean; next_cursor?: string };
    }>(
      `/api/v1/organizations?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
      { headers: accountHeaders(id) },
    );
    items.push(...page.items);
    if (!page.page.has_more) return items;
    if (!page.page.next_cursor || cursors.has(page.page.next_cursor))
      throw new Error("IAM could not load every organization. Please retry.");
    cursor = page.page.next_cursor;
    cursors.add(cursor);
  } while (cursors.size < 100);
  throw new Error(
    "There are too many organizations to display. Please contact support.",
  );
}
const COLLAPSED = "iam.collapsed-accounts.v1";
export function collapsedAccounts(): string[] {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(COLLAPSED) || "[]");
    return Array.isArray(value)
      ? value.filter((id): id is string => typeof id === "string").slice(0, 100)
      : [];
  } catch {
    return [];
  }
}
export function saveCollapsedAccounts(ids: string[]): void {
  try {
    localStorage.setItem(COLLAPSED, JSON.stringify(ids.slice(0, 100)));
  } catch {
    /* Optional preference only. */
  }
}
export function addAccountUrl(type?: "carbon" | "silicon"): string {
  const url = new URL(location.href);
  url.pathname = "/login";
  url.searchParams.set("add_account", "1");
  if (type) url.searchParams.set("type", type);
  return url.href;
}
