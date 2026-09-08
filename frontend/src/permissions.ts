import { orgPath, request, type Page, type RecordValue } from "./api";
import type { Operation } from "./forms";
export async function organizationAuthority(
  org: string,
  principal: string,
): Promise<RecordValue> {
  let cursor = "";
  for (let count = 0; count < 100; count++) {
    const page = await request<Page>(
      `${orgPath(org)}/members?limit=100&principal_type=carbon${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
    );
    const own = page.items.find(
      (item) =>
        item.principal.principal_id === principal && item.status === "active",
    );
    if (own) return request(`${orgPath(org)}/members/${own.id}/authorization`);
    if (!page.page.has_more || !page.page.next_cursor) break;
    cursor = page.page.next_cursor;
  }
  throw new Error(
    "Your active organization membership could not be resolved. Refresh or select another organization.",
  );
}
export function operationAllowed(
  op: Operation,
  authority: RecordValue,
): string | undefined {
  if (authority.org_role === "owner") return;
  const has = (capability: string) =>
    (authority.capabilities || []).includes(capability);
  const admin = authority.org_role === "admin";
  let required = "";
  if (op.path.endsWith("/ownership-transfers"))
    return "Only the current organization owner can transfer ownership.";
  if (
    op.path.includes("/testing-environments") ||
    op.path.includes("/approval-requests") ||
    op.path.endsWith("/trust/effective")
  )
    return; // Creator/quorum policy is checked per record by IAM.
  if (/\/sso(?:\/|$)/.test(op.path)) required = "sso.manage";
  else if (/\/trust\//.test(op.path)) required = "trust.manage";
  else if (/\/carbon-invites/.test(op.path)) required = "members.invite";
  else if (/\/admin-promotions$/.test(op.path)) required = "admins.create";
  else if (/\/(admin-demotions|capabilities)$/.test(op.path))
    required = "admins.manage";
  else if (/\/members\/[^/]+\/(job-role|tags)$/.test(op.path)) {
    if (!admin)
      return "Direct job-role and tag changes require a current organization owner or admin.";
    required = op.path.endsWith("/tags") ? "tags.manage" : "roles.approve";
  } else if (/\/members\/[^/]+$/.test(op.path))
    required =
      op.method === "DELETE" ? "members.remove" : "members.update_directory";
  else if (/\/silicons/.test(op.path))
    required = op.path.includes("token-rotation")
      ? "silicons.rotate_token"
      : op.method === "DELETE" && !op.path.includes("/webhook")
        ? "silicons.remove"
        : op.path.endsWith("/silicons")
          ? "silicons.create"
          : "silicons.update_directory";
  else if (/\/tags(?:\/|$)/.test(op.path)) required = "tags.manage";
  else if (op.method === "PATCH") required = "organization.update";
  if (required && !has(required))
    return `Your current membership does not grant ${required}. Ask the organization owner to delegate the required capability.`;
}
