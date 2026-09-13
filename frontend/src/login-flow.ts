/** Pure login URL and handoff rules, shared by the UI and regression checks. */
export type LoginToken = {
  app_id: string;
  slt: string;
  expires_in: number;
  expires_at?: string;
  request_id?: string;
};
export function loginApplications(params: URLSearchParams): {
  ids: string[];
  batch: boolean;
  bundleId?: string;
} {
  if (params.has("org_id") || params.has("org_ids"))
    throw new Error(
      "Applications cannot choose your organizations. Remove org_id / org_ids and choose them in IAM.",
    );
  if (
    params.getAll("bundle_id").length > 1 ||
    params.getAll("app_id").length > 1 ||
    params.getAll("app_ids").length > 1 ||
    ["app_id", "app_ids", "bundle_id"].filter((key) => params.has(key)).length >
      1
  )
    throw new Error(
      "Use one app_id, a comma-separated app_ids list, or one bundle_id.",
    );
  if (params.has("bundle_id")) {
    const bundleId = params.get("bundle_id")!;
    if (!/^[a-z0-9_-]{3,50}>[a-z][a-z0-9_-]{0,79}$/.test(bundleId))
      throw new Error("Choose a valid application bundle ID.");
    return { ids: [], batch: true, bundleId };
  }
  const batch = params.has("app_ids");
  const raw = params.get(batch ? "app_ids" : "app_id");
  const ids = raw === null ? [] : batch ? raw.split(",") : [raw];
  if (
    !ids.length ||
    ids.length > 100 ||
    new Set(ids).size !== ids.length ||
    ids.some((id) => !/^[a-z0-9_-]{3,50}>[a-z][a-z0-9_-]{0,79}$/.test(id))
  )
    throw new Error("Choose between 1 and 100 unique, valid application IDs.");
  return { ids, batch };
}
export function loginCallback(raw: string | null): URL | undefined {
  if (raw === null) return;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("The callback must be a valid absolute URL.");
  }
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "[::1]" ||
    /^127\.\d+\.\d+\.\d+$/.test(url.hostname);
  if (
    raw.length > 2048 ||
    url.username ||
    url.password ||
    url.hash ||
    url.port === "0" ||
    (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
  )
    throw new Error(
      "The callback must use HTTPS (or HTTP on localhost), without credentials or a fragment.",
    );
  return url;
}
export function tokenDestination(
  destination: URL,
  items: LoginToken[],
  batch: boolean,
): string {
  const result = new URL(destination);
  if (batch) {
    result.searchParams.delete("slt");
    result.searchParams.delete("slts");
    result.hash = new URLSearchParams({
      slts: JSON.stringify(items),
    }).toString();
  } else {
    result.searchParams.set("slt", items[0].slt);
  }
  return result.href;
}

/** An empty selection is allowed only when IAM confirms this user's eligibility. */
export function canApproveOrganizationSelections(
  choices: {
    app_id: string;
    allow_empty_organization_selection?: boolean;
  }[],
  selected: Record<string, string[]>,
): boolean {
  return (
    choices.length > 0 &&
    choices.every((app) => {
      const ids = selected[app.app_id];
      return (
        Array.isArray(ids) &&
        ids.length <= 1000 &&
        (ids.length > 0 || app.allow_empty_organization_selection === true)
      );
    })
  );
}
