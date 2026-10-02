export type OboEndpoint = {
  audience: string;
  app_name: string;
  endpoint_id: string;
  obo_id?: string;
  name?: string;
  note_to_user?: string | null;
  additional_warnings?: string[];
  description: string;
  critical: boolean;
  downstream: OboEndpoint[];
};

export type OboConsent = {
  id: string;
  app_id: string;
  app_name: string;
  actor: { type: string; public_id: string };
  org_id: string;
  status: "pending" | "approved" | "declined" | "exchanged" | "expired";
  version: number;
  expires_at: string;
  endpoints: OboEndpoint[];
  providers?: {
    app_id: string;
    app_name?: string;
    org_id: string;
    actor: { type: string; public_id: string };
  }[];
};

export type OboDecision = {
  request_id: string;
  status: "approved" | "declined";
  authorization_code?: string;
  redirect_uri?: string;
  expires_at: string;
};

export type OboGrant = {
  id: string;
  app_id: string;
  app_name: string;
  org_id: string;
  audience: string;
  endpoint_id: string;
  status: string;
  created_at: string;
  expires_at: string | null;
  endpoints: OboEndpoint[];
};

export type OboGrantPage = {
  items: OboGrant[];
  page: { has_more: boolean; next_cursor?: string | null };
};

const record = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
const text = (value: unknown): value is string =>
  typeof value === "string" && value.trim().length > 0;
const timestamp = (value: unknown): value is string =>
  text(value) && Number.isFinite(Date.parse(value));
const optionalName = (value: unknown): boolean =>
  value == null || typeof value === "string";

/** Never hide malformed or missing branches and then approve the remaining graph. */
function endpoints(
  value: unknown,
  callers: string[],
  depth = 1,
): value is OboEndpoint[] {
  if (!Array.isArray(value) || depth > 11) return false;
  if (depth === 11) return value.length === 0;
  const siblings = new Set<string>();
  return value.every((node) => {
    if (!record(node) || !text(node.audience) || !text(node.endpoint_id))
      return false;
    const key = `${node.audience}:${node.endpoint_id}`;
    if (siblings.has(key) || callers.includes(node.audience)) return false;
    siblings.add(key);
    return (
      optionalName(node.app_name) &&
      optionalName(node.name) &&
      optionalName(node.note_to_user) &&
      (node.additional_warnings === undefined ||
        (Array.isArray(node.additional_warnings) &&
          node.additional_warnings.every(text))) &&
      text(node.description) &&
      typeof node.critical === "boolean" &&
      endpoints(node.downstream, [...callers, node.audience], depth + 1)
    );
  });
}

function endpointNames(nodes: OboEndpoint[]): OboEndpoint[] {
  return nodes.map((node) => ({
    ...node,
    app_name: text(node.app_name) ? node.app_name : node.audience,
    downstream: endpointNames(node.downstream),
  }));
}

export function consentDetail(value: unknown, requestId: string): OboConsent {
  if (
    !record(value) ||
    value.id !== requestId ||
    !text(value.app_id) ||
    !optionalName(value.app_name) ||
    !text(value.org_id) ||
    !timestamp(value.expires_at) ||
    !Number.isSafeInteger(value.version) ||
    Number(value.version) < 1 ||
    !["pending", "approved", "declined", "exchanged", "expired"].includes(
      String(value.status),
    ) ||
    !record(value.actor) ||
    !text(value.actor.type) ||
    !text(value.actor.public_id) ||
    !endpoints(value.endpoints, [value.app_id]) ||
    value.endpoints.length === 0 ||
    (value.providers !== undefined &&
      (!Array.isArray(value.providers) ||
        value.providers.some(
          (provider) =>
            !record(provider) ||
            !text(provider.app_id) ||
            !text(provider.org_id) ||
            !record(provider.actor) ||
            !text(provider.actor.public_id),
        )))
  )
    throw new Error(
      "IAM could not load the complete OBO permissions. Reload before approving.",
    );
  return {
    ...value,
    app_name: text(value.app_name) ? value.app_name : value.app_id,
    endpoints: endpointNames(value.endpoints),
  } as OboConsent;
}

export function grantDetails(value: unknown): OboGrant[] {
  if (!record(value) || !Array.isArray(value.items))
    throw new Error(
      "IAM returned an unreadable OBO grant list. Reload to try again.",
    );
  const seen = new Set<string>();
  for (const item of value.items) {
    if (
      !record(item) ||
      !text(item.id) ||
      seen.has(item.id) ||
      !text(item.app_id) ||
      !optionalName(item.app_name) ||
      !text(item.org_id) ||
      !text(item.audience) ||
      !text(item.endpoint_id) ||
      !text(item.status) ||
      !timestamp(item.created_at) ||
      (item.expires_at !== null && !timestamp(item.expires_at)) ||
      !endpoints(item.endpoints, [item.app_id]) ||
      item.endpoints.length !== 1 ||
      item.endpoints[0].audience !== item.audience ||
      item.endpoints[0].endpoint_id !== item.endpoint_id
    )
      throw new Error(
        "IAM could not load the complete OBO grant details. Reload to try again.",
      );
    seen.add(item.id);
  }
  return (value.items as OboGrant[]).map((item) => ({
    ...item,
    app_name: text(item.app_name) ? item.app_name : item.app_id,
    endpoints: endpointNames(item.endpoints),
  }));
}

export function grantPage(value: unknown): OboGrantPage {
  if (
    !record(value) ||
    !record(value.page) ||
    typeof value.page.has_more !== "boolean" ||
    (value.page.has_more
      ? !text(value.page.next_cursor)
      : value.page.next_cursor != null)
  )
    throw new Error(
      "IAM could not load the OBO grant list pagination. Reload to try again.",
    );
  return {
    items: grantDetails(value),
    page: value.page as OboGrantPage["page"],
  };
}

export function appendGrantPage(
  current: OboGrantPage,
  next: OboGrantPage,
): OboGrantPage {
  if (next.page.has_more && next.page.next_cursor === current.page.next_cursor)
    throw new Error("IAM did not advance the OBO grant list. Try again.");
  const seen = new Set(current.items.map((item) => item.id));
  return {
    items: [
      ...current.items,
      ...next.items.filter((item) => !seen.has(item.id)),
    ],
    page: next.page,
  };
}

export function decisionResult(
  value: unknown,
  requestId: string,
  decision: "approve" | "decline",
): OboDecision {
  if (
    !record(value) ||
    value.request_id !== requestId ||
    value.status !== (decision === "approve" ? "approved" : "declined") ||
    !timestamp(value.expires_at) ||
    (value.redirect_uri !== undefined && !safeOboRedirect(value.redirect_uri)) ||
    (decision === "approve" && !text(value.authorization_code)) ||
    (decision === "decline" && value.authorization_code !== undefined)
  )
    throw new Error(
      "IAM could not confirm this decision. Retry the same submission.",
    );
  return value as OboDecision;
}

export function consentPending(value: OboConsent, now: number): boolean {
  return value.status === "pending" && Date.parse(value.expires_at) > now;
}

export function callerLabel(callerId: string, callerName: string): string {
  return callerName === callerId ? callerId : `${callerName} (${callerId})`;
}

/** Only a server-bound callback from the confirmed decision may carry its code. */
export function safeOboRedirect(value: unknown): string | undefined {
  if(typeof value!=="string") return;
  try {const url=new URL(value);if(url.username||url.password||url.hash)return;
    if(url.protocol!=="https:" && !(url.protocol==="http:" && ["localhost","127.0.0.1","[::1]"].includes(url.hostname)))return;
    return url.href;
  }catch{return;}
}
