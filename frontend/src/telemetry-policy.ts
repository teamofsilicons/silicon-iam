import routes from "./telemetry-routes.json" with { type: "json" };
export const TELEMETRY_TABLE = "siliconiam";
export const TELEMETRY_SETTING = "iam.telemetry.enabled";
const types = new Set([
  "page_view",
  "page_exit",
  "click",
  "error",
  "scroll",
  "timing",
  "network",
  "network_error",
  "iam.request.started",
  "iam.request.completed",
  "iam.request.failed",
  "iam.session.expired",
  "iam.render.failed",
]);
const pages = new Set([
  "/",
  "/login",
  "/signup",
  "/sso/complete",
  "/applications",
  "/organizations",
  "/members",
  "/silicons",
  "/invitations",
  "/tags",
  "/trust",
  "/approvals",
  "/scope-reviews",
  "/bundles",
  "/testing",
  "/profile",
  "/sessions",
]);
const uuid = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export function safeRoute(value: unknown): string {
  if (typeof value !== "string") return "<unmatched>";
  let path: string;
  try {
    path = new URL(value, "https://iam.invalid").pathname;
  } catch {
    return "<unmatched>";
  }
  if (pages.has(path)) return path;
  if (/^\/join\/[^/]+$/.test(path)) return "/join/{org_id}";
  const parts = path.split("/");
  return (
    routes.find((route) => {
      const pattern = route.split("/");
      return (
        pattern.length === parts.length &&
        pattern.every(
          (part, i) =>
            part === parts[i] ||
            (part.startsWith("{") && part.endsWith("}") && parts[i] !== ""),
        )
      );
    }) || "<unmatched>"
  );
}
export function preference(
  storage: Pick<Storage, "getItem"> | undefined,
): boolean {
  try {
    return storage?.getItem(TELEMETRY_SETTING) !== "off";
  } catch {
    return true;
  }
}
export function safeData(value: unknown): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  if (!value || typeof value !== "object" || Array.isArray(value))
    return output;
  for (const [key, val] of Object.entries(value)) {
    if (
      [
        "status",
        "duration_ms",
        "elapsed_ms",
        "percent",
        "dns_ms",
        "connect_ms",
        "response_ms",
        "dom_content_loaded_ms",
        "load_ms",
        "line",
        "column",
      ].includes(key) &&
      typeof val === "number" &&
      Number.isFinite(val) &&
      val >= 0 &&
      val <= 1e10
    )
      output[key] = val;
    if (
      key === "method" &&
      typeof val === "string" &&
      /^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(val)
    )
      output[key] = val;
    if (
      key === "kind" &&
      ["runtime", "unhandledrejection"].includes(String(val))
    )
      output[key] = val;
    if (
      key === "tag" &&
      [
        "a",
        "button",
        "input",
        "select",
        "textarea",
        "label",
        "div",
        "span",
        "svg",
      ].includes(String(val))
    )
      output[key] = val;
    if (
      key === "role" &&
      ["button", "link", "checkbox", "switch", "menuitem", "tab"].includes(
        String(val),
      )
    )
      output[key] = val;
    if (key === "request_id" && uuid(val)) output[key] = val;
    if (key === "success" && typeof val === "boolean") output[key] = val;
    if (key === "url" || key === "route") output.route = safeRoute(val);
  }
  return output;
}
export type BrowserEvent = {
  id: string;
  type: string;
  data: Record<string, unknown>;
  metadata: Record<string, unknown>;
};
export function safeBatch(value: unknown): {
  table: string;
  events: BrowserEvent[];
} {
  const input = value as { table?: unknown; events?: unknown };
  if (
    !input ||
    input.table !== TELEMETRY_TABLE ||
    !Array.isArray(input.events) ||
    input.events.length < 1 ||
    input.events.length > 40
  )
    throw new Error("invalid telemetry batch");
  const events = input.events.map((value): BrowserEvent => {
    if (!value || !uuid(value.id) || !types.has(value.type))
      throw new Error("invalid telemetry event");
    const metadata: Record<string, unknown> = {
      path: safeRoute(value.metadata?.path),
      client_reported: true,
    };
    if (uuid(value.metadata?.session_id))
      metadata.session_id = value.metadata.session_id;
    const occurredAt = value.metadata?.occurred_at;
    if (
      typeof occurredAt === "string" &&
      occurredAt.length <= 32 &&
      Number.isFinite(Date.parse(occurredAt))
    )
      metadata.occurred_at = new Date(occurredAt).toISOString();
    for (const [key, allowed] of Object.entries({
      browser: ["chrome", "firefox", "safari", "edge", "unknown"],
      device: ["mobile", "desktop"],
    })) {
      if (allowed.includes(value.metadata?.[key]))
        metadata[key] = value.metadata[key];
    }
    return {
      id: value.id,
      type: value.type,
      data: safeData(value.data),
      metadata,
    };
  });
  return { table: TELEMETRY_TABLE, events };
}
