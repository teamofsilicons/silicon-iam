import { track, telemetryPreference } from "./telemetry";
export type RecordValue = Record<string, any>;
export type Page<T = RecordValue> = {
  items: T[];
  page: { next_cursor?: string | null; has_more: boolean };
};
export type Configuration = {
  telemetryEnabled?: boolean;
  consoleOrigin: string;
  authOrigin: string;
  environment: string;
};
export type SessionState = {
  authenticated: boolean;
  user?: RecordValue;
  sessionId?: string;
  expiresAt?: number;
};
export const segment = (value: string) => encodeURIComponent(value);
export const orgPath = (org: string) => `/api/v1/organizations/${segment(org)}`;
export function validateBaseOrigin(value: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(
      "Base URL must be a valid origin, such as https://app.example.com.",
    );
  }
  const loopback =
    ["localhost", "[::1]"].includes(url.hostname) ||
    /^127\.\d+\.\d+\.\d+$/.test(url.hostname);
  if (
    !/^https?:\/\/[^/?#\s]+$/.test(value) ||
    url.username ||
    url.password ||
    (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
  )
    throw new Error(
      "Base URL must contain only the origin, with no trailing slash, path, query, or fragment. Use HTTPS except for local loopback development.",
    );
}
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public requestId?: string,
    public details?: RecordValue,
    public retryAfter?: string | null,
  ) {
    super(message);
  }
}
export async function request<T = RecordValue>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const started = performance.now();
  track("iam.request.started", { route: path, method: init.method || "GET" });
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      credentials: "same-origin",
      redirect: "error",
      headers: {
        "X-IAM-Frontend": "1",
        "X-IAM-Telemetry": telemetryPreference() ? "on" : "off",
        Accept: "application/json",
        ...init.headers,
      },
      signal: AbortSignal.timeout(35000),
    });
  } catch {
    track("iam.request.failed", {
      route: path,
      method: init.method || "GET",
      duration_ms: performance.now() - started,
    });
    throw new ApiError(
      0,
      "connection_interrupted",
      "IAM could not confirm the request. Retry the same submission; its request key has been retained.",
    );
  }
  track("iam.request.completed", {
    route: path,
    method: init.method || "GET",
    status: response.status,
    duration_ms: performance.now() - started,
    request_id: response.headers.get("x-request-id"),
  });
  if (path === "/api/v1/logout" && response.ok) clearApprovalRetries();
  if (response.status === 204) return undefined as T;
  let value: RecordValue;
  try {
    value = await response.json();
  } catch {
    throw new ApiError(
      502,
      "unexpected_response",
      "IAM returned an unreadable response. Retry the same submission.",
    );
  }
  if (!response.ok) {
    const error = value.error || {};
    if (
      response.status === 401 &&
      ["session_expired", "sign_in_required"].includes(error.code)
    ) {
      clearApprovalRetries();
      window.dispatchEvent(new Event("iam:session-expired"));
    }
    throw new ApiError(
      response.status,
      error.code || "request_failed",
      error.message ||
        `IAM could not complete the request (${response.status}).`,
      error.request_id,
      error.details,
      response.headers.get("retry-after"),
    );
  }
  return value as T;
}
// Persist only approval retry keys and hashed signatures; generic mutations also
// carry secrets, so request bodies must never be written to browser storage.
const APPROVAL_RETRIES = "iam.approval-retries.v1";
type ApprovalRetry = { key: string; expiresAt: number };
function approvalRetries(): Record<string, ApprovalRetry> {
  try {
    const entries = Object.entries(
      JSON.parse(window.sessionStorage.getItem(APPROVAL_RETRIES) || "{}"),
    );
    return Object.fromEntries(
      entries
        .filter(([hash, entry]) => {
          const value = entry as ApprovalRetry;
          return (
            /^[a-f0-9]{64}$/.test(hash) &&
            typeof value?.key === "string" &&
            /^[a-f0-9-]{36}$/.test(value.key) &&
            Number.isFinite(value.expiresAt) &&
            value.expiresAt > Date.now() &&
            value.expiresAt <= Date.now() + 12 * 60 * 60 * 1000
          );
        })
        .slice(-100),
    ) as Record<string, ApprovalRetry>;
  } catch {
    return {};
  }
}
function saveApprovalRetry(hash: string, key?: string) {
  if (!hash) return;
  try {
    const entries = approvalRetries();
    if (key)
      entries[hash] = {
        key,
        expiresAt: entries[hash]?.expiresAt || Date.now() + 12 * 60 * 60 * 1000,
      };
    else delete entries[hash];
    window.sessionStorage.setItem(
      APPROVAL_RETRIES,
      JSON.stringify(Object.fromEntries(Object.entries(entries).slice(-100))),
    );
  } catch {
    /* Exact in-memory retries remain available with storage disabled. */
  }
}
export function clearApprovalRetries() {
  try {
    window.sessionStorage.removeItem(APPROVAL_RETRIES);
  } catch {
    /* Optional storage. */
  }
}
async function approvalRetryHash(signature: string): Promise<string> {
  try {
    const hash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(signature),
    );
    return Array.from(new Uint8Array(hash), (value) =>
      value.toString(16).padStart(2, "0"),
    ).join("");
  } catch {
    return "";
  }
}

// Each form owns this closure. Ambiguous retries reuse both the key and exact payload.
export function mutation() {
  const pending = new Map<string, string>();
  return async <T = RecordValue>(
    method: string,
    path: string,
    body?: unknown,
    options: { version?: number; stepUp?: string; contentType?: string } = {},
  ): Promise<T> => {
    const serialized = body === undefined ? undefined : JSON.stringify(body);
    const signature = JSON.stringify([
      method,
      path,
      serialized,
      options.version,
    ]);
    const retryHash = await approvalRetryHash(signature);
    const key =
      pending.get(signature) ||
      approvalRetries()[retryHash]?.key ||
      crypto.randomUUID();
    pending.set(signature, key);
    const headers: Record<string, string> = { "Idempotency-Key": key };
    if (serialized !== undefined)
      headers["Content-Type"] =
        options.contentType ||
        (method === "PATCH"
          ? "application/merge-patch+json"
          : "application/json");
    if (options.version !== undefined)
      headers["If-Match"] = `"${options.version}"`;
    if (options.stepUp) headers["X-Step-Up-Token"] = options.stepUp;
    try {
      const result = await request<T>(path, {
        method,
        headers,
        body: serialized,
      });
      pending.delete(signature);
      saveApprovalRetry(retryHash);
      return result;
    } catch (error) {
      if (error instanceof ApiError && error.code === "approval_required")
        saveApprovalRetry(retryHash, key);
      if (
        error instanceof ApiError &&
        error.status >= 400 &&
        error.status < 500 &&
        ![408, 425, 429].includes(error.status) &&
        error.code !== "approval_required" &&
        !error.code.startsWith("idempotency_")
      ) {
        pending.delete(signature);
        saveApprovalRetry(retryHash);
      }
      throw error;
    }
  };
}
export function description(value: unknown): string {
  return value instanceof Error
    ? value.message
    : "Something went wrong. Please try again.";
}
export const date = (value?: string) =>
  value
    ? new Date(value).toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      })
    : "—";
export const label = (value: string) =>
  value.replaceAll("_", " ").replace(/\b\w/g, (s) => s.toUpperCase());
export function authDestination(config: Configuration, signup = false): string {
  const result = new URL(signup ? "/signup" : "/login", config.authOrigin);
  const current = new URL(location.href);
  for (const name of [
    "app_id",
    "app_ids",
    "bundle_id",
    "redirect_uri",
    "org_id",
    "org_ids",
    "next",
    "request",
  ]) {
    for (const value of current.searchParams.getAll(name))
      result.searchParams.append(name, value);
  }
  if (current.pathname === "/join") result.searchParams.set("next", "join");
  return result.href;
}
export function continueDestination(): string {
  const result = new URL("/auth/continue", location.origin),
    current = new URL(location.href);
  for (const name of [
    "app_id",
    "app_ids",
    "bundle_id",
    "redirect_uri",
    "org_id",
    "org_ids",
    "next",
    "request",
  ]) {
    for (const value of current.searchParams.getAll(name))
      result.searchParams.append(name, value);
  }
  if (current.pathname === "/join") result.searchParams.set("next", "join");
  return result.pathname + result.search;
}
