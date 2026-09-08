export type RecordValue = Record<string, any>;
export type Page<T = RecordValue> = {
  items: T[];
  page: { next_cursor?: string | null; has_more: boolean };
};
export type Configuration = {
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
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      credentials: "same-origin",
      redirect: "error",
      headers: {
        "X-IAM-Frontend": "1",
        Accept: "application/json",
        ...init.headers,
      },
      signal: AbortSignal.timeout(35000),
    });
  } catch {
    throw new ApiError(
      0,
      "connection_interrupted",
      "IAM could not confirm the request. Retry the same submission; its request key has been retained.",
    );
  }
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
      !path.includes("/login/challenges") &&
      !path.includes("/signup/")
    )
      window.dispatchEvent(new Event("iam:session-expired"));
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
    const key = pending.get(signature) || crypto.randomUUID();
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
      return result;
    } catch (error) {
      if (
        error instanceof ApiError &&
        error.status >= 400 &&
        error.status < 500 &&
        ![408, 425, 429].includes(error.status) &&
        !error.code.startsWith("idempotency_")
      )
        pending.delete(signature);
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
  for (const name of ["app_id", "redirect_uri", "org_id", "next"]) {
    const value = current.searchParams.get(name);
    if (value) result.searchParams.set(name, value);
  }
  if (current.pathname === "/join") result.searchParams.set("next", "join");
  return result.href;
}
export function continueDestination(): string {
  const result = new URL("/auth/continue", location.origin),
    current = new URL(location.href);
  for (const name of ["app_id", "redirect_uri", "org_id", "next"]) {
    const value = current.searchParams.get(name);
    if (value) result.searchParams.set(name, value);
  }
  if (current.pathname === "/join") result.searchParams.set("next", "join");
  return result.pathname + result.search;
}
