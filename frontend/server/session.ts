export type Environment = {
  IAM_TELEMETRY?: string;
  IAM_TELEMETRY_KEY?: string;
  IAM_TELEMETRY_URL?: string;
  API_UPSTREAM: string;
  CONSOLE_ORIGIN: string;
  AUTH_ORIGIN: string;
  SESSION_COOKIE_KEY: string;
  COOKIE_DOMAIN?: string;
  DISPLAY_ENVIRONMENT?: string;
  ASSETS?: { fetch(request: Request): Promise<Response> };
};
export type Session = {
  access: string;
  refresh: string;
  expires: number;
  deadline: number;
  browserCookie: string;
  sessionId: string;
};
export type Settings = {
  upstream: URL;
  console: URL;
  auth: URL;
  key: Uint8Array<ArrayBuffer>;
  cookieName: string;
  cookieOptions: string;
};
const encoder = new TextEncoder();
const flights = new Map<
  string,
  { expires: number; promise: Promise<Session> }
>();
export class RefreshRejected extends Error {
  constructor(public status: number) {
    super("IAM refresh rejected");
  }
}
export const isLoopback = (host: string) =>
  host === "localhost" || host === "[::1]" || /^127\.\d+\.\d+\.\d+$/.test(host);
const encode = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
const decode = (text: string) =>
  Uint8Array.from(atob(text.replaceAll("-", "+").replaceAll("_", "/")), (c) =>
    c.charCodeAt(0),
  );
export const fail = (code: string, message: string, status: number) =>
  Response.json({ error: { code, message } }, { status });
function origin(value: string): URL {
  const url = new URL(value);
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/" ||
    !(
      url.protocol === "https:" ||
      (url.protocol === "http:" && isLoopback(url.hostname))
    )
  )
    throw new Error("Invalid origin configuration");
  return url;
}
export function settings(env: Environment): Settings {
  const upstream = origin(env.API_UPSTREAM),
    main = origin(env.CONSOLE_ORIGIN),
    auth = origin(env.AUTH_ORIGIN),
    key = decode(env.SESSION_COOKIE_KEY);
  if (key.byteLength !== 32)
    throw new Error(
      "SESSION_COOKIE_KEY must be a base64url-encoded 32-byte key",
    );
  const secure = main.protocol === "https:";
  if (secure !== (auth.protocol === "https:"))
    throw new Error("Frontend protocols must match");
  let domain = "";
  if (env.COOKIE_DOMAIN) {
    const value = env.COOKIE_DOMAIN.replace(/^\./, "");
    if (
      !secure ||
      !/^[a-z0-9.-]+$/.test(value) ||
      value.split(".").length < 3 ||
      ![main, auth].every(
        (url) => url.hostname === value || url.hostname.endsWith(`.${value}`),
      )
    )
      throw new Error("Invalid shared cookie domain");
    domain = `; Domain=${value}`;
  } else if (main.hostname !== auth.hostname)
    throw new Error("Separate frontend hosts need a shared cookie domain");
  return {
    upstream,
    console: main,
    auth,
    key,
    cookieName: secure ? "__Secure-iam_frontend" : "iam_frontend_dev",
    cookieOptions: `; Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}${domain}`,
  };
}
const associated = (config: Settings) =>
  encoder.encode(
    `iam-frontend:v1|${config.upstream.origin}|${config.console.origin}|${config.auth.origin}`,
  );
async function seal(session: Session, config: Settings): Promise<string> {
  const key = await crypto.subtle.importKey(
      "raw",
      config.key,
      "AES-GCM",
      false,
      ["encrypt"],
    ),
    iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: associated(config) },
    key,
    encoder.encode(JSON.stringify(session)),
  );
  return `v1.${encode(iv)}.${encode(new Uint8Array(cipher))}`;
}
export async function readSession(
  request: Request,
  config: Settings,
): Promise<Session | null> {
  const cookies = (request.headers.get("cookie") || "")
    .split(";")
    .map((v) => v.trim())
    .filter((v) => v.startsWith(`${config.cookieName}=`));
  if (cookies.length !== 1) return null;
  try {
    const [version, iv, cipher, extra] = cookies[0]
      .slice(config.cookieName.length + 1)
      .split(".");
    if (version !== "v1" || extra || !iv || !cipher || cipher.length > 6000)
      return null;
    const key = await crypto.subtle.importKey(
      "raw",
      config.key,
      "AES-GCM",
      false,
      ["decrypt"],
    );
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: decode(iv), additionalData: associated(config) },
      key,
      decode(cipher),
    );
    const value = JSON.parse(new TextDecoder().decode(plain)) as Session;
    if (
      typeof value.access !== "string" ||
      !value.access.startsWith("cat_") ||
      typeof value.refresh !== "string" ||
      typeof value.browserCookie !== "string" ||
      !value.browserCookie.startsWith("iam_session=") ||
      !Number.isFinite(value.expires) ||
      !Number.isFinite(value.deadline) ||
      value.deadline <= Date.now()
    )
      return null;
    return value;
  } catch {
    return null;
  }
}
export function fromTokens(
  value: Record<string, unknown>,
  upstream: Response,
  previous?: Session,
): Session {
  const actor = value.actor as { type?: string },
    browserCookie =
      upstream.headers.get("set-cookie")?.split(";")[0] ||
      previous?.browserCookie;
  if (
    actor?.type !== "carbon" ||
    typeof value.access_token !== "string" ||
    typeof value.refresh_token !== "string" ||
    !browserCookie?.startsWith("iam_session=")
  )
    throw new Error("Unexpected IAM session response");
  const deadline = Date.parse(String(value.refresh_expires_at)),
    expires = Date.now() + Number(value.expires_in) * 1000;
  if (!Number.isFinite(deadline) || !Number.isFinite(expires))
    throw new Error("Unexpected IAM token lifetime");
  return {
    access: value.access_token,
    refresh: value.refresh_token,
    browserCookie,
    expires,
    deadline,
    sessionId: String(value.session_id),
  };
}
export async function refreshed(
  session: Session,
  config: Settings,
): Promise<Session> {
  if (session.expires > Date.now() + 30000) return session;
  // Deterministic idempotency across replicas prevents rotating-refresh reuse.
  const key = await crypto.subtle.importKey(
    "raw",
    config.key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = encode(
    new Uint8Array(
      await crypto.subtle.sign(
        "HMAC",
        key,
        encoder.encode(`refresh:v1:${session.refresh}`),
      ),
    ),
  );
  const now = Date.now();
  for (const [id, entry] of flights)
    if (entry.expires < now) flights.delete(id);
  const existing = flights.get(digest);
  if (existing) return existing.promise;
  if (flights.size > 1000) throw new Error("Session refresh is busy");
  const promise = (async () => {
    const response = await fetch(
      new URL("/api/v1/auth/tokens/refresh", config.upstream),
      {
        method: "POST",
        redirect: "manual",
        signal: AbortSignal.timeout(15000),
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": `frontend-refresh-${digest}`,
        },
        body: JSON.stringify({ refresh_token: session.refresh }),
      },
    );
    if (!response.ok) throw new RefreshRejected(response.status);
    return fromTokens(
      (await response.json()) as Record<string, unknown>,
      response,
      session,
    );
  })();
  flights.set(digest, { expires: now + 60000, promise });
  try {
    return await promise;
  } catch (error) {
    flights.delete(digest);
    throw error;
  }
}
export async function finish(
  response: Response,
  config: Settings,
  session?: Session | null,
): Promise<Response> {
  const headers = new Headers(response.headers);
  for (const name of [
    "content-encoding",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
  ])
    headers.delete(name);
  headers.delete("set-cookie");
  headers.delete("access-control-allow-origin");
  headers.delete("access-control-allow-credentials");
  headers.set("Cache-Control", "no-store");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  if (session === null)
    headers.set(
      "Set-Cookie",
      `${config.cookieName}=; Max-Age=0${config.cookieOptions}`,
    );
  else if (session)
    headers.set(
      "Set-Cookie",
      `${config.cookieName}=${await seal(session, config)}; Max-Age=${Math.max(0, Math.floor((session.deadline - Date.now()) / 1000))}${config.cookieOptions}`,
    );
  return new Response(response.body, { status: response.status, headers });
}
export function apiHeaders(request: Request, session: Session | null): Headers {
  const headers = new Headers({ Accept: "application/json" });
  for (const name of [
    "content-type",
    "idempotency-key",
    "if-match",
    "x-step-up-token",
  ]) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }
  if (session) {
    headers.set("Authorization", `Bearer ${session.access}`);
    headers.set("Cookie", session.browserCookie);
  }
  if (
    request.headers.get("x-iam-telemetry") === "off" ||
    /(?:^|;\s*)iam_telemetry=off(?:;|$)/.test(
      request.headers.get("cookie") || "",
    )
  )
    headers.set("x-iam-telemetry", "off");
  return headers;
}
