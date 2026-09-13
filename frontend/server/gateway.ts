import { collectTelemetry, deploymentTelemetryEnabled } from "./telemetry.ts";
import { testApplicationView } from "./test-view.ts";
import {
  apiHeaders,
  fail,
  finish,
  fromTokens,
  isLoopback,
  readSession,
  refreshed,
  RefreshRejected,
  settings,
  type Environment,
  type Session,
  type Settings,
} from "./session.ts";
export type { Environment } from "./session.ts";
const isPublic = (path: string, method: string) =>
  (method === "POST" &&
    (/^\/api\/v1\/signup\/sessions(?:\/[0-9a-f-]+\/(?:email|phone)(?:\/verify)?|\/[0-9a-f-]+\/complete)?$/.test(
      path,
    ) ||
      /^\/api\/v1\/login\/challenges(?:\/[0-9a-f-]+\/verify)?$/.test(path))) ||
  (method === "GET" &&
    (/^\/api\/v1\/(?:carbon-ids|organization-ids)\/[^/]+\/availability$/.test(
      path,
    ) ||
      path === "/api/v1/version"));
const navigationRoute = (path: string) =>
  path === "/api/v1/login" ||
  path === "/api/v1/login/status" ||
  path === "/api/v1/sso/callback" ||
  /^\/api\/v1\/organizations\/[^/]+\/sso\/authorize$/.test(path);
const blockedRoute = (path: string) =>
  /^\/api\/v1\/(?:auth\/tokens|silicon-auth|oauth|provider-webhooks|application-directory|obo-access)(?:\/|$)/.test(
    path,
  ) || path === "/api/v1/app-auth/tokens";
async function boundedBody(request: Request): Promise<Uint8Array<ArrayBuffer>> {
  if (Number(request.headers.get("content-length")) > 262144)
    throw new Error("body_limit");
  const reader = request.body?.getReader(),
    chunks: Uint8Array[] = [];
  let length = 0;
  if (reader)
    try {
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        length += part.value.byteLength;
        if (length > 262144) {
          await reader.cancel();
          throw new Error("body_limit");
        }
        chunks.push(part.value);
      }
    } finally {
      reader.releaseLock();
    }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}
export async function gateway(
  request: Request,
  env: Environment,
): Promise<Response> {
  let config: Settings;
  try {
    config = settings(env);
  } catch {
    return fail(
      "frontend_configuration",
      "The IAM frontend is not configured correctly.",
      503,
    );
  }
  const url = new URL(request.url),
    path = url.pathname;
  if (/%(?:2f|5c|00)/i.test(path))
    return fail(
      "invalid_path",
      "Encoded path separators are not supported.",
      400,
    );
  if (![config.console.origin, config.auth.origin].includes(url.origin))
    return fail("untrusted_host", "This frontend host is not allowed.", 403);
  if (path === "/api/web/telemetry") return collectTelemetry(request, env);
  if (path === "/api/config" && request.method === "GET")
    return finish(
      Response.json({
        telemetryEnabled: deploymentTelemetryEnabled(env),
        consoleOrigin: config.console.origin,
        authOrigin: config.auth.origin,
        environment:
          env.DISPLAY_ENVIRONMENT ||
          (isLoopback(config.upstream.hostname)
            ? "Local testing"
            : "Production"),
      }),
      config,
    );
  if (!path.startsWith("/api/") && !path.startsWith("/auth/")) {
    if (!env.ASSETS) return fail("not_found", "Page not found.", 404);
    let asset = await env.ASSETS.fetch(request);
    if (
      asset.status === 404 &&
      request.method === "GET" &&
      request.headers.get("accept")?.includes("text/html")
    )
      asset = await env.ASSETS.fetch(
        new Request(new URL("/index.html", url), request),
      );
    const response = await finish(asset, config);
    if (response.headers.get("content-type")?.includes("text/html"))
      response.headers.set(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
      );
    return response;
  }
  // SSO's exact callback intentionally allows a cross-site top-level GET.
  const navigation =
    request.method === "GET" &&
    (navigationRoute(path) || path === "/auth/continue");
  if (!navigation) {
    const originHeader = request.headers.get("origin");
    if (
      request.headers.get("x-iam-frontend") !== "1" ||
      request.headers.get("sec-fetch-site") === "cross-site" ||
      (originHeader && originHeader !== url.origin) ||
      (!["GET", "HEAD"].includes(request.method) && originHeader !== url.origin)
    )
      return finish(
        fail(
          "frontend_csrf",
          "This request must originate from the IAM frontend.",
          403,
        ),
        config,
      );
  }
  let session = await readSession(request, config),
    changed: Session | null | undefined;
  const publicRequest = isPublic(path, request.method);
  if (session && !publicRequest) {
    try {
      const fresh = await refreshed(session, config);
      if (fresh !== session) changed = fresh;
      session = fresh;
    } catch (error) {
      if (error instanceof RefreshRejected && error.status === 401)
        return finish(
          fail(
            "session_expired",
            "Your session has expired. Sign in again.",
            401,
          ),
          config,
          null,
        );
      return finish(
        fail(
          "refresh_unavailable",
          "IAM could not renew your session right now. Please retry; your session has been preserved.",
          503,
        ),
        config,
      );
    }
  }
  if (path === "/auth/continue") {
    const target = new URL("/login", config.auth);
    for (const key of [
      "app_id",
      "app_ids",
      "bundle_id",
      "redirect_uri",
      "org_id",
      "org_ids",
      "next",
    ]) {
      for (const value of url.searchParams.getAll(key))
        target.searchParams.append(key, value);
    }
    if (
      session &&
      !target.searchParams.has("app_id") &&
      !target.searchParams.has("app_ids") &&
      !target.searchParams.has("bundle_id")
    ) {
      // Only an explicit internal destination is accepted; never an arbitrary URL.
      const destination = new URL(
        url.searchParams.get("next") === "join" ? "/join" : "/",
        config.console,
      );
      const organization = url.searchParams.get("org_id");
      if (destination.pathname === "/join" && organization)
        destination.searchParams.set("org_id", organization);
      return finish(Response.redirect(destination, 303), config, changed);
    }
    return finish(Response.redirect(target, 303), config, changed);
  }
  if (path === "/api/session") {
    if (request.method !== "GET")
      return finish(
        fail("method_not_allowed", "Unsupported method.", 405),
        config,
      );
    if (!session)
      return finish(Response.json({ authenticated: false }), config);
    try {
      const response = await fetch(new URL("/api/v1/me", config.upstream), {
        headers: apiHeaders(request, session),
        redirect: "manual",
        signal: AbortSignal.timeout(15000),
      });
      if (response.status === 401)
        return finish(Response.json({ authenticated: false }), config, null);
      if (!response.ok) return finish(response, config, changed);
      return finish(
        Response.json({
          authenticated: true,
          user: await response.json(),
          sessionId: session.sessionId,
          expiresAt: session.expires,
        }),
        config,
        changed,
      );
    } catch {
      return finish(
        fail(
          "upstream_unavailable",
          "IAM is unavailable. Please try again.",
          502,
        ),
        config,
        changed,
      );
    }
  }
  if (path === "/api/test-application-view") {
    if (request.method !== "POST")
      return finish(
        fail("method_not_allowed", "Unsupported method.", 405),
        config,
        changed,
      );
    if (!session)
      return finish(
        fail("sign_in_required", "Sign in to continue.", 401),
        config,
        changed,
      );
    let input: Uint8Array<ArrayBuffer>;
    try {
      input = await boundedBody(request);
    } catch {
      return finish(
        fail("request_too_large", "Request exceeds the size limit.", 413),
        config,
        changed,
      );
    }
    return finish(await testApplicationView(input, config), config, changed);
  }
  if (
    !path.startsWith("/api/v1/") ||
    blockedRoute(path) ||
    !["GET", "POST", "PUT", "PATCH", "DELETE"].includes(request.method)
  )
    return finish(
      fail(
        "route_not_available",
        "This operation belongs in an application server, not a browser.",
        404,
      ),
      config,
    );
  if (!session && !isPublic(path, request.method)) {
    if (navigation) {
      const login = new URL("/login", config.auth);
      for (const key of [
        "app_id",
        "app_ids",
        "bundle_id",
        "redirect_uri",
        "org_id",
        "org_ids",
      ]) {
        for (const value of url.searchParams.getAll(key))
          login.searchParams.append(key, value);
      }
      return finish(Response.redirect(login, 303), config, null);
    }
    return finish(
      fail("sign_in_required", "Sign in to continue.", 401),
      config,
    );
  }
  const headers = apiHeaders(request, publicRequest ? null : session);
  let body: Uint8Array<ArrayBuffer> | undefined;
  if (!["GET", "HEAD"].includes(request.method)) {
    try {
      body = await boundedBody(request);
    } catch {
      return finish(
        fail("request_too_large", "Request exceeds the size limit.", 413),
        config,
      );
    }
    if (!headers.get("idempotency-key"))
      return finish(
        fail(
          "idempotency_key_required",
          "This request needs an idempotency key.",
          400,
        ),
        config,
      );
  }
  try {
    const response = await fetch(new URL(path + url.search, config.upstream), {
      method: request.method,
      headers,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(20000),
    });
    if (response.status >= 300 && response.status < 400) {
      if (!navigation)
        return finish(
          fail(
            "unexpected_redirect",
            "IAM returned an unexpected redirect.",
            502,
          ),
          config,
          changed,
        );
      const location = response.headers.get("location");
      if (!location)
        return finish(
          fail("invalid_redirect", "IAM returned an invalid destination.", 502),
          config,
          changed,
        );
      const redirect = new URL(location, config.upstream);
      if (
        redirect.protocol !== "https:" &&
        !(redirect.protocol === "http:" && isLoopback(redirect.hostname))
      )
        return finish(
          fail("unsafe_redirect", "IAM returned an unsafe destination.", 502),
          config,
          changed,
        );
      if (
        redirect.origin === config.upstream.origin &&
        navigationRoute(redirect.pathname)
      ) {
        redirect.host = url.host;
        redirect.protocol = url.protocol;
      }
      return finish(
        Response.redirect(redirect, response.status),
        config,
        changed,
      );
    }
    if (
      response.ok &&
      /^\/api\/v1\/login\/challenges\/[0-9a-f-]+\/verify$/.test(path)
    ) {
      const established = fromTokens(
        (await response.json()) as Record<string, unknown>,
        response,
      );
      return finish(
        Response.json({ authenticated: true, expiresAt: established.expires }),
        config,
        established,
      );
    }
    if (navigation && !response.ok) {
      let code = `iam_${response.status}`;
      try {
        const failure = (await response.json()) as {
          error?: { code?: string };
        };
        if (/^[a-z0-9_]{1,100}$/.test(failure.error?.code || ""))
          code = failure.error!.code!;
      } catch {
        /* Keep a generic non-sensitive error code. */
      }
      const target = new URL("/login", config.auth);
      for (const key of [
        "app_id",
        "app_ids",
        "bundle_id",
        "redirect_uri",
        "org_id",
        "org_ids",
      ]) {
        for (const value of url.searchParams.getAll(key))
          target.searchParams.append(key, value);
      }
      target.searchParams.set("auth_error", code);
      return finish(
        Response.redirect(target, 303),
        config,
        response.status === 401 ? null : changed,
      );
    }
    if (
      (path === "/api/v1/logout" && response.ok) ||
      (response.status === 401 && !!session && !publicRequest)
    )
      changed = null;
    return finish(response, config, changed);
  } catch {
    return finish(
      fail(
        "upstream_unavailable",
        "IAM could not confirm this request. Retry the same submission rather than creating a duplicate.",
        502,
      ),
      config,
      changed,
    );
  }
}
export default { fetch: gateway };
