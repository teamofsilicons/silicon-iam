import { collectTelemetry, deploymentTelemetryEnabled } from "./telemetry.ts";
import { testApplicationView } from "./test-view.ts";
import {
  scopeReviewDestination,
  scopeReviewRequest,
} from "../src/scope-review-link.ts";
import {
  oboConsentDestination,
  oboConsentRequest,
} from "../src/obo-consent-link.ts";
import {
  apiHeaders,
  fail,
  finish as finishResponse,
  accountResponse,
  forgetAccountResponse,
  readAccounts,
  MAX_ACCOUNTS,
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
    (path === "/api/v1/silicon-auth/token" ||
      path === "/api/v1/silicon-signup/requests" ||
      path === "/api/silicon-signup/status" ||
      /^\/api\/v1\/signup\/social\/(?:google|apple)\/(?:start|status)$/.test(
        path,
      ) ||
      /^\/api\/v1\/login\/social\/(?:google|apple)\/(?:start|status|complete)$/.test(
        path,
      ) ||
      /^\/api\/v1\/signup\/sessions(?:\/[0-9a-f-]+\/(?:email|phone)(?:\/verify)?|\/[0-9a-f-]+\/complete)?$/.test(
        path,
      ) ||
      /^\/api\/v1\/login\/challenges(?:\/[0-9a-f-]+\/verify)?$/.test(path))) ||
  (method === "DELETE" &&
    /^\/api\/v1\/signup\/sessions\/[0-9a-f-]+\/phone$/.test(path)) ||
  (method === "GET" &&
    (/^\/api\/v1\/(?:carbon-ids|organization-ids)\/[^/]+\/availability$/.test(
      path,
    ) ||
      path === "/api/v1/version" ||
      path === "/api/v1/signup/social/providers"));
const navigationRoute = (path: string) =>
  path === "/api/v1/login" ||
  path === "/api/v1/login/status" ||
  path === "/api/v1/sso/callback" ||
  /^\/api\/v1\/organizations\/[^/]+\/sso\/authorize$/.test(path);
const userOboRoute = (path: string, method: string) =>
  (method === "GET" && path === "/api/v1/obo-access/grants") ||
  (method === "GET" &&
    /^\/api\/v1\/obo-access\/consents\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(
      path,
    )) ||
  (method === "POST" &&
    /^\/api\/v1\/obo-access\/(?:consents\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/decision|grants\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/revoke)$/i.test(
      path,
    ));
const blockedRoute = (path: string, method: string) =>
  (path.startsWith("/api/v1/obo-access") && !userOboRoute(path, method)) ||
  (path !== "/api/v1/silicon-auth/token" &&
    !(path === "/api/v1/silicon-auth/step-up" && method === "POST") &&
    /^\/api\/v1\/(?:auth\/tokens|silicon-auth|oauth|provider-webhooks|application-directory)(?:\/|$)/.test(
      path,
    )) ||
  path === "/api/v1/app-auth/tokens";
const BODY_LIMIT = 262144;
// Organization logos are raw images; IAM itself caps them at 512 KiB.
const LOGO_BODY_LIMIT = 532480;
export const bodyLimit = (path: string, method: string) =>
  method === "PUT" &&
  (path === "/api/v1/me/photo" ||
    /^\/api\/v1\/organizations\/[^/]+\/logo$/.test(path))
    ? LOGO_BODY_LIMIT
    : BODY_LIMIT;
async function boundedBody(
  request: Request,
  limit = BODY_LIMIT,
): Promise<Uint8Array<ArrayBuffer>> {
  if (Number(request.headers.get("content-length")) > limit)
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
        if (length > limit) {
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
  const accountUpdates: Session[] = [];
  const accountRemovals: string[] = [];
  async function finish(
    response: Response,
    settings: Settings,
    value?: Session | null,
  ) {
    let result = await finishResponse(response, settings, value);
    for (const updated of accountUpdates)
      result = await accountResponse(result, settings, updated);
    for (const id of accountRemovals)
      result = forgetAccountResponse(result, settings, id);
    return result;
  }
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
  const scopeRequest = scopeReviewRequest(url);
  const oboRequest = oboConsentRequest(url);
  if (
    request.method === "GET" &&
    path === "/obo/consent" &&
    oboRequest &&
    url.origin !== config.auth.origin
  )
    return finish(
      Response.redirect(
        oboConsentDestination(
          oboRequest,
          config.auth.origin,
          url.searchParams.get("display") === "popup",
        ),
        303,
      ),
      config,
    );
  if (
    request.method === "GET" &&
    scopeRequest &&
    (path === "/applications" ||
      (path === "/scope-reviews" && url.origin !== config.console.origin))
  )
    return finish(
      Response.redirect(
        scopeReviewDestination(scopeRequest, config.console.origin),
        303,
      ),
      config,
    );
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
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
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
  config.selectedAccount = request.headers.get("x-iam-account") || undefined;
  let session = await readSession(request, config),
    changed: Session | null | undefined;
  const publicRequest = isPublic(path, request.method);
  const requestedKind = request.headers.get("x-iam-identity-kind");
  const typedLoginRoute =
    /^\/api\/v1\/app-auth\/(?:organizations|short-lived-tokens|batch\/(?:organizations|short-lived-tokens)|bundles\/[^/]+\/(?:organizations|short-lived-tokens))$/.test(
      path,
    );
  if (typedLoginRoute && requestedKind !== null) {
    if (!["carbon", "silicon"].includes(requestedKind))
      return finish(
        fail(
          "invalid_identity_kind",
          "Choose Carbon or Silicon for this sign-in.",
          400,
        ),
        config,
      );
    if (session && session.actorType !== requestedKind)
      return finish(
        fail(
          "identity_kind_mismatch",
          "Choose an account of the requested type to continue.",
          403,
        ),
        config,
      );
  }

  if (
    session &&
    !publicRequest &&
    path !== "/api/accounts" &&
    !/^\/api\/accounts\//.test(path)
  ) {
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
  const refreshFailure = (error: unknown) => {
    if (!(error instanceof RefreshRejected)) return undefined;
    const expired = error.status === 401;
    return finish(
      fail(
        expired ? "session_expired" : "refresh_unavailable",
        expired
          ? "Your session has expired. Sign in again."
          : "IAM could not renew your session right now. Please retry; your session has been preserved.",
        expired ? 401 : 503,
      ),
      config,
      expired ? null : changed,
    );
  };
  async function authenticatedFetch(target: URL, init: RequestInit) {
    let response = await fetch(target, init);
    if (response.status === 401 && session && !publicRequest) {
      // The saved expiry can be stale (replayed credentials or clock drift).
      // Retry once with the same request body and mutation key after renewal.
      await response.body?.cancel();
      session = await refreshed(session, config, true);
      changed = session;
      const headers = new Headers(init.headers);
      headers.set("Authorization", `Bearer ${session.access}`);
      if (session.browserCookie) headers.set("Cookie", session.browserCookie);
      response = await fetch(target, { ...init, headers });
    }
    return response;
  }
  if (path === "/auth/continue") {
    const target = new URL("/login", config.auth);
    for (const key of [
      "app_id",
      "app_ids",
      "bundle_id",
      "identity_kind",
      "display",
      "redirect_uri",
      "org_id",
      "org_ids",
      "next",
      "request",
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
        url.searchParams.get("next") === "join"
          ? "/join"
          : url.searchParams.get("next") === "obo-grants"
            ? "/obo-grants"
            : url.searchParams.get("next") === "silicon-custody"
              ? "/silicon-custody"
              : "/",
        config.console,
      );
      if (url.searchParams.get("next") === "obo-consent")
        return finish(
          oboRequest
            ? Response.redirect(
                oboConsentDestination(
                  oboRequest,
                  config.auth.origin,
                  url.searchParams.get("display") === "popup",
                ),
                303,
              )
            : fail(
                "invalid_request",
                "This OBO consent link is invalid. Ask the application to start again.",
                400,
              ),
          config,
          changed,
        );
      if (url.searchParams.get("next") === "scope-reviews" && scopeRequest)
        return finish(
          Response.redirect(
            scopeReviewDestination(scopeRequest, config.console.origin),
            303,
          ),
          config,
          changed,
        );
      if (destination.pathname === "/silicon-custody") {
        const custodyRequest = url.searchParams.get("request") || "";
        if (
          /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(custodyRequest)
        )
          destination.searchParams.set("request", custodyRequest);
      }
      const organization = url.searchParams.get("org_id");
      if (destination.pathname === "/join" && organization)
        destination.searchParams.set("org_id", organization);
      return finish(Response.redirect(destination, 303), config, changed);
    }
    return finish(Response.redirect(target, 303), config, changed);
  }
  if (path === "/api/silicon-signup/status" && request.method === "POST") {
    try {
      const input = JSON.parse(
        new TextDecoder().decode(await boundedBody(request, 4096)),
      );
      if (
        typeof input.request_id !== "string" ||
        !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(
          input.request_id,
        ) ||
        typeof input.poll_token !== "string" ||
        input.poll_token.length < 20 ||
        input.poll_token.length > 512 ||
        /[\r\n]/.test(input.poll_token)
      )
        return finish(
          fail("invalid_request", "This signup request is invalid.", 400),
          config,
        );
      const response = await fetch(
        new URL(
          `/api/v1/silicon-signup/requests/${input.request_id}`,
          config.upstream,
        ),
        {
          headers: {
            Authorization: `Bearer ${input.poll_token}`,
            Accept: "application/json",
          },
          redirect: "manual",
          signal: AbortSignal.timeout(15000),
        },
      );
      if (response.status >= 300 && response.status < 400)
        return finish(
          fail(
            "unexpected_redirect",
            "IAM returned an unexpected response.",
            502,
          ),
          config,
        );
      return finish(response, config);
    } catch {
      return finish(
        fail(
          "signup_unavailable",
          "IAM could not check this signup. Please retry.",
          503,
        ),
        config,
      );
    }
  }
  if (path === "/api/accounts" && request.method === "GET") {
    const saved = await readAccounts(request, config);
    const accounts = await Promise.all(
      saved.map(async (account) => {
        try {
          let current = await refreshed(account, config);
          let response = await fetch(new URL("/api/v1/me", config.upstream), {
            headers: apiHeaders(request, current),
            redirect: "manual",
            signal: AbortSignal.timeout(15000),
          });
          if (response.status === 401) {
            current = await refreshed(current, config, true);
            response = await fetch(new URL("/api/v1/me", config.upstream), {
              headers: apiHeaders(request, current),
              redirect: "manual",
              signal: AbortSignal.timeout(15000),
            });
          }
          if (current !== account) accountUpdates.push(current);
          if (!response.ok)
            return { account_id: account.sessionId, unavailable: true };
          return {
            account_id: account.sessionId,
            type: current.actorType || "carbon",
            user: await response.json(),
          };
        } catch (error) {
          return {
            account_id: account.sessionId,
            expired: error instanceof RefreshRejected && error.status === 401,
            unavailable: true,
          };
        }
      }),
    );
    return finish(
      Response.json({
        items: accounts,
        active_account_id: config.activeSessionId,
        maximum_accounts: MAX_ACCOUNTS,
      }),
      config,
    );
  }
  const removeAccount = /^\/api\/accounts\/([A-Za-z0-9_-]{1,80})$/.exec(path);
  if (removeAccount && request.method === "DELETE") {
    config.selectedAccount = removeAccount[1];
    return finish(Response.json({ removed: true }), config, null);
  }
  if (path === "/api/accounts/select" && request.method === "POST") {
    try {
      const input = JSON.parse(
        new TextDecoder().decode(await boundedBody(request)),
      ) as { account_id?: string };
      const selected = (await readAccounts(request, config)).find(
        (item) => item.sessionId === input.account_id,
      );
      if (!selected)
        return finish(
          fail("account_not_configured", "Sign in to this account again.", 401),
          config,
        );
      const current = await refreshed(selected, config);
      config.selectedAccount = undefined;
      return finish(
        Response.json({ authenticated: true, account_id: current.sessionId }),
        config,
        current,
      );
    } catch {
      return finish(
        fail(
          "account_unavailable",
          "This account could not be selected. Please retry.",
          503,
        ),
        config,
      );
    }
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
      const response = await authenticatedFetch(
        new URL("/api/v1/me", config.upstream),
        {
          headers: apiHeaders(request, session),
          redirect: "manual",
          signal: AbortSignal.timeout(15000),
        },
      );
      if (response.status === 401)
        return finish(
          fail(
            "session_unconfirmed",
            "IAM could not confirm your session. Please retry.",
            503,
          ),
          config,
          changed,
        );
      if (!response.ok) return finish(response, config, changed);
      return finish(
        Response.json({
          authenticated: true,
          user: await response.json(),
          accountId: session.sessionId,
          actorType: session.actorType || "carbon",
          sessionId: session.sessionId,
          expiresAt: session.expires,
        }),
        config,
        changed,
      );
    } catch (error) {
      const rejection = refreshFailure(error);
      if (rejection) return rejection;
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
    blockedRoute(path, request.method) ||
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
        "identity_kind",
        "display",
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
  if (
    publicRequest &&
    request.method === "POST" &&
    (/\/login\/challenges\/[^/]+\/verify$|\/complete$/.test(path) ||
      path === "/api/v1/silicon-auth/token") &&
    (await readAccounts(request, config)).length >= MAX_ACCOUNTS
  )
    return finish(
      fail(
        "account_limit",
        "This browser has eight configured accounts. Sign out of an account before adding another.",
        409,
      ),
      config,
    );
  const headers = apiHeaders(request, publicRequest ? null : session);
  let body: Uint8Array<ArrayBuffer> | undefined;
  if (!["GET", "HEAD"].includes(request.method)) {
    try {
      body = await boundedBody(request, bodyLimit(path, request.method));
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
    if (
      body &&
      request.method === "POST" &&
      /^\/api\/v1\/obo-access\/consents\/[^/]+\/decision$/.test(path)
    ) {
      let input: Record<string, unknown>;
      try {
        input = JSON.parse(new TextDecoder().decode(body));
      } catch {
        return finish(
          fail("invalid_request", "The permission request is unreadable.", 400),
          config,
          changed,
        );
      }
      if (input.contexts !== undefined) {
        if (!Array.isArray(input.contexts) || input.contexts.length > 100)
          return finish(
            fail(
              "invalid_contexts",
              "Choose an account and organization for each application.",
              400,
            ),
            config,
            changed,
          );
        const accounts = await readAccounts(request, config);
        const contexts = [];
        for (const context of input.contexts) {
          if (
            !context ||
            typeof context !== "object" ||
            context.account_token !== undefined ||
            typeof context.app_id !== "string" ||
            typeof context.org_id !== "string" ||
            typeof context.account_id !== "string"
          )
            return finish(
              fail(
                "invalid_contexts",
                "Choose a configured account for every application.",
                400,
              ),
              config,
              changed,
            );
          const account = accounts.find(
            (item) => item.sessionId === context.account_id,
          );
          if (!account)
            return finish(
              fail(
                "account_not_configured",
                "Sign in to the selected account again before approving.",
                401,
              ),
              config,
              changed,
            );
          const current = await refreshed(account, config);
          if (current !== account) accountUpdates.push(current);
          contexts.push({
            app_id: context.app_id,
            org_id: context.org_id,
            account_token: current.access,
          });
        }
        body = new TextEncoder().encode(JSON.stringify({ ...input, contexts }));
      }
    }
    const response = await authenticatedFetch(
      new URL(path + url.search, config.upstream),
      {
        method: request.method,
        headers,
        body,
        redirect: "manual",
        signal: AbortSignal.timeout(20000),
      },
    );
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
      (/^\/api\/v1\/login\/challenges\/[0-9a-f-]+\/verify$/.test(path) ||
        /^\/api\/v1\/login\/social\/(?:google|apple)\/complete$/.test(path) ||
        /^\/api\/v1\/signup\/sessions\/[0-9a-f-]+\/complete$/.test(path) ||
        path === "/api/v1/silicon-auth/token")
    ) {
      const value = (await response.json()) as Record<string, unknown>;
      const established = fromTokens(value, response);
      const saved = await readAccounts(request, config);
      for (const account of saved) {
        if (account.sessionId === established.sessionId) continue;
        if (
          established.actorId &&
          account.actorId === established.actorId &&
          account.actorType === established.actorType
        )
          accountRemovals.push(account.sessionId);
        else accountUpdates.push(account);
      }
      config.selectedAccount = undefined;
      // Updating the previous account's saved cookie must not select it again
      // after this response establishes a different active identity.
      config.activeSessionId = established.sessionId;
      return finish(
        Response.json({
          authenticated: true,
          account_id: established.sessionId,
          expiresAt: established.expires,
          onboarding: value.onboarding,
        }),
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
        "identity_kind",
        "display",
        "redirect_uri",
        "org_id",
        "org_ids",
      ]) {
        for (const value of url.searchParams.getAll(key))
          target.searchParams.append(key, value);
      }
      target.searchParams.set("auth_error", code);
      return finish(Response.redirect(target, 303), config, changed);
    }
    if (path === "/api/v1/logout" && response.ok) changed = null;
    return finish(response, config, changed);
  } catch (error) {
    const rejection = refreshFailure(error);
    if (rejection) return rejection;
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
