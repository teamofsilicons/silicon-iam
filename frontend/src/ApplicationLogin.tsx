import { createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { mutation, request } from "./api";
import {
  loginApplications,
  loginCallback,
  tokenDestination,
  type LoginToken,
} from "./login-flow";
import { ErrorBox } from "./ui";
import { ScopeList } from "./Scopes";
import { validateConsent, type ScopeDescriptor } from "./scope-model";

type Organization = { org_id: string; name: string; authorized: boolean };
type Choices = {
  app_id: string;
  app_name?: string;
  items: Organization[];
  consent_required: boolean;
  scope_version: number;
  scopes: ScopeDescriptor[];
};
type Bundle = { bundle_id: string; app_name?: string; app_ids: string[] };

/** One IAM session approves independent, explicitly selected grants per app. */
export default function ApplicationLogin() {
  const [choices, setChoices] = createSignal<Choices[]>([]);
  const [selected, setSelected] = createSignal<Record<string, string[]>>({});
  const [bundle, setBundle] = createSignal<Bundle>();
  const [step, setStep] = createSignal<
    "validate" | "consent" | "select" | "loading" | "done"
  >("validate");
  const [error, setError] = createSignal<unknown>();
  const [tokens, setTokens] = createSignal<LoginToken[]>([]);
  const [expired, setExpired] = createSignal(false);
  const send = mutation();
  let batch = false;
  let destination: URL | undefined;
  let disposed = false;
  let expiryTimer: ReturnType<typeof setTimeout> | undefined;
  onCleanup(() => {
    disposed = true;
    clearTimeout(expiryTimer);
  });
  onMount(async () => {
    try {
      const params = new URL(location.href).searchParams;
      const parsed = loginApplications(params);
      batch = parsed.batch;
      destination = loginCallback(params.get("redirect_uri"));
      const bundled = parsed.bundleId
        ? await request<{ bundle: Bundle; items: Choices[] }>(
            `/api/v1/app-auth/bundles/${encodeURIComponent(parsed.bundleId)}/organizations`,
          )
        : undefined;
      const values = bundled
        ? bundled.items
        : batch
          ? (
              await request<{ items: Choices[] }>(
                `/api/v1/app-auth/batch/organizations?app_ids=${encodeURIComponent(parsed.ids.join(","))}`,
              )
            ).items
          : [
              await request<Choices>(
                `/api/v1/app-auth/organizations?app_id=${encodeURIComponent(parsed.ids[0])}`,
              ),
            ];
      if (disposed) return;
      validateConsent(values);
      if (bundled) setBundle(bundled.bundle);
      setChoices(values);
      const sharedExisting = bundled
        ? [
            ...new Set(
              values.flatMap((app) =>
                app.items
                  .filter((org) => org.authorized)
                  .map((org) => org.org_id),
              ),
            ),
          ].filter((orgId) =>
            values.every((app) =>
              app.items.some((org) => org.org_id === orgId),
            ),
          )
        : undefined;
      setSelected(
        Object.fromEntries(
          values.map((app) => [
            app.app_id,
            sharedExisting ??
              app.items
                .filter((org) => org.authorized)
                .map((org) => org.org_id),
          ]),
        ),
      );
    } catch (err) {
      if (!disposed) setError(err);
    }
  });
  const canApprove = () =>
    choices().length > 0 &&
    choices().every((app) => selected()[app.app_id]?.length);
  const needsConsent = () =>
    choices().some((app) => app.consent_required !== false);
  const sharedChoices = () =>
    bundle()
      ? [
          {
            ...choices()[0],
            app_id: bundle()!.bundle_id,
            app_name: bundle()!.app_name,
            items: choices()[0]
              .items.filter((org) =>
                choices().every((app) =>
                  app.items.some((item) => item.org_id === org.org_id),
                ),
              )
              .map((org) => ({
                ...org,
                authorized: choices().some((app) =>
                  app.items.some(
                    (item) => item.org_id === org.org_id && item.authorized,
                  ),
                ),
              })),
          },
        ]
      : choices();
  const selectedFor = (id: string) =>
    bundle()
      ? [...new Set(choices().flatMap((app) => selected()[app.app_id] || []))]
      : selected()[id] || [];
  function choose(appId: string, ids: string[]) {
    const idsToChange = bundle() ? choices().map((app) => app.app_id) : [appId];
    setSelected((current) => ({
      ...current,
      ...Object.fromEntries(idsToChange.map((id) => [id, ids])),
    }));
  }
  const consentGroups = () =>
    bundle()
      ? [
          {
            app_id: bundle()!.bundle_id,
            app_name: bundle()!.app_name,
            scopes: [
              ...new Map(
                choices()
                  .filter((app) => app.consent_required !== false)
                  .flatMap((app) => app.scopes)
                  .map((scope) => [scope.scope, scope]),
              ).values(),
            ],
          },
        ]
      : choices().filter((app) => app.consent_required !== false);
  async function approve() {
    if (step() !== "select" || !canApprove()) return;
    setError();
    setStep("loading");
    const started = Date.now();
    try {
      const applications = choices().map((app) => ({
        app_id: app.app_id,
        org_ids: selected()[app.app_id],
        approved_scopes: app.scopes.map((scope) => scope.scope),
        scope_version: app.scope_version,
      }));
      const callback = destination ? { redirect_uri: destination.href } : {};
      const result = batch
        ? await send<{ items: LoginToken[] }>(
            "POST",
            bundle()
              ? `/api/v1/app-auth/bundles/${encodeURIComponent(bundle()!.bundle_id)}/short-lived-tokens`
              : "/api/v1/app-auth/batch/short-lived-tokens",
            { applications, ...callback },
          )
        : {
            items: [
              {
                ...(await send("POST", "/api/v1/app-auth/short-lived-tokens", {
                  ...applications[0],
                  ...callback,
                })),
                app_id: applications[0].app_id,
              } as LoginToken,
            ],
          };
      if (disposed) return;
      const remaining = Math.min(
        ...result.items.map((item) =>
          item.expires_at
            ? Date.parse(item.expires_at) - Date.now()
            : item.expires_in * 1000 - (Date.now() - started),
        ),
      );
      if (remaining <= 0) {
        setExpired(true);
        setStep("done");
        return;
      }
      setStep("done");
      if (destination) {
        location.assign(tokenDestination(destination, result.items, batch));
      } else {
        setTokens(result.items);
        expiryTimer = setTimeout(() => {
          setTokens([]);
          setExpired(true);
        }, remaining);
      }
    } catch (err) {
      if (!disposed) {
        setError(err);
        setStep("select");
      }
    }
  }
  return (
    <div class="stack">
      <ErrorBox error={error()} />
      <Show
        when={choices().length}
        fallback={
          <p role="status">
            {error()
              ? "Sign-in has not been authorized."
              : "Validating applications…"}
          </p>
        }
      >
        <Show when={step() === "validate"}>
          <div class="notice">
            <strong>
              {bundle()
                ? "Connect application bundle"
                : choices().length === 1
                  ? "Connect application"
                  : `Connect ${choices().length} applications`}
            </strong>
            <p>
              You decide which organizations each app can read. Your credentials
              stay in IAM.
            </p>
            <ul>
              <For
                each={
                  bundle()
                    ? [
                        {
                          app_id: bundle()!.bundle_id,
                          app_name: bundle()!.app_name,
                        },
                      ]
                    : choices()
                }
              >
                {(app) => (
                  <li>
                    <strong>{app.app_name || app.app_id}</strong>
                    <small> · {app.app_id}</small>
                  </li>
                )}
              </For>
            </ul>
            <Show when={destination}>
              <p>Return to: {destination?.origin}</p>
            </Show>
          </div>
          <button
            class="button primary"
            onClick={() => setStep(needsConsent() ? "consent" : "select")}
          >
            {needsConsent() ? "Review permissions" : "Choose organizations"}
          </button>
        </Show>
        <Show when={step() === "consent"}>
          <h2>Review requested permissions</h2>
          <p>
            Continuing approves these permissions for the organizations you
            choose next. Critical permissions include access to other members or
            sensitive application actions.
          </p>
          <For each={consentGroups()}>
            {(app) => (
              <section class="stack">
                <h3>{app.app_name || app.app_id}</h3>
                <ScopeList items={app.scopes} />
              </section>
            )}
          </For>
          <div class="actions">
            <button class="button" onClick={() => setStep("validate")}>
              Back
            </button>
            <button class="button primary" onClick={() => setStep("select")}>
              Approve permissions & choose organizations
            </button>
          </div>
        </Show>
        <Show when={["select", "loading", "done"].includes(step())}>
          <p>
            Share at least one organization with each app. Existing access is
            kept; future memberships are not shared automatically.
          </p>
          <Show when={choices().length > 1 && !bundle()}>
            <button
              type="button"
              class="text-button"
              disabled={step() !== "select"}
              onClick={() =>
                setSelected(
                  Object.fromEntries(
                    choices().map((app) => [
                      app.app_id,
                      app.items.map((org) => org.org_id),
                    ]),
                  ),
                )
              }
            >
              Share all current organizations with every listed app
            </button>
          </Show>
          <For each={sharedChoices()}>
            {(app) => (
              <fieldset
                disabled={step() !== "select"}
                class="stack organization-consent"
              >
                <legend>{app.app_name || app.app_id}</legend>
                <small>{app.app_id}</small>
                <Show
                  when={app.items.length}
                  fallback={
                    <p>
                      Join or create an organization in IAM, then return here to
                      sign in.
                    </p>
                  }
                >
                  <button
                    type="button"
                    class="text-button"
                    onClick={() =>
                      choose(
                        app.app_id,
                        app.items.map((org) => org.org_id),
                      )
                    }
                  >
                    Select all current organizations for this app
                  </button>
                  <For each={app.items}>
                    {(org) => (
                      <label class="organization-choice">
                        <input
                          type="checkbox"
                          checked={selectedFor(app.app_id).includes(org.org_id)}
                          disabled={org.authorized}
                          onChange={(event) => {
                            const checked = event.currentTarget.checked;
                            choose(
                              app.app_id,
                              checked
                                ? [...selectedFor(app.app_id), org.org_id]
                                : selectedFor(app.app_id).filter(
                                    (id) => id !== org.org_id,
                                  ),
                            );
                          }}
                        />
                        <span>
                          <strong>{org.name}</strong>
                          <small>
                            {org.org_id}
                            {org.authorized
                              ? bundle()
                                ? " · Already authorized for a member"
                                : " · Already authorized"
                              : ""}
                          </small>
                        </span>
                      </label>
                    )}
                  </For>
                </Show>
              </fieldset>
            )}
          </For>
          <p class="muted">
            Each application receives only its declared, approved permissions in
            your selected organizations. Your IAM authentication credentials
            stay in IAM.
          </p>
          <Show when={step() === "select" && needsConsent()}>
            <button class="text-button" onClick={() => setStep("consent")}>
              Review permissions again
            </button>
          </Show>
          <button
            type="button"
            class="button primary handoff-button"
            classList={{ "handoff-ready": step() === "done" }}
            disabled={!canApprove() || step() !== "select"}
            aria-busy={step() === "loading"}
            onClick={() => void approve()}
          >
            <span class="handoff-label" role="status" aria-live="polite">
              <Show when={step() === "loading"}>
                <span class="handoff-spinner" aria-hidden="true" />
              </Show>
              {step() === "done"
                ? "✓ Authorized"
                : step() === "loading"
                  ? "Authorizing…"
                  : `Authorize ${bundle() ? "bundle" : choices().length === 1 ? "application" : `${choices().length} applications`}`}
            </span>
          </button>
          <For each={tokens()}>
            {(token) => (
              <div class="notice">
                <strong>{token.app_id}</strong>
                <p>
                  If requested, give this short-lived token only to this
                  application.
                </p>
                <code class="login-token">{token.slt}</code>
                <p>Valid for one exchange and at most two minutes.</p>
                <Show when={token.request_id}>
                  <a
                    href={`/api/v1/login/status?request=${encodeURIComponent(token.request_id!)}`}
                  >
                    Check sign-in status
                  </a>
                </Show>
              </div>
            )}
          </For>
          <Show when={expired()}>
            <p role="status">Tokens expired. Reload to start a new sign-in.</p>
          </Show>
        </Show>
      </Show>
    </div>
  );
}
