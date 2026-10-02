import { createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { createResource } from "./resource";
import { ApiError, date, mutation, request, segment } from "./api";
import { oboConsentRequest } from "./obo-consent-link";
import {
  appendGrantPage,
  callerLabel,
  consentDetail,
  consentPending,
  decisionResult,
  safeOboRedirect,
  grantPage,
  type OboDecision,
  type OboEndpoint,
  type OboGrant,
} from "./obo-consent-model";
import { Badge, Empty, ErrorBox, Loading, PageTitle } from "./ui";
import OboContextPicker, { type OboContext } from "./OboContextPicker";

/** Every edge names its caller, including repeated targets reached on different branches. */
export function OboEndpointTree(props: {
  callerId: string;
  callerName: string;
  endpoints: OboEndpoint[];
}) {
  return (
    <ul
      class="obo-chain"
      aria-label={`Actions requested by ${props.callerName}`}
    >
      <For each={props.endpoints}>
        {(endpoint) => (
          <li>
            <article class="obo-chain-action">
              <p class="obo-call-route">
                <span>{callerLabel(props.callerId, props.callerName)}</span>
                <span aria-label="calls"> → </span>
                <strong>
                  {callerLabel(endpoint.audience, endpoint.app_name)}
                </strong>
              </p>
              <Show when={endpoint.name}>
                <h3>{endpoint.name}</h3>
              </Show>
              <p>{endpoint.description}</p>
              <Show when={endpoint.note_to_user}>
                <p class="endpoint-note">{endpoint.note_to_user}</p>
              </Show>
              <Show when={endpoint.additional_warnings?.length}>
                <div class="endpoint-warnings">
                  <For each={endpoint.additional_warnings}>
                    {(warning) => (
                      <span class="warning-chip">
                        {warning.replaceAll("_", " ")}
                      </span>
                    )}
                  </For>
                </div>
              </Show>
              <div class="actions">
                <code>{endpoint.obo_id || endpoint.endpoint_id}</code>
                <span
                  class={`badge ${endpoint.critical ? "scope-critical" : "scope-standard"}`}
                >
                  {endpoint.critical ? "Critical" : "Non-critical"}
                </span>
              </div>
            </article>
            <Show when={endpoint.downstream.length}>
              <OboEndpointTree
                callerId={endpoint.audience}
                callerName={endpoint.app_name}
                endpoints={endpoint.downstream}
              />
            </Show>
          </li>
        )}
      </For>
    </ul>
  );
}

export default function OboConsent() {
  const requestId = oboConsentRequest(new URL(location.href));
  const [detail, { refetch }] = createResource(async () => {
    if (!requestId)
      throw new Error(
        "This OBO consent link is invalid. Ask the application to start again.",
      );
    return consentDetail(
      await request(`/api/v1/obo-access/consents/${segment(requestId)}`),
      requestId,
    );
  });
  const [contexts, setContexts] = createSignal<OboContext[]>([]);
  const [contextsReady, setContextsReady] = createSignal(false);
  const [config] = createResource(() =>
    request<{ consoleOrigin: string }>("/api/config"),
  );
  const [busy, setBusy] = createSignal<"approve" | "decline">();
  const [error, setError] = createSignal<unknown>();
  const [decision, setDecision] = createSignal<OboDecision>();
  const [needsReview, setNeedsReview] = createSignal(false);
  const [copied, setCopied] = createSignal(false);
  const [now, setNow] = createSignal(Date.now());
  const send = mutation();
  let disposed = false;
  onMount(() => {
    const timer = setInterval(() => {
      setNow(Date.now());
      const result = decision();
      if (
        result?.authorization_code &&
        Date.parse(result.expires_at) <= Date.now()
      ) {
        setDecision({ ...result, authorization_code: undefined });
        setCopied(false);
      }
    }, 1000);
    onCleanup(() => clearInterval(timer));
  });
  onCleanup(() => {
    disposed = true;
  });
  const pending = () => !!detail() && consentPending(detail()!, now());
  async function reload() {
    if (busy()) return;
    setError();
    setNeedsReview(true);
    try {
      const loaded = await refetch();
      if (loaded && !disposed) setNeedsReview(false);
    } catch (cause) {
      if (!disposed) setError(cause);
    }
  }
  async function decide(value: "approve" | "decline") {
    if (
      !detail() ||
      !pending() ||
      busy() ||
      decision() ||
      needsReview() ||
      detail.loading ||
      (value === "approve" && !!detail()?.providers?.length && !contextsReady())
    )
      return;
    setBusy(value);
    setError();
    try {
      const result = decisionResult(
        await send(
          "POST",
          `/api/v1/obo-access/consents/${segment(detail()!.id)}/decision`,
          {
            decision: value,
            version: detail()!.version,
            ...(value === "approve" && detail()!.providers?.length
              ? { contexts: contexts() }
              : {}),
          },
        ),
        detail()!.id,
        value,
      );
      if (!disposed) {
        setDecision(result);
        const destination=safeOboRedirect(result.redirect_uri);
        if(destination) window.location.replace(destination);
      }
    } catch (cause) {
      if (!disposed) {
        setError(cause);
        if (cause instanceof ApiError && cause.status === 412)
          setNeedsReview(true);
      }
    } finally {
      if (!disposed) setBusy();
    }
  }
  async function copyCode() {
    if (
      !decision()?.authorization_code ||
      Date.parse(decision()!.expires_at) <= Date.now()
    )
      return;
    try {
      await navigator.clipboard.writeText(decision()!.authorization_code!);
      if (!disposed) setCopied(true);
    } catch {
      if (!disposed)
        setError(
          new Error(
            "The code could not be copied. Select it and copy it manually.",
          ),
        );
    }
  }
  return (
    <section class="stack obo-consent" aria-label="OBO permission request">
      <h2>Review actions on your behalf</h2>
      <ErrorBox error={detail.error} retry={() => void reload()} />
      <Show when={!detail.loading} fallback={<Loading />}>
        <Show when={detail()}>
          {(consent) => (
            <>
              <dl class="obo-context">
                <div>
                  <dt>Requesting application</dt>
                  <dd>{callerLabel(consent().app_id, consent().app_name)}</dd>
                </div>
                <div>
                  <dt>Acting as</dt>
                  <dd>
                    {consent().actor.public_id}{" "}
                    <small>({consent().actor.type})</small>
                  </dd>
                </div>
                <div>
                  <dt>Organization</dt>
                  <dd>{consent().org_id}</dd>
                </div>
              </dl>
              <div class="notice">
                <strong>Approval allows repeated use</strong>
                <p>
                  {consent().app_name} can repeat these actions while your
                  approval remains valid. Each action includes the dependent
                  calls shown below. You can revoke this access in IAM at any
                  time.
                </p>
              </div>
              <OboEndpointTree
                callerId={consent().app_id}
                callerName={consent().app_name}
                endpoints={consent().endpoints}
              />
              <Show when={consent().providers?.length && !decision()}>
                <OboContextPicker
                  providers={consent().providers!}
                  disabled={!!busy() || !pending()}
                  change={(items, ready) => {
                    setContexts(items);
                    setContextsReady(ready);
                  }}
                />
              </Show>
              <Show when={config()}>
                <p class="muted">
                  You can manage these permissions at any time in{" "}
                  <a
                    href={`${config()!.consoleOrigin}/obo-grants?app=${encodeURIComponent(consent().app_id)}`}
                  >
                    this application’s OBO settings
                  </a>
                  .
                </p>
              </Show>
              <ErrorBox error={error()} />
              <Show when={needsReview()}>
                <div class="notice" role="status">
                  <p>
                    The requested permissions changed. Reload and review the
                    complete chain before deciding.
                  </p>
                  <button
                    class="button"
                    type="button"
                    onClick={() => void reload()}
                  >
                    Reload permissions
                  </button>
                </div>
              </Show>
              <Show
                when={!decision()}
                fallback={
                  <div class="stack notice" role="status">
                    <strong>
                      {decision()?.status === "approved"
                        ? "Permissions approved"
                        : "Request declined"}
                    </strong>
                    <Show
                      when={decision()?.status === "approved"}
                      fallback={
                        <p>
                          Your ordinary application login remains available.
                        </p>
                      }
                    >
                      <Show
                        when={
                          decision()?.authorization_code &&
                          Date.parse(decision()!.expires_at) > now()
                        }
                        fallback={
                          <p>
                            The authorization code has expired. Return to{" "}
                            {consent().app_name} to request a new code.
                          </p>
                        }
                      >
                        <p>
                          Return this single-use authorization code to{" "}
                          {consent().app_name}. It expires{" "}
                          {date(decision()?.expires_at)}.
                        </p>
                        <label class="stack">
                          Authorization code
                          <textarea
                            class="obo-code"
                            rows={3}
                            readonly
                            autocomplete="off"
                            spellcheck={false}
                            value={decision()?.authorization_code || ""}
                            onFocus={(event) => event.currentTarget.select()}
                          />
                        </label>
                        <button
                          class="button primary"
                          type="button"
                          onClick={() => void copyCode()}
                        >
                          {copied() ? "Copied" : "Copy authorization code"}
                        </button>
                      </Show>
                    </Show>
                  </div>
                }
              >
                <Show
                  when={pending()}
                  fallback={
                    <div class="notice" role="status">
                      <strong>
                        {consent().status === "pending" ||
                        consent().status === "expired"
                          ? "This request has expired"
                          : `This request is ${consent().status}`}
                      </strong>
                      <p>
                        Return to {consent().app_name} to start a new request if
                        needed.
                      </p>
                    </div>
                  }
                >
                  <p class="muted">
                    Only approve if you want these actions. Declining leaves
                    your ordinary application login available. This request
                    expires {date(consent().expires_at)}.
                  </p>
                  <div class="actions">
                    <button
                      class="button"
                      type="button"
                      disabled={!!busy() || needsReview()}
                      onClick={() => void decide("decline")}
                    >
                      {busy() === "decline" ? "Declining…" : "Decline"}
                    </button>
                    <button
                      class="button primary"
                      type="button"
                      disabled={
                        !!busy() ||
                        needsReview() ||
                        (!!consent().providers?.length && !contextsReady())
                      }
                      onClick={() => void decide("approve")}
                    >
                      {busy() === "approve"
                        ? "Approving…"
                        : "Approve these actions"}
                    </button>
                  </div>
                </Show>
              </Show>
            </>
          )}
        </Show>
      </Show>
    </section>
  );
}

export function OboGrants() {
  const application = new URL(location.href).searchParams.get("app");
  const grantQuery = `limit=10${application ? `&app_id=${encodeURIComponent(application)}` : ""}`;
  const [grants, { refetch, mutate }] = createResource(async () =>
    grantPage(await request(`/api/v1/obo-access/grants?${grantQuery}`)),
  );
  const [moreBusy, setMoreBusy] = createSignal(false);
  const [selected, setSelected] = createSignal<string>();
  const [busy, setBusy] = createSignal<string>();
  const [error, setError] = createSignal<unknown>();
  const [notice, setNotice] = createSignal("");
  const send = mutation();
  async function loadMore() {
    const cursor = grants()?.page.next_cursor;
    if (
      !cursor ||
      !grants()?.page.has_more ||
      grants.loading ||
      moreBusy() ||
      busy()
    )
      return;
    setMoreBusy(true);
    setError();
    try {
      const next = grantPage(
        await request(
          `/api/v1/obo-access/grants?${grantQuery}&cursor=${segment(cursor)}`,
        ),
      );
      mutate((current) =>
        current?.page.next_cursor === cursor
          ? appendGrantPage(current, next)
          : current,
      );
    } catch (cause) {
      setError(cause);
    } finally {
      setMoreBusy(false);
    }
  }
  async function revoke(grant: OboGrant) {
    if (busy() || moreBusy()) return;
    setBusy(grant.id);
    setError();
    setNotice("");
    try {
      const result = await send<{ id: string; status: string }>(
        "POST",
        `/api/v1/obo-access/grants/${segment(grant.id)}/revoke`,
      );
      if (result.id !== grant.id || result.status !== "revoked")
        throw new Error(
          "IAM could not confirm the revocation. Retry to check this grant.",
        );
      mutate(
        (current) =>
          current && {
            ...current,
            items: current.items.map((item) =>
              item.id === grant.id ? { ...item, status: "revoked" } : item,
            ),
          },
      );
      setSelected();
      setNotice(
        `Access to ${grant.endpoint_id} for ${grant.app_name} has been revoked, including its downstream calls.`,
      );
    } catch (cause) {
      setError(cause);
    } finally {
      setBusy();
    }
  }
  return (
    <>
      <PageTitle
        title="Actions on your behalf"
        subtitle={
          application
            ? `Review and revoke actions approved for ${application}.`
            : "Review and revoke the actions you have approved for applications."
        }
      />
      <p class="muted">
        These approvals allow repeated use of the actions and dependent calls
        shown. Revocation ends their access immediately; your ordinary
        application login stays available.
      </p>
      <ErrorBox error={grants.error} retry={() => void refetch()} />
      <ErrorBox error={error()} />
      <Show when={notice()}>
        <div class="notice success" role="status">
          {notice()}
        </div>
      </Show>
      <Show when={!grants.loading} fallback={<Loading />}>
        <Show
          when={grants()?.items.length}
          fallback={
            !grants.error && (
              <Empty title="No OBO approvals">
                Applications will appear here after you approve actions they
                request.
              </Empty>
            )
          }
        >
          <div class="stack obo-grants">
            <For each={grants()?.items}>
              {(grant) => (
                <article class="panel padded stack">
                  <div class="section-heading">
                    <div>
                      <h2>{grant.app_name}</h2>
                      <small>
                        {grant.app_id} · Organization {grant.org_id}
                      </small>
                    </div>
                    <Badge
                      value={
                        grant.status === "active" &&
                        !!grant.expires_at &&
                        Date.parse(grant.expires_at) <= Date.now()
                          ? "expired"
                          : grant.status
                      }
                    />
                  </div>
                  <p class="muted">
                    Approved {date(grant.created_at)} ·{" "}
                    {grant.expires_at ? "Expires " : ""}
                    {grant.expires_at
                      ? date(grant.expires_at)
                      : "Until revoked"}
                  </p>
                  <OboEndpointTree
                    callerId={grant.app_id}
                    callerName={grant.app_name}
                    endpoints={grant.endpoints}
                  />
                  <Show
                    when={
                      grant.status === "active" &&
                      (!grant.expires_at ||
                        Date.parse(grant.expires_at) > Date.now())
                    }
                  >
                    <Show
                      when={selected() === grant.id}
                      fallback={
                        <button
                          class="button danger align-start"
                          type="button"
                          disabled={!!busy() || moreBusy()}
                          onClick={() => {
                            setSelected(grant.id);
                            setError();
                          }}
                        >
                          Revoke access
                        </button>
                      }
                    >
                      <div class="notice">
                        <p>
                          Stop {grant.app_name} from using {grant.endpoint_id}{" "}
                          and all of its dependent calls for {grant.org_id}?
                        </p>
                        <div class="actions">
                          <button
                            class="button"
                            type="button"
                            disabled={!!busy() || moreBusy()}
                            onClick={() => setSelected()}
                          >
                            Keep access
                          </button>
                          <button
                            class="button danger"
                            type="button"
                            disabled={!!busy() || moreBusy()}
                            onClick={() => void revoke(grant)}
                          >
                            {busy() === grant.id
                              ? "Revoking…"
                              : "Confirm revocation"}
                          </button>
                        </div>
                      </div>
                    </Show>
                  </Show>
                </article>
              )}
            </For>
          </div>
        </Show>
        <Show when={grants()?.page.has_more}>
          <button
            class="button"
            type="button"
            disabled={moreBusy() || !!busy()}
            onClick={() => void loadMore()}
          >
            {moreBusy() ? "Loading…" : "Load more"}
          </button>
        </Show>
      </Show>
    </>
  );
}
