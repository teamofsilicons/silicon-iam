import { createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { mutation, request } from "./api";
import { ErrorBox } from "./ui";

type Organization = { org_id: string; name: string; authorized: boolean };
type Choices = { app_id: string; app_name?: string; items: Organization[] };

/** IAM owns this selection; no organization supplied by an app is trusted. */
export default function ApplicationLogin(props: { appId: string }) {
  const [choices, setChoices] = createSignal<Choices>();
  const [selected, setSelected] = createSignal<string[]>([]);
  const [step, setStep] = createSignal<
    "validate" | "select" | "loading" | "done"
  >("validate");
  const [error, setError] = createSignal<unknown>();
  const [token, setToken] = createSignal("");
  const [expired, setExpired] = createSignal(false);
  const send = mutation();
  let disposed = false;
  let expiryTimer: ReturnType<typeof setTimeout> | undefined;
  onCleanup(() => {
    disposed = true;
    clearTimeout(expiryTimer);
  });
  onMount(async () => {
    try {
      const params = new URL(location.href).searchParams;
      if (params.has("org_id") || params.has("org_ids"))
        throw new Error(
          "Applications cannot choose your organizations. Remove org_id / org_ids from the login URL and choose them here in IAM.",
        );
      const value = await request<Choices>(
        `/api/v1/app-auth/organizations?app_id=${encodeURIComponent(props.appId)}`,
      );
      if (disposed) return;
      setChoices(value);
      setSelected(
        value.items.filter((org) => org.authorized).map((org) => org.org_id),
      );
    } catch (err) {
      if (!disposed) setError(err);
    }
  });

  async function approve() {
    if (step() !== "select" || !selected().length) return;
    setError();
    let destination: URL | undefined;
    try {
      const redirect = new URL(location.href).searchParams.get("redirect_uri");
      if (redirect) {
        destination = new URL(redirect);
        const local = ["localhost", "127.0.0.1", "[::1]"].includes(
          destination.hostname,
        );
        if (
          destination.username ||
          destination.password ||
          destination.hash ||
          (destination.protocol !== "https:" &&
            !(destination.protocol === "http:" && local))
        )
          throw new Error(
            "The callback must use HTTPS (or HTTP on localhost), without credentials or a fragment.",
          );
      }
      setStep("loading");
      const start = Date.now();
      const value = await send("POST", "/api/v1/app-auth/short-lived-tokens", {
        app_id: props.appId,
        org_ids: selected(),
        ...(destination ? { redirect_uri: destination.href } : {}),
      });
      await new Promise((resolve) =>
        setTimeout(resolve, Math.max(0, 1500 - (Date.now() - start))),
      );
      if (disposed) return;
      setStep("done");
      await new Promise((resolve) => setTimeout(resolve, 700));
      if (disposed) return;
      if (destination) {
        destination.searchParams.set("slt", value.slt);
        location.assign(destination.href);
      } else {
        setToken(value.slt);
        expiryTimer = setTimeout(
          () => {
            setToken("");
            setExpired(true);
            if (value.request_id)
              location.assign(
                `/api/v1/login/status?request=${encodeURIComponent(value.request_id)}`,
              );
          },
          Math.max(0, value.expires_in * 1000 - (Date.now() - start)),
        );
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
        when={choices()}
        fallback={
          <p role="status">
            {error()
              ? "Sign-in has not been authorized."
              : "Validating application…"}
          </p>
        }
      >
        {(value) => (
          <>
            <Show when={step() === "validate"}>
              <div class="notice">
                <strong>{value().app_name || value().app_id}</strong>
                <p>Verified IAM application · {value().app_id}</p>
                <p>
                  You decide which organizations it can read. Your other
                  organizations stay private.
                </p>
              </div>
              <button class="button primary" onClick={() => setStep("select")}>
                Choose organizations
              </button>
            </Show>
            <Show when={step() !== "validate"}>
              <fieldset
                disabled={step() !== "select"}
                class="stack organization-consent"
              >
                <legend>Organizations to share</legend>
                <p>
                  Share at least one. Existing access is kept; organizations you
                  join later are not shared automatically.
                </p>
                <Show
                  when={value().items.length}
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
                      setSelected(value().items.map((org) => org.org_id))
                    }
                  >
                    Select all current organizations
                  </button>
                  <For each={value().items}>
                    {(org) => (
                      <label class="organization-choice">
                        <input
                          type="checkbox"
                          checked={selected().includes(org.org_id)}
                          disabled={org.authorized}
                          onChange={(event) =>
                            setSelected((ids) =>
                              event.currentTarget.checked
                                ? [...ids, org.org_id]
                                : ids.filter((id) => id !== org.org_id),
                            )
                          }
                        />
                        <span>
                          <strong>{org.name}</strong>
                          <small>
                            {org.org_id}
                            {org.authorized ? " · Already authorized" : ""}
                          </small>
                        </span>
                      </label>
                    )}
                  </For>
                </Show>
              </fieldset>
              <p class="muted">
                The app can read members, roles, tags, trust and directory data
                in these organizations. It cannot change them.
              </p>
              <button
                type="button"
                class="button primary handoff-button"
                classList={{ "handoff-ready": step() === "done" }}
                disabled={!selected().length || step() !== "select"}
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
                      : `Authorize ${selected().length} organization${selected().length === 1 ? "" : "s"}`}
                </span>
              </button>
              <Show when={token()}>
                <div class="notice">
                  <p>
                    If requested, this is your short-lived token. Give only this
                    token to the application.
                  </p>
                  <code class="login-token">{token()}</code>
                  <p>Valid for one exchange and at most two minutes.</p>
                </div>
              </Show>
              <Show when={expired()}>
                <p role="status">
                  Token expired. Reload to start a new sign-in.
                </p>
              </Show>
            </Show>
          </>
        )}
      </Show>
    </div>
  );
}
