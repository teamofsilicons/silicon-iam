import { createSignal, Show } from "solid-js";
import { createResource } from "./resource";
import {
  authDestination,
  mutation,
  request,
  type Configuration,
  type SessionState,
} from "./api";
import { Brand, ErrorBox, Loading } from "./ui";
export default function SiliconCustody(props: {
  config: Configuration;
  session: SessionState;
}) {
  const id = new URL(location.href).searchParams.get("request") || "";
  const valid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(id);
  const path = `/api/v1/silicon-signup/requests/${encodeURIComponent(id)}/custodian`;
  const [detail, { refetch }] = createResource(
    () => (props.session.authenticated && valid ? id : undefined),
    () =>
      request<{
        silicon_id: string;
        display_name: string;
        status: string;
        timezone: string;
      }>(path),
  );
  const [allow, setAllow] = createSignal(true),
    [busy, setBusy] = createSignal(false),
    [error, setError] = createSignal<unknown>(),
    [decision, setDecision] = createSignal<string>();
  const send = mutation();
  async function decide(approve: boolean) {
    if (busy()) return;
    setBusy(true);
    setError();
    try {
      await send("POST", path, { approve, can_create_organizations: allow() });
      setDecision(approve ? "approved" : "rejected");
      await refetch();
    } catch (cause) {
      setError(cause);
    } finally {
      setBusy(false);
    }
  }
  return (
    <main class="onboarding-layout">
      <section class="onboarding-card stack">
        <Brand />
        <p class="eyebrow">SILICON CUSTODIAN</p>
        <h1>A partnership starts here</h1>
        <Show
          when={valid}
          fallback={
            <ErrorBox
              error={
                new Error(
                  "This custodian invitation is incomplete. Open the link from your email again.",
                )
              }
            />
          }
        >
          <Show
            when={props.session.authenticated}
            fallback={
              <>
                <p>
                  Sign in with the email that received this invitation to review
                  the Silicon account.
                </p>
                <a class="button primary" href={authDestination(props.config)}>
                  Sign in to review
                </a>
                <a href={authDestination(props.config, true)}>
                  Create a Carbon account
                </a>
              </>
            }
          >
            <a
              href={`${authDestination(props.config)}&add_account=1&type=carbon`}
            >
              Use another Carbon account
            </a>
            <Show when={!detail.loading} fallback={<Loading />}>
              <ErrorBox error={detail.error} retry={() => void refetch()} />
              <Show when={detail()}>
                <div>
                  <strong>
                    {detail()!.display_name || detail()!.silicon_id}
                  </strong>
                  <p>
                    {detail()!.silicon_id} would like you to become its
                    custodian.
                  </p>
                </div>
                <Show
                  when={!decision() && detail()!.status === "pending"}
                  fallback={
                    <div class="notice" role="status">
                      This request is {decision() || detail()!.status}.{" "}
                      <a href={props.config.consoleOrigin}>Open IAM</a>
                    </div>
                  }
                >
                  <label class="choice">
                    <input
                      type="checkbox"
                      checked={allow()}
                      onChange={(e) => setAllow(e.currentTarget.checked)}
                    />{" "}
                    Allow this Silicon to create its own organizations
                  </label>
                  <p class="muted">
                    Accepting links this Silicon to your account. You can manage
                    its custodian settings in IAM.
                  </p>
                  <div class="actions">
                    <button
                      class="button primary"
                      disabled={busy()}
                      onClick={() => void decide(true)}
                    >
                      Accept partnership
                    </button>
                    <button
                      class="button"
                      disabled={busy()}
                      onClick={() => void decide(false)}
                    >
                      Decline
                    </button>
                  </div>
                </Show>
                <ErrorBox error={error()} />
              </Show>
            </Show>
          </Show>
        </Show>
      </section>
    </main>
  );
}
