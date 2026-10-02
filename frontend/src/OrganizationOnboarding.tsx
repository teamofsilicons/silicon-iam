import { SiliconInvitationInbox } from "./SiliconInvitations";
import { createSignal, Show } from "solid-js";
import { mutation, type Configuration } from "./api";
import { Brand, ErrorBox, Field } from "./ui";
export default function OrganizationOnboarding(props: {
  config: Configuration;
  displayName?: string;
  canCreate?: boolean;
  silicon?: boolean;
  complete: () => void;
}) {
  const [name, setName] = createSignal(
    props.displayName ? `${props.displayName}'s organization` : "",
  );
  const [handle, setHandle] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  const send = mutation();
  async function create(event: SubmitEvent) {
    event.preventDefault();
    if (busy() || props.canCreate === false) return;
    setBusy(true);
    setError();
    try {
      await send("POST", "/api/v1/organizations", {
        org_id: handle().trim(),
        name: name().trim(),
      });
      props.complete();
    } catch (cause) {
      setError(cause);
    } finally {
      setBusy(false);
    }
  }
  return (
    <main class="onboarding-layout">
      <div class="onboarding-card stack">
        <Brand />
        <p class="eyebrow">YOUR FIRST ORGANIZATION</p>
        <h1>A place to make things happen.</h1>
        <p class="muted">
          {props.canCreate === false
            ? "Your account is ready. Your custodian has disabled organization creation. Ask to join an organization to start using Silicon applications."
            : "Your account is ready. Create an organization to start using Silicon applications."}
        </p>
        <Show when={props.canCreate !== false}>
          <form class="stack" onSubmit={create}>
            <Field name="Organization name" required>
              <input
                required
                maxlength="200"
                value={name()}
                onInput={(event) => setName(event.currentTarget.value)}
                autocomplete="organization"
                placeholder="My organization"
              />
            </Field>
            <Field
              name="Organization ID"
              required
              hint="A unique name using lowercase letters, numbers, underscores or hyphens."
            >
              <input
                required
                pattern="[a-z0-9_-]{3,50}"
                minlength="3"
                maxlength="50"
                value={handle()}
                onInput={(event) =>
                  setHandle(event.currentTarget.value.toLowerCase())
                }
                placeholder="my-organization"
              />
            </Field>
            <ErrorBox error={error()} />
            <button class="button primary" disabled={busy()} aria-busy={busy()}>
              {busy() ? "Creating your organization…" : "Create organization"}
            </button>
          </form>
        </Show>
        <Show
          when={props.silicon}
          fallback={
            <a href={new URL("/join", props.config.consoleOrigin).href}>
              Have an invitation? Join an organization
            </a>
          }
        >
          <SiliconInvitationInbox changed={props.complete} />
        </Show>
      </div>
    </main>
  );
}
