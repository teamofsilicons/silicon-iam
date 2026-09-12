import { createSignal, createEffect, Show, For } from "solid-js";
import { request, type RecordValue } from "./api";
import { ErrorBox, RecordDetails } from "./ui";

export function ApplicationTestView(props: { appId: string }) {
  const [view, setView] = createSignal<RecordValue>();
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  let form: HTMLFormElement | undefined;
  createEffect(() => {
    props.appId;
    setView();
    setError();
    form?.reset();
  });
  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!form || busy()) return;
    const data = new FormData(form);
    const appId = props.appId;
    setBusy(true);
    setView();
    setError();
    try {
      const result = await request("/api/test-application-view", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          app_id: appId,
          app_secret: data.get("app_secret"),
          iam_test_key: data.get("iam_test_key"),
        }),
      });
      if (appId === props.appId) setView(result);
    } catch (cause) {
      setError(cause);
    } finally {
      form?.reset();
      setBusy(false);
    }
  }
  return (
    <section class="panel padded stack">
      <h2>View test application</h2>
      <p>
        Enter this application’s test secret and IAM test key to inspect its
        configuration in that isolated environment.
      </p>
      <form ref={form} class="stack" onSubmit={submit} autocomplete="off">
        <label class="field">
          Test app secret
          <input
            name="app_secret"
            type="password"
            required
            autocomplete="off"
            spellcheck={false}
            disabled={busy()}
          />
        </label>
        <label class="field">
          IAM test key
          <input
            name="iam_test_key"
            type="password"
            required
            autocomplete="off"
            spellcheck={false}
            disabled={busy()}
          />
        </label>
        <div class="actions">
          <button class="button primary" type="submit" disabled={busy()}>
            {busy() ? "Loading test application…" : "View test application"}
          </button>
        </div>
      </form>
      <ErrorBox error={error()} />
      <Show when={view()}>
        {(selected) => (
          <div
            class="stack"
            role="region"
            aria-label="Test application configuration"
          >
            <div class="notice">
              <strong>Testing environment</strong>
              <p>
                <code>{selected().environment_id}</code>
              </p>
            </div>
            <RecordDetails
              value={{
                app_id: selected().application.app_id,
                app_name: selected().application.app_name,
                base_url: selected().application.base_url,
                testing_idle_days: selected().application.testing_idle_days,
              }}
            />
            <h3>IAM scopes</h3>
            <ul>
              <For each={selected().application.app_scope.iam}>
                {(scope) => (
                  <li>
                    <code>{String(scope)}</code>
                  </li>
                )}
              </For>
            </ul>
            <h3>External scopes</h3>
            <ul>
              <For each={selected().application.app_scope.external}>
                {(scope: any) => (
                  <li>
                    <code>{scope.app_id}</code>: {scope.endpoint_id}
                  </li>
                )}
              </For>
            </ul>
            <p>
              Webhook scopes: {selected().application.webhook_scope.join(", ")}
            </p>
            <button class="button" type="button" onClick={() => setView()}>
              Close test view
            </button>
          </div>
        )}
      </Show>
      <p class="muted">
        Credentials are cleared after each request. This view shows test
        configuration; your console session remains in production.
      </p>
    </section>
  );
}
