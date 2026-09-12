import { createSignal, For, Show } from "solid-js";
import { createResource } from "./resource";
import { mutation, request, segment, type RecordValue } from "./api";
import { ErrorBox, Field, Loading } from "./ui";
import {
  defaultAppScope,
  scopeNames,
  selectedScope,
  type AppScope,
  type ScopeDescriptor,
} from "./scope-model";

export function ScopeList(props: { items: ScopeDescriptor[] }) {
  return (
    <ul class="scope-list">
      <For each={props.items}>
        {(scope) => (
          <li>
            <div>
              <strong>{scope.description || scope.scope}</strong>
              <code>{scope.scope}</code>
              <small>{scope.app_id || "Silicon IAM"}</small>
            </div>
            <span
              class={`badge ${scope.critical ? "scope-critical" : "scope-standard"}`}
            >
              {scope.critical ? "Critical" : "Non-critical"}
            </span>
          </li>
        )}
      </For>
    </ul>
  );
}

export function ScopePicker(props: {
  value: AppScope;
  change: (scope: AppScope) => void;
}) {
  const [catalog, { refetch }] = createResource(() =>
    request<{ items: ScopeDescriptor[] }>("/api/v1/application-scopes"),
  );
  const [query, setQuery] = createSignal(""),
    [error, setError] = createSignal<unknown>();
  const toggle = (name: string, checked: boolean) => {
    try {
      const names = scopeNames(props.value);
      props.change(
        selectedScope(
          checked ? [...names, name] : names.filter((item) => item !== name),
          catalog()?.items || [],
        ),
      );
      setError();
    } catch (cause) {
      setError(cause);
    }
  };
  return (
    <div class="stack">
      <p class="muted">
        Choose what your application may read and which external endpoints it
        may call. Critical permissions require approval from IAM or the
        receiving application.
      </p>
      <ErrorBox error={catalog.error || error()} retry={refetch} />
      <Show when={!catalog.loading} fallback={<Loading />}>
        <input
          class="search"
          aria-label="Filter permissions"
          placeholder="Filter by application or permission…"
          value={query()}
          onInput={(e) => setQuery(e.currentTarget.value)}
        />
        <div class="scope-picker">
          <For
            each={catalog()?.items.filter((item) =>
              `${item.scope} ${item.description} ${item.app_id || "IAM"}`
                .toLowerCase()
                .includes(query().toLowerCase()),
            )}
          >
            {(scope) => (
              <label class="organization-choice">
                <input
                  type="checkbox"
                  checked={scopeNames(props.value).includes(scope.scope)}
                  onChange={(e) => toggle(scope.scope, e.currentTarget.checked)}
                />
                <span>
                  <strong>{scope.description || scope.scope}</strong>
                  <code>{scope.scope}</code>
                  <small>
                    {scope.app_id || "Silicon IAM"} ·{" "}
                    {scope.critical
                      ? "Critical — approval required"
                      : "Non-critical"}
                  </small>
                </span>
              </label>
            )}
          </For>
        </div>
        <Show when={catalog() && !catalog()!.items.length}>
          <p>No permissions are currently published.</p>
        </Show>
      </Show>
      <small>{scopeNames(props.value).length} permissions selected</small>
    </div>
  );
}

export function ApplicationScopes(props: {
  app: RecordValue;
  refresh: () => unknown;
}) {
  const [scope, setScope] = createSignal<AppScope>(
      structuredClone(props.app.app_scope || defaultAppScope()),
    ),
    [message, setMessage] = createSignal(""),
    [busy, setBusy] = createSignal(false),
    [error, setError] = createSignal<unknown>(),
    [notice, setNotice] = createSignal("");
  const send = mutation();
  async function save(review: boolean) {
    if (busy()) return;
    setBusy(true);
    setError();
    setNotice("");
    try {
      if (review && !message().trim())
        throw new Error(
          "Explain why your application needs each critical permission before submitting a review.",
        );
      const path = `/api/v1/applications/${segment(props.app.app_id)}`;
      await send(
        review ? "POST" : "PATCH",
        review ? `${path}/scope-requests` : path,
        review
          ? { app_scope: scope(), message: message().trim() }
          : { app_scope: scope() },
        { version: props.app.version },
      );
      await props.refresh();
      setNotice(
        review
          ? "Review submitted. Open Scope reviews to follow the discussion."
          : "Permissions saved. New critical permissions become usable after their review is approved.",
      );
    } catch (cause) {
      setError(cause);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section class="panel padded stack">
      <div class="section-heading">
        <h2>Application permissions</h2>
        <a href="/scope-reviews">Scope reviews →</a>
      </div>
      <Show
        when={
          props.app.has_pending_changes || props.app.status === "under_review"
        }
      >
        <div class="notice">
          {props.app.status === "under_review"
            ? "This application cannot be used until its critical permissions are approved."
            : "An upgraded permission set is awaiting approval. The application continues working with its previously approved permissions."}
        </div>
      </Show>
      <details>
        <summary>Currently usable permissions</summary>
        <ul>
          <For
            each={scopeNames(
              props.app.effective_app_scope || { iam: [], external: [] },
            )}
          >
            {(name) => (
              <li>
                <code>{name}</code>
              </li>
            )}
          </For>
        </ul>
      </details>
      <fieldset disabled={busy()}>
        <legend>Declared permissions</legend>
        <ScopePicker value={scope()} change={setScope} />
      </fieldset>
      <Field
        name="Review message"
        hint="Describe your application and the purpose of every critical permission. Your message is shared with the reviewers."
      >
        <textarea
          rows={5}
          maxlength={10000}
          value={message()}
          onInput={(e) => setMessage(e.currentTarget.value)}
        />
      </Field>
      <ErrorBox error={error()} />
      <Show when={notice()}>
        <p class="notice success" role="status">
          {notice()}
        </p>
      </Show>
      <div class="actions">
        <button
          class="button"
          disabled={busy()}
          onClick={() => void save(false)}
        >
          Save permissions
        </button>
        <button
          class="button primary"
          disabled={busy() || !message().trim()}
          onClick={() => void save(true)}
        >
          Submit critical scope review
        </button>
      </div>
    </section>
  );
}
