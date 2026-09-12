import {
  createEffect,
  createMemo,
  createSignal,
  For,
  onCleanup,
  Show,
} from "solid-js";
import { createResource } from "./resource";
import { ApiError, mutation, request, segment, type RecordValue } from "./api";
import { ErrorBox, Field, Loading } from "./ui";
import {
  createScopeLookup,
  defaultAppScope,
  scopeApprovalLabel,
  scopeCatalog,
  scopeNames,
  toggleScope,
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

type ExternalCatalog = {
  appId: string;
  items: ScopeDescriptor[];
  loading: boolean;
  error?: unknown;
};

export function ScopePicker(props: {
  value: AppScope;
  change: (scope: AppScope) => void;
}) {
  const [catalog, { refetch }] = createResource(async () => {
    const result = await request<{ items: ScopeDescriptor[] }>(
      "/api/v1/application-scopes",
    );
    return scopeCatalog(result.items, null);
  });
  const [appId, setAppId] = createSignal(""),
    [lookupBusy, setLookupBusy] = createSignal(false),
    [lookupError, setLookupError] = createSignal<unknown>(),
    [external, setExternal] = createSignal<ExternalCatalog[]>([]),
    [error, setError] = createSignal<unknown>();
  const selected = createMemo(() => new Set(scopeNames(props.value)));
  const inFlight = new Map<string, Promise<ScopeDescriptor[]>>();
  let disposed = false;
  const loadApp = (id: string) => {
    const pending = inFlight.get(id);
    if (pending) return pending;
    const promise = request<{ items: ScopeDescriptor[] }>(
      `/api/v1/application-scopes?app_id=${segment(id)}`,
    )
      .then((result) => scopeCatalog(result.items, id))
      .finally(() => inFlight.delete(id));
    inFlight.set(id, promise);
    return promise;
  };
  const lookup = createScopeLookup(loadApp);
  const updateCatalog = (entry: ExternalCatalog) => {
    if (disposed) return;
    setExternal((current) =>
      current.some((item) => item.appId === entry.appId)
        ? current.map((item) => (item.appId === entry.appId ? entry : item))
        : [...current, entry],
    );
  };
  async function hydrate(id: string) {
    updateCatalog({ appId: id, items: [], loading: true });
    try {
      updateCatalog({ appId: id, items: await loadApp(id), loading: false });
    } catch (error) {
      updateCatalog({ appId: id, items: [], loading: false, error });
    }
  }
  createEffect(() => {
    for (const id of new Set(props.value.external.map((item) => item.app_id)))
      if (!external().some((item) => item.appId === id)) void hydrate(id);
  });
  onCleanup(() => {
    disposed = true;
    lookup.invalidate();
  });
  async function findApp() {
    if (lookupBusy()) return;
    const id = appId().trim();
    setLookupError();
    if (!id) {
      setLookupError(new Error("app_id invalid"));
      return;
    }
    setLookupBusy(true);
    try {
      const items = await lookup.run(id);
      if (!items) return;
      updateCatalog({ appId: id, items, loading: false });
      setLookupBusy(false);
    } catch (error) {
      setLookupError(
        error instanceof ApiError && [404, 422].includes(error.status)
          ? new Error("app_id invalid")
          : error,
      );
      setLookupBusy(false);
    }
  }
  const toggle = (scope: ScopeDescriptor, checked: boolean) => {
    try {
      props.change(toggleScope(props.value, scope, checked));
      setError();
    } catch (cause) {
      setError(cause);
    }
  };
  const choices = (items: ScopeDescriptor[]) => (
    <div class="scope-picker">
      <For each={items}>
        {(scope) => (
          <label class="organization-choice">
            <input
              type="checkbox"
              checked={selected().has(scope.scope)}
              onChange={(event) => toggle(scope, event.currentTarget.checked)}
            />
            <span>
              <strong>{scope.description || scope.scope}</strong>
              <code>{scope.scope}</code>
              <small>{scopeApprovalLabel(scope)}</small>
            </span>
          </label>
        )}
      </For>
    </div>
  );
  return (
    <div class="stack">
      <section class="stack" aria-label="IAM scopes">
        <h3>IAM scopes</h3>
        <p class="muted">Select the IAM data your application needs.</p>
        <ErrorBox error={catalog.error || error()} retry={refetch} />
        <Show when={!catalog.loading} fallback={<Loading />}>
          {choices(catalog() || [])}
        </Show>
      </section>
      <section class="stack" aria-label="External application scopes">
        <h3>External application scopes</h3>
        <p class="muted">
          Look up an application to select the scopes it exposes.
        </p>
        <Field
          name="External app_id"
          hint="Enter the full application ID, including its organization prefix."
        >
          <input
            value={appId()}
            placeholder="organization>application"
            onInput={(event) => {
              lookup.invalidate();
              setAppId(event.currentTarget.value);
              setLookupBusy(false);
              setLookupError();
            }}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                void findApp();
              }
            }}
          />
        </Field>
        <div class="actions">
          <button
            class="button"
            type="button"
            disabled={lookupBusy()}
            onClick={() => void findApp()}
          >
            {lookupBusy() ? "Looking up…" : "Find scopes"}
          </button>
        </div>
        <ErrorBox error={lookupError()} />
        <For each={external()}>
          {(group) => (
            <fieldset class="stack">
              <legend>{group.appId}</legend>
              <Show when={group.loading}>
                <Loading />
              </Show>
              <ErrorBox
                error={group.error}
                retry={() => void hydrate(group.appId)}
              />
              {choices(group.items)}
              <Show
                when={!group.loading && !group.error && !group.items.length}
              >
                <p>This application has no exposed scopes.</p>
              </Show>
              <For
                each={props.value.external.filter(
                  (item) =>
                    item.app_id === group.appId &&
                    !group.items.some(
                      (scope) =>
                        scope.scope ===
                        `obo:${item.app_id}:${item.endpoint_id}`,
                    ),
                )}
              >
                {(item) => (
                  <label class="organization-choice">
                    <input
                      type="checkbox"
                      checked
                      onChange={() =>
                        props.change({
                          iam: [...props.value.iam],
                          external: props.value.external.filter(
                            (current) =>
                              current.app_id !== item.app_id ||
                              current.endpoint_id !== item.endpoint_id,
                          ),
                        })
                      }
                    />
                    <span>
                      <strong>{item.endpoint_id}</strong>
                      <code>{`obo:${item.app_id}:${item.endpoint_id}`}</code>
                      <small>
                        {group.loading
                          ? "Loading scope details…"
                          : group.error
                            ? "Saved selection. Scope details are unavailable; retry the lookup or uncheck to remove."
                            : "This scope is no longer exposed. Uncheck it before saving."}
                      </small>
                    </span>
                  </label>
                )}
              </For>
            </fieldset>
          )}
        </For>
      </section>
      <small>{selected().size} scopes selected</small>
    </div>
  );
}

export function WebhookScopePicker(props: {
  value: string[];
  change: (scope: string[]) => void;
}) {
  const options = [
    ["full", "All authorized updates"],
    ["membership", "Membership updates"],
    ["updates", "Profile and organization updates"],
    ["trust", "Trust updates"],
  ];
  return (
    <div class="stack">
      <p class="muted">
        Choose which updates IAM delivers. These subscriptions do not grant
        access to data.
      </p>
      <For each={options}>
        {([value, name]) => (
          <label class="checkbox">
            <input
              type="checkbox"
              checked={props.value.includes(value)}
              onChange={(event) =>
                props.change(
                  event.currentTarget.checked
                    ? [...new Set([...props.value, value])]
                    : props.value.filter((item) => item !== value),
                )
              }
            />
            <span>
              {name} <code>{value}</code>
            </span>
          </label>
        )}
      </For>
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
