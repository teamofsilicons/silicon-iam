import {
  createEffect,
  createSignal,
  For,
  onCleanup,
  onMount,
  Show,
  type Accessor,
  type JSX,
} from "solid-js";
import { createResource } from "./resource";
import {
  ApiError,
  date,
  description,
  label,
  mutation,
  request,
  type Configuration,
  type Page,
  type RecordValue,
} from "./api";

export function Brand() {
  return (
    <a class="brand" href="/">
      <img src="/brand/mark.svg" alt="" />
      silicon<span>IAM</span>
    </a>
  );
}
export function ErrorBox(props: { error: unknown; retry?: () => void }) {
  const error = () =>
    props.error instanceof ApiError ? props.error : undefined;
  return (
    <Show when={props.error}>
      <div class="notice error" role="alert">
        <strong>{description(props.error)}</strong>
        <Show when={error()?.status === 412}>
          <p>
            This record changed since you opened it. Reload it, review the
            latest values, and submit a new change.
          </p>
        </Show>
        <Show when={error()?.retryAfter}>
          <p>Wait {error()?.retryAfter} seconds before retrying.</p>
        </Show>
        <Show when={error()?.details?.fields}>
          <ul>
            <For each={error()?.details?.fields}>
              {(field: RecordValue) => (
                <li>
                  {field.field || field.path}:{" "}
                  {field.message || field.reason || "Check this value."}
                </li>
              )}
            </For>
          </ul>
        </Show>
        <Show when={error()?.details?.field}>
          <p>
            {error()?.details?.field}: {error()?.details?.message}
          </p>
        </Show>
        <Show when={error()?.code === "idempotency_expired"}>
          <p>
            The recovery window expired. Check the resource’s current state
            before starting a new operation.
          </p>
        </Show>
        <Show when={error()?.requestId}>
          <small>
            Request ID: <code>{error()?.requestId}</code>
          </small>
        </Show>
        <Show when={props.retry}>
          <button class="button small" type="button" onClick={props.retry}>
            Reload
          </button>
        </Show>
      </div>
    </Show>
  );
}
export function Empty(props: { title: string; children?: JSX.Element }) {
  return (
    <div class="empty">
      <span class="empty-icon" aria-hidden="true">
        ＋
      </span>
      <h3>{props.title}</h3>
      <div class="muted">{props.children}</div>
    </div>
  );
}
export function Loading() {
  return (
    <div class="loading" role="status">
      <span class="spinner" />
      Loading…
    </div>
  );
}
export function Badge(props: { value?: string }) {
  return (
    <span
      class={`badge ${["active", "verified", "approved", "owner"].includes(props.value || "") ? "good" : ["rejected", "revoked", "deleted", "suspended"].includes(props.value || "") ? "bad" : ""}`}
    >
      {label(props.value || "unknown")}
    </span>
  );
}
export function PageTitle(props: {
  title: string;
  subtitle?: string;
  children?: JSX.Element;
}) {
  return (
    <header class="page-title">
      <div>
        <p class="eyebrow">WORKSPACE</p>
        <h1>{props.title}</h1>
        <Show when={props.subtitle}>
          <p class="muted">{props.subtitle}</p>
        </Show>
      </div>
      <div class="actions">{props.children}</div>
    </header>
  );
}
export function Modal(props: {
  title: string;
  children: JSX.Element;
  close: () => void;
  wide?: boolean;
}) {
  let element!: HTMLDialogElement;
  onMount(() => element.showModal());
  onCleanup(() => element.close());
  return (
    <dialog
      ref={element}
      class={props.wide ? "modal wide" : "modal"}
      aria-label={props.title}
      onCancel={(e) => {
        e.preventDefault();
        props.close();
      }}
    >
      <header>
        <h2>{props.title}</h2>
        <button
          class="icon-button"
          aria-label="Close dialog"
          onClick={props.close}
        >
          ×
        </button>
      </header>
      {props.children}
    </dialog>
  );
}
export function Field(props: {
  name: string;
  hint?: string;
  children: JSX.Element;
  required?: boolean;
}) {
  return (
    <label>
      {props.name}
      {props.required ? " *" : ""}
      {props.children}
      <Show when={props.hint}>
        <small class="muted">{props.hint}</small>
      </Show>
    </label>
  );
}
export function JsonDetails(props: { value: unknown; title?: string }) {
  return (
    <details class="json-details">
      <summary>{props.title || "API details"}</summary>
      <pre>{JSON.stringify(props.value, null, 2)}</pre>
    </details>
  );
}
export function RecordDetails(props: {
  value: RecordValue;
  fields?: string[];
}) {
  const keys = () =>
    props.fields ||
    Object.keys(props.value).filter((key) => !/secret|token|key$/.test(key));
  return (
    <dl class="record-details">
      <For each={keys()}>
        {(key) => (
          <>
            <dt>{label(key)}</dt>
            <dd>
              {typeof props.value[key] === "object" &&
              props.value[key] !== null ? (
                <JsonDetails value={props.value[key]} title="View details" />
              ) : /_at$/.test(key) ? (
                date(props.value[key])
              ) : (
                String(props.value[key] ?? "—")
              )}
            </dd>
          </>
        )}
      </For>
    </dl>
  );
}
export function SecretResult(props: {
  result: RecordValue;
  close: () => void;
}) {
  const [visible, setVisible] = createSignal(false),
    [copied, setCopied] = createSignal("");
  const secrets = () =>
    Object.entries(props.result).filter(
      ([key, value]) =>
        typeof value === "string" &&
        /secret|token|^key$|testing_key|slt$/.test(key) &&
        !/_at$/.test(key),
    );
  return (
    <Modal title="Save your credentials" close={props.close}>
      <div class="stack">
        <div class="notice">
          Store these in your server’s secret manager. They are not saved in
          browser storage and will disappear when you dismiss this dialog.
        </div>
        <For each={secrets()}>
          {([key, value]) => (
            <div class="secret-field">
              <Field name={label(key)}>
                <input
                  aria-label={label(key)}
                  type={visible() ? "text" : "password"}
                  readonly
                  value={String(value)}
                  autocomplete="off"
                />
              </Field>
              <button
                class="button small"
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(String(value));
                    setCopied(key);
                  } catch {
                    setVisible(true);
                    setCopied("");
                  }
                }}
              >
                {copied() === key ? "Copied" : "Copy"}
              </button>
            </div>
          )}
        </For>
        <label class="check">
          <input
            type="checkbox"
            checked={visible()}
            onChange={(e) => setVisible(e.currentTarget.checked)}
          />
          Show credentials
        </label>
        <Show when={props.result.secret_replay_expires_at}>
          <p class="muted">
            Retry recovery expires {date(props.result.secret_replay_expires_at)}
            .
          </p>
        </Show>
        <button class="button primary" onClick={props.close}>
          I’ve saved them — close
        </button>
      </div>
    </Modal>
  );
}
export function LocalOtp(props: { code?: string; config: Configuration }) {
  return (
    <Show
      when={
        props.code &&
        (["localhost", "[::1]"].includes(location.hostname) ||
          /^127\.\d+\.\d+\.\d+$/.test(location.hostname))
      }
    >
      <div class="notice local-otp">
        Local provider code: <code>{props.code}</code>
        <small>Only available on this isolated development instance.</small>
      </div>
    </Show>
  );
}
export function StepUp(props: {
  action: string;
  resource: string;
  config: Configuration;
  onVerified: (token: string) => void;
  close: () => void;
}) {
  const send = mutation(),
    [channel, setChannel] = createSignal("email"),
    [challenge, setChallenge] = createSignal<RecordValue>(),
    [code, setCode] = createSignal(""),
    [busy, setBusy] = createSignal(false),
    [error, setError] = createSignal<unknown>();
  async function submit(e: SubmitEvent) {
    e.preventDefault();
    setBusy(true);
    setError();
    try {
      if (!challenge())
        setChallenge(
          await send("POST", "/api/v1/step-up/challenges", {
            channel: channel(),
            action: props.action,
            resource_id: props.resource,
          }),
        );
      else {
        const result = await send(
          "POST",
          `/api/v1/step-up/challenges/${challenge()!.session_id}/verify`,
          { code: code() },
        );
        props.onVerified(result.step_up_token);
      }
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title="Verify it’s you" close={props.close}>
      <form class="stack" onSubmit={submit}>
        <p class="muted">
          This sensitive change needs a fresh verification. The code authorizes
          only this action and this resource.
        </p>
        <Show
          when={challenge()}
          fallback={
            <Field name="Send a code to">
              <select
                value={channel()}
                onChange={(e) => setChannel(e.currentTarget.value)}
              >
                <option value="email">Verified email</option>
                <option value="phone_number">Verified phone</option>
              </select>
            </Field>
          }
        >
          <Field name="Verification code" required>
            <input
              autofocus
              required
              pattern="[0-9]{6}"
              maxlength="6"
              inputmode="numeric"
              autocomplete="one-time-code"
              value={code()}
              onInput={(e) => setCode(e.currentTarget.value)}
            />
          </Field>
          <LocalOtp code={challenge()?.local_otp} config={props.config} />
        </Show>
        <ErrorBox error={error()} />
        <button class="button primary" disabled={busy()}>
          {busy()
            ? "Please wait…"
            : challenge()
              ? "Verify & continue"
              : "Send verification code"}
        </button>
      </form>
    </Modal>
  );
}
export function usePage(
  path: Accessor<string | undefined>,
  revision: Accessor<number> = () => 0,
  read: (url: string) => Promise<Page> = request<Page>,
) {
  const [data, controls] = createResource(
    () => (path() ? ([path()!, revision()] as const) : undefined),
    ([url]) => read(url + (url.includes("?") ? "&" : "?") + "limit=30"),
  );
  const [moreBusy, setMoreBusy] = createSignal(false),
    [moreError, setMoreError] = createSignal<unknown>();
  createEffect(() => {
    path();
    setMoreError();
  });
  async function more() {
    const current = data(),
      source = path(),
      sourceRevision = revision();
    if (!source || !current?.page?.next_cursor || moreBusy()) return;
    setMoreBusy(true);
    setMoreError();
    try {
      const next = await read(
        source +
          (source.includes("?") ? "&" : "?") +
          `limit=30&cursor=${encodeURIComponent(current.page.next_cursor)}`,
      );
      if (path() === source && revision() === sourceRevision)
        controls.mutate({ ...next, items: [...current.items, ...next.items] });
    } catch (e) {
      setMoreError(e);
    } finally {
      setMoreBusy(false);
    }
  }
  return { data, refresh: controls.refetch, more, moreBusy, moreError };
}
export function PageFooter(props: { page: ReturnType<typeof usePage> }) {
  return (
    <div class="page-footer">
      <ErrorBox error={props.page.moreError()} />
      <Show when={props.page.data()?.page?.has_more}>
        <button
          class="button"
          disabled={props.page.moreBusy()}
          onClick={props.page.more}
        >
          {props.page.moreBusy() ? "Loading…" : "Load more"}
        </button>
      </Show>
      <span class="muted">
        {props.page.data()?.items.length || 0} loaded
        {props.page.data()?.page?.has_more ? " · more available" : ""}
      </span>
    </div>
  );
}
