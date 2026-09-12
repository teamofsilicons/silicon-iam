import {
  createMemo,
  createSignal,
  For,
  Index,
  Match,
  Show,
  Switch,
} from "solid-js";
import { createResource } from "./resource";
import {
  date,
  mutation,
  request,
  segment,
  orgPath,
  validateBaseOrigin,
  type Configuration,
  type RecordValue,
} from "./api";
import { OperationForm, type Operation } from "./forms";
import { ApplicationScopes, ScopePicker, WebhookScopePicker } from "./Scopes";
import { defaultAppScope } from "./scope-model";
import {
  Badge,
  Empty,
  ErrorBox,
  Field,
  JsonDetails,
  Loading,
  Modal,
  PageFooter,
  PageTitle,
  RecordDetails,
  SecretResult,
  usePage,
} from "./ui";

export function ApplicationCreate(props: {
  config: Configuration;
  orgs: RecordValue[];
  selectedOrg: string;
  close: () => void;
  success: (result: RecordValue) => void;
}) {
  const [org, setOrg] = createSignal(props.selectedOrg),
    [handle, setHandle] = createSignal(""),
    [name, setName] = createSignal(""),
    [base, setBase] = createSignal(""),
    [webhook, setWebhook] = createSignal(""),
    [secret, setSecret] = createSignal(""),
    [scope, setScope] = createSignal(defaultAppScope()),
    [webhookScope, setWebhookScope] = createSignal(["full"]),
    [busy, setBusy] = createSignal(false),
    [error, setError] = createSignal<unknown>();
  const send = mutation();
  const [membership] = createResource(
    () => org() || undefined,
    (id) => request(`${orgPath(id)}/directory/self`),
  );
  const mayCreate = () =>
    ["owner", "admin"].includes(membership()?.role?.org_role);
  async function submit(e: SubmitEvent) {
    e.preventDefault();
    setBusy(true);
    setError();
    try {
      if (!mayCreate())
        throw new Error(
          "Application creation requires the selected organization’s current owner or admin.",
        );
      validateBaseOrigin(base());
      if (!/^[a-z][a-z0-9_-]{0,79}$/.test(handle()))
        throw new Error(
          "App handle must be 1–80 lowercase letters, digits, underscores or hyphens, starting with a letter. Enter only the local handle.",
        );
      if (!/^[\x21-\x7e]{32,512}$/.test(secret()))
        throw new Error(
          "Webhook secret must be 32–512 non-whitespace ASCII characters.",
        );
      const result = await send("POST", "/api/v1/applications", {
        org_id: org(),
        app_id: handle(),
        ...(name().trim() ? { app_name: name().trim() } : {}),
        base_url: base(),
        webhook_url: webhook(),
        webhook_secret: secret(),
        app_scope: scope(),
        webhook_scope: webhookScope(),
      });
      setSecret("");
      props.success(result);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title="Create application" close={props.close} wide>
      <form class="stack" onSubmit={submit}>
        <p class="muted">
          Apps belong to an organization. You must be its current owner or
          admin. All fields marked * are required.
        </p>
        <div class="form-grid">
          <Field name="Organization" required>
            <select
              required
              value={org()}
              onChange={(e) => setOrg(e.currentTarget.value)}
            >
              <option value="">Choose an organization</option>
              <For each={props.orgs}>
                {(item) => (
                  <option value={item.org_id}>
                    {item.name} ({item.org_id})
                  </option>
                )}
              </For>
            </select>
          </Field>
          <Field
            name="App handle"
            required
            hint="1–80 characters, starting with a lowercase letter. IAM adds the organization prefix."
          >
            <input
              autofocus
              required
              minlength="1"
              maxlength="80"
              value={handle()}
              onInput={(e) => setHandle(e.currentTarget.value)}
              placeholder="space-station"
            />
          </Field>
        </div>
        <div class="identifier-preview">
          <span>Application ID</span>
          <code>
            {org() || "organization"}&gt;{handle() || "app-handle"}
          </code>
        </div>
        <Field name="App name">
          <input
            maxlength="200"
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
            placeholder="Space Station"
          />
        </Field>
        <Field
          name="Base URL"
          required
          hint="The backend origin. No trailing slash or path."
        >
          <input
            type="url"
            required
            value={base()}
            onInput={(e) => setBase(e.currentTarget.value)}
            placeholder="https://app.example.com"
          />
        </Field>
        <Field
          name="Webhook URL"
          required
          hint="A public HTTPS endpoint. A path and trailing slash are allowed here."
        >
          <input
            type="url"
            required
            pattern="https://.*"
            value={webhook()}
            onInput={(e) => setWebhook(e.currentTarget.value)}
            placeholder="https://app.example.com/webhooks/iam"
          />
        </Field>
        <Field
          name="Webhook secret"
          required
          hint="Your own 32–512 character secret. Configure the same value on your webhook receiver."
        >
          <input
            type="password"
            required
            minlength="32"
            maxlength="512"
            autocomplete="off"
            value={secret()}
            onInput={(e) => setSecret(e.currentTarget.value)}
          />
        </Field>
        <fieldset>
          <legend>Application permissions</legend>
          <ScopePicker value={scope()} change={setScope} />
        </fieldset>
        <fieldset class="stack">
          <legend>Webhook subscriptions</legend>
          <WebhookScopePicker value={webhookScope()} change={setWebhookScope} />
        </fieldset>
        <div class="notice">
          After creating the app, save its client secret. The initial webhook
          must be approved before production deliveries begin. If you selected
          critical permissions, open the app’s Permissions tab to submit the
          review before its first login.
        </div>
        <ErrorBox error={error() || membership.error} />
        <Show
          when={org() && !membership.loading && membership() && !mayCreate()}
        >
          <div class="notice">
            Only the selected organization’s current owner or admin can create
            an application.
          </div>
        </Show>
        <div class="form-actions">
          <button class="button" type="button" onClick={props.close}>
            Cancel
          </button>
          <button
            class="button primary"
            disabled={busy() || membership.loading || !mayCreate()}
          >
            {busy() ? "Creating…" : "Create application"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
export default function Applications(props: {
  config: Configuration;
  orgs: RecordValue[];
  selectedOrg: string;
}) {
  const page = usePage(() => "/api/v1/applications"),
    [query, setQuery] = createSignal(""),
    [creating, setCreating] = createSignal(
      new URL(location.href).searchParams.get("create") === "1",
    ),
    [secret, setSecret] = createSignal<RecordValue>();
  const appId = new URL(location.href).searchParams.get("app");
  const filtered = createMemo(() =>
    (page.data()?.items || []).filter((app) =>
      `${app.app_id} ${app.app_name || ""}`
        .toLowerCase()
        .includes(query().toLowerCase()),
    ),
  );
  return (
    <Show
      when={!appId}
      fallback={<ApplicationDetail appId={appId!} config={props.config} />}
    >
      <PageTitle
        title="Applications"
        subtitle="Connect your tools to one identity system."
      >
        <button class="button primary" onClick={() => setCreating(true)}>
          ＋ Create application
        </button>
      </PageTitle>
      <div class="panel">
        <div class="panel-toolbar">
          <h2>Your applications</h2>
          <input
            class="search"
            aria-label="Search loaded applications"
            placeholder="Search loaded applications…"
            value={query()}
            onInput={(e) => setQuery(e.currentTarget.value)}
          />
        </div>
        <ErrorBox error={page.data.error} retry={page.refresh} />
        <Show
          when={!page.data.loading && !page.data.error}
          fallback={
            <Show when={page.data.loading}>
              <Loading />
            </Show>
          }
        >
          <Show
            when={filtered().length}
            fallback={
              <Empty
                title={
                  query() ? "No matching applications" : "No applications yet"
                }
              >
                {query()
                  ? "Try a different search or load the next page."
                  : "Create your first app to set up authentication, webhooks, and inter-app access."}
              </Empty>
            }
          >
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Application</th>
                    <th>Organization</th>
                    <th>Status</th>
                    <th>Webhook</th>
                    <th>Updated</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={filtered()}>
                    {(app) => (
                      <tr>
                        <td>
                          <a
                            class="primary-link"
                            href={`/applications?app=${segment(app.app_id)}`}
                          >
                            {app.app_name || app.app_id.split(">")[1]}
                          </a>
                          <small>
                            <code>{app.app_id}</code>
                          </small>
                        </td>
                        <td>{app.org_id}</td>
                        <td>
                          <Badge value={app.status} />
                        </td>
                        <td>
                          <Badge value={app.webhook?.status} />
                        </td>
                        <td>{date(app.updated_at)}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
          <PageFooter page={page} />
        </Show>
      </div>
      <Show when={creating()}>
        <ApplicationCreate
          {...props}
          close={() => setCreating(false)}
          success={(result) => {
            setCreating(false);
            setSecret(result);
            void page.refresh();
          }}
        />
      </Show>
      <Show when={secret()}>
        <SecretResult result={secret()!} close={() => setSecret()} />
      </Show>
    </Show>
  );
}
function ApplicationDetail(props: { appId: string; config: Configuration }) {
  const path = `/api/v1/applications/${segment(props.appId)}`,
    [app, { refetch }] = createResource(() => request(path));
  const [tab, setTab] = createSignal("Overview"),
    [operation, setOperation] = createSignal<Operation>(),
    [secret, setSecret] = createSignal<RecordValue>(),
    [notice, setNotice] = createSignal("");
  const tabs = [
    "Overview",
    "Authentication",
    "Permissions",
    "OBO endpoints",
    "Testing",
    "Webhook",
    "Login history",
    "Failed deliveries",
  ];
  const operate = (op: Operation) => {
    setNotice("");
    setOperation(op);
  };
  return (
    <>
      <a class="back-link" href="/applications">
        ← Applications
      </a>
      <PageTitle title={app()?.app_name || props.appId} subtitle={props.appId}>
        <Show when={app()}>
          <Badge value={app()!.status} />
        </Show>
        <button class="button" onClick={() => refetch()}>
          Refresh
        </button>
      </PageTitle>
      <ErrorBox error={app.error} retry={refetch} />
      <Show when={notice()}>
        <div class="notice success" role="status">
          {notice()}
        </div>
      </Show>
      <Show
        when={app()}
        fallback={
          <Show when={app.loading}>
            <Loading />
          </Show>
        }
      >
        <div class="tabs" role="tablist" aria-label="Application sections">
          <For each={tabs}>
            {(item) => (
              <button
                role="tab"
                aria-selected={tab() === item}
                onClick={() => setTab(item)}
              >
                {item}
              </button>
            )}
          </For>
        </div>
        <div role="tabpanel">
          <Switch>
            <Match when={tab() === "Overview"}>
              <div class="detail-grid">
                <section class="panel padded">
                  <div class="section-heading">
                    <h2>Application details</h2>
                    <button
                      class="button small"
                      onClick={() =>
                        operate({
                          title: "Save application",
                          path,
                          method: "PATCH",
                          schema: "ApplicationPatch",
                          initial: app(),
                          version: app()!.version,
                          description:
                            "App ID and organization are permanent. OBO endpoints are a full replacement when included.",
                        })
                      }
                    >
                      Edit
                    </button>
                  </div>
                  <RecordDetails
                    value={app()!}
                    fields={[
                      "app_id",
                      "org_id",
                      "base_url",
                      "status",
                      "created_at",
                      "updated_at",
                      "version",
                    ]}
                  />
                </section>
                <section class="panel padded stack">
                  <h2>Credentials</h2>
                  <p class="muted">
                    Client secrets stay on your application server. Never put
                    them in frontend code.
                  </p>
                  <button
                    class="button"
                    onClick={() =>
                      operate({
                        title: "Rotate client secret",
                        path: `${path}/client-secret-rotations`,
                        version: app()!.version,
                        danger: true,
                        description:
                          "This replaces the application client secret. Prepare to update your server’s secret manager.",
                        stepUp: {
                          action: "application.client_secret.rotate",
                          resource: app()!.id,
                        },
                      })
                    }
                  >
                    Rotate client secret
                  </button>
                  <p class="muted">
                    Webhook status: <Badge value={app()!.webhook?.status} />
                  </p>
                  <button class="text-button" onClick={() => setTab("Webhook")}>
                    Manage webhook →
                  </button>
                </section>
              </div>
            </Match>
            <Match when={tab() === "Authentication"}>
              <LoginLinks config={props.config} app={app()!} />
            </Match>
            <Match when={tab() === "Permissions"}>
              <Show keyed when={app()}>
                {(value) => <ApplicationScopes app={value} refresh={refetch} />}
              </Show>
            </Match>
            <Match when={tab() === "OBO endpoints"}>
              <Endpoints app={app()!} refresh={refetch} />
            </Match>
            <Match when={tab() === "Testing"}>
              <section class="panel padded stack">
                <h2>Test this application</h2>
                <p>
                  Create an isolated IAM environment, then import this
                  application by its public ID. IAM brings in its declared
                  application dependencies and issues separate test credentials.
                </p>
                <p>
                  Use the environment key with the same client, CLI, and API
                  operations. Test verification codes are <code>000000</code>.
                </p>
                <div class="actions">
                  <a
                    class="button primary"
                    href={`/testing?org=${segment(app()!.org_id)}`}
                  >
                    Manage testing environments →
                  </a>
                  <a
                    class="button"
                    href="https://docs.iam.teamofsilicons.com/api/testing-environments/"
                  >
                    Application testing guide ↗
                  </a>
                </div>
                <p class="muted">
                  Configure the app’s inactivity retention and OBO review
                  instructions in Application details. Imported webhook secrets
                  stay private; replacing a test destination gives it a separate
                  secret.
                </p>
              </section>
            </Match>
            <Match when={tab() === "Webhook"}>
              <section class="panel padded stack">
                <h2>Webhook delivery</h2>
                <p class="muted">
                  IAM delivers signed events and authorization snapshots limited
                  by your effective scopes and user consent to this endpoint.
                  Production destinations need approval; testing destinations
                  activate immediately.
                </p>
                <RecordDetails value={app()!.webhook || {}} />
                <div class="actions">
                  <button
                    class="button"
                    onClick={() =>
                      operate({
                        title: "Update webhook",
                        path: `${path}/webhook`,
                        method: "PUT",
                        schema: "ApplicationWebhookReplace",
                        initial: {
                          url:
                            app()!.webhook?.pending_url ||
                            app()!.webhook?.active_url,
                        },
                        version: app()!.version,
                        description:
                          "Production keeps the current signing secret unless you provide a replacement. In a testing environment, IAM generates a fresh test-only secret when you leave this blank; save it on your receiver.",
                      })
                    }
                  >
                    Change destination
                  </button>
                  <Show when={app()!.webhook?.pending_url}>
                    <button
                      class="button primary"
                      onClick={() =>
                        operate({
                          title: "Approve webhook",
                          path: `${path}/webhook/approvals`,
                          body: {},
                          version: app()!.version,
                          description:
                            "Approve this destination to receive organization and authorization events. Verify that your application controls this endpoint.",
                          stepUp: {
                            action: "application.webhook.approve",
                            resource: app()!.id,
                          },
                        })
                      }
                    >
                      Approve webhook
                    </button>
                  </Show>
                  <button
                    class="button"
                    onClick={() =>
                      operate({
                        title: "Rotate webhook secret",
                        path: `${path}/webhook-secret-rotations`,
                        schema: "ApplicationWebhookSecretRotate",
                        version: app()!.version,
                        stepUp: {
                          action: "application.webhook_secret.rotate",
                          resource: app()!.id,
                        },
                        description:
                          "Enter the user-managed secret that your webhook receiver will use.",
                      })
                    }
                  >
                    Rotate signing secret
                  </button>
                </div>
              </section>
            </Match>
            <Match when={tab() === "Login history"}>
              <Activity
                path={`${path}/login-history`}
                title="Application login history"
              />
            </Match>
            <Match when={tab() === "Failed deliveries"}>
              <Activity
                path={`${path}/webhook/dead-letters`}
                title="Failed webhook deliveries"
                replay={(ids) =>
                  operate({
                    title: "Replay deliveries",
                    path: `${path}/webhook/dead-letters/replays`,
                    body: { delivery_ids: ids },
                    description:
                      "Retry these failed events after fixing the receiving endpoint.",
                  })
                }
              />
            </Match>
          </Switch>
        </div>
      </Show>
      <Show when={operation()}>
        <OperationForm
          operation={operation()!}
          config={props.config}
          close={() => setOperation()}
          success={(result) => {
            setOperation();
            setNotice("Change saved.");
            if (
              result &&
              Object.keys(result).some((key) => /secret$|token$/.test(key))
            )
              setSecret(result);
            void refetch();
          }}
        />
      </Show>
      <Show when={secret()}>
        <SecretResult result={secret()!} close={() => setSecret()} />
      </Show>
    </>
  );
}
function LoginLinks(props: { app: RecordValue; config: Configuration }) {
  const [callback, setCallback] = createSignal(""),
    [copied, setCopied] = createSignal(false),
    [error, setError] = createSignal("");
  const link = createMemo(() => {
    const url = new URL("/login", props.config.authOrigin);
    url.searchParams.set("app_id", props.app.app_id);
    if (callback()) url.searchParams.set("redirect_uri", callback());
    return url.href;
  });
  function valid() {
    if (!callback()) return true;
    try {
      const url = new URL(callback());
      if (
        (url.protocol !== "https:" &&
          !(
            url.protocol === "http:" &&
            ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
          )) ||
        url.username ||
        url.password ||
        url.hash
      )
        throw new Error();
      setError("");
      return true;
    } catch {
      setError(
        "Use an HTTPS callback, or HTTP on loopback, with no credentials or fragment.",
      );
      return false;
    }
  }
  return (
    <section class="panel padded stack">
      <h2>Connect application login</h2>
      <p class="muted">
        Send users to IAM. They authenticate here; your application receives a
        single-use SLT valid for two minutes. Without a callback, IAM shows a
        token for manual copying.
      </p>
      <Field
        name="Callback URL"
        hint="Optional. Use a callback controlled by this application. IAM validates URL safety; this is not a callback registration."
      >
        <input
          type="url"
          value={callback()}
          onInput={(e) => {
            setCallback(e.currentTarget.value);
            setCopied(false);
          }}
          placeholder="https://app.example.com/auth/callback"
        />
      </Field>
      <Field name="Login URL">
        <textarea readonly rows={3} value={link()} />
      </Field>
      <Show when={error()}>
        <div class="notice error" role="alert">
          {error()}
        </div>
      </Show>
      <div class="actions">
        <button
          class="button"
          onClick={async () => {
            if (valid())
              try {
                await navigator.clipboard.writeText(link());
                setCopied(true);
              } catch {
                setError(
                  "Clipboard unavailable. Select and copy the URL above.",
                );
              }
          }}
        >
          {copied() ? "Copied" : "Copy login URL"}
        </button>
        <a
          class="button primary"
          href={link()}
          onClick={(e) => {
            if (!valid()) e.preventDefault();
          }}
        >
          Open login flow →
        </a>
      </div>
      <div class="integration-steps">
        <div>
          <span>01</span>
          <h3>Redirect to IAM</h3>
          <p>
            Preserve your application’s own anti-CSRF state in its callback URL.
            Do not ask for IAM email codes in your app.
          </p>
        </div>
        <div>
          <span>02</span>
          <h3>Exchange on your server</h3>
          <p>
            Exchange the SLT at <code>/api/v1/app-auth/tokens</code> using the
            app ID and secret through the client SDK.
          </p>
        </div>
        <div>
          <span>03</span>
          <h3>Synchronize authorization</h3>
          <p>
            Verify webhook signatures, initialize the authorization snapshot,
            and enforce current membership and epoch before serving protected
            data.
          </p>
        </div>
      </div>
      <a
        href="https://docs.iam.teamofsilicons.com/client/"
        target="_blank"
        rel="noopener noreferrer"
      >
        Read the application integration docs ↗
      </a>
    </section>
  );
}
function Endpoints(props: { app: RecordValue; refresh: () => unknown }) {
  const [items, setItems] = createSignal<RecordValue[]>(
      structuredClone(props.app.obo_endpoints || []),
    ),
    [error, setError] = createSignal<unknown>(),
    [busy, setBusy] = createSignal(false),
    [saved, setSaved] = createSignal(false);
  const send = mutation();
  const update = (index: number, key: string, value: unknown) => {
    setSaved(false);
    setItems((list) =>
      list.map((item, i) => (i === index ? { ...item, [key]: value } : item)),
    );
  };
  async function save(e: SubmitEvent) {
    e.preventDefault();
    setBusy(true);
    setError();
    try {
      const endpoints = items().map((item) => {
        const metadata =
          typeof item.metadata === "string"
            ? JSON.parse(item.metadata)
            : item.metadata;
        if (
          !metadata ||
          typeof metadata !== "object" ||
          Array.isArray(metadata)
        )
          throw new Error("Endpoint metadata must be a JSON object.");
        return {
          endpoint_id: item.endpoint_id,
          path: item.path,
          metadata,
          critical: item.critical === true,
        };
      });
      await send(
        "PATCH",
        `/api/v1/applications/${segment(props.app.app_id)}`,
        { obo_endpoints: endpoints },
        { version: props.app.version },
      );
      await props.refresh();
      setSaved(true);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section class="panel padded stack">
      <div class="section-heading">
        <div>
          <h2>Inter-application access</h2>
          <p class="muted">
            Expose callable endpoints to applications in any organization.
            Critical endpoints require your approval before a caller can use
            them.
          </p>
        </div>
        <button
          class="button small"
          disabled={items().length >= 50}
          onClick={() => {
            setSaved(false);
            setItems((v) => [
              ...v,
              { endpoint_id: "", path: "", metadata: "{}", critical: false },
            ]);
          }}
        >
          ＋ Add endpoint
        </button>
      </div>
      <div class="notice">
        OBO exchange and proof verification run on application servers, using
        signed requests and current delegated authorization. Client secrets and
        proof verification do not belong in this browser.
      </div>
      <form class="stack" onSubmit={save}>
        <Show
          when={items().length}
          fallback={
            <Empty title="No OBO endpoints">
              Add the endpoints other apps may call on behalf of an actor.
            </Empty>
          }
        >
          <Index each={items()}>
            {(item, index) => (
              <fieldset>
                <legend>Endpoint {index + 1}</legend>
                <div class="form-grid">
                  <Field name="Endpoint ID" required>
                    <input
                      required
                      value={item().endpoint_id}
                      onInput={(e) =>
                        update(index, "endpoint_id", e.currentTarget.value)
                      }
                      placeholder="files.upload"
                    />
                  </Field>
                  <Field
                    name="Path"
                    required
                    hint="An existing endpoint ID cannot be reassigned to a different path."
                  >
                    <input
                      required
                      value={item().path}
                      onInput={(e) =>
                        update(index, "path", e.currentTarget.value)
                      }
                      placeholder="/api/files"
                    />
                  </Field>
                </div>
                <label class="check">
                  <input
                    type="checkbox"
                    checked={item().critical === true}
                    onChange={(e) =>
                      update(index, "critical", e.currentTarget.checked)
                    }
                  />
                  Critical permission — require approval for each calling
                  application
                </label>
                <Field
                  name="Required metadata"
                  hint="JSON object. Each top-level key is required in an OBO exchange."
                >
                  <textarea
                    rows={3}
                    value={
                      typeof item().metadata === "string"
                        ? item().metadata
                        : JSON.stringify(item().metadata, null, 2)
                    }
                    onInput={(e) =>
                      update(index, "metadata", e.currentTarget.value)
                    }
                    placeholder={'{"filename":{"type":"string"}}'}
                  />
                </Field>
                <button
                  class="text-button destructive"
                  type="button"
                  onClick={() => {
                    setItems((v) => v.filter((_, i) => i !== index));
                    setSaved(false);
                  }}
                >
                  Remove endpoint
                </button>
              </fieldset>
            )}
          </Index>
        </Show>
        <p class="muted">
          Saving replaces the entire exposed endpoint list. Removing an endpoint
          retires it.
        </p>
        <ErrorBox error={error()} />
        <Show when={saved()}>
          <div class="notice success" role="status">
            Endpoints saved.
          </div>
        </Show>
        <button class="button primary align-start" disabled={busy()}>
          {busy() ? "Saving…" : "Save endpoints"}
        </button>
      </form>
    </section>
  );
}
export function Activity(props: {
  path: string;
  title: string;
  replay?: (ids: string[]) => void;
}) {
  const page = usePage(() => props.path);
  return (
    <section class="panel">
      <div class="panel-toolbar">
        <h2>{props.title}</h2>
        <button class="button small" onClick={page.refresh}>
          Refresh
        </button>
      </div>
      <ErrorBox error={page.data.error} retry={page.refresh} />
      <Show
        when={!page.data.loading && !page.data.error}
        fallback={
          <Show when={page.data.loading}>
            <Loading />
          </Show>
        }
      >
        <Show
          when={page.data()?.items.length}
          fallback={
            <Empty title="No events yet">
              Events will appear here as IAM processes activity.
            </Empty>
          }
        >
          <div class="event-list">
            <For each={page.data()?.items}>
              {(event) => (
                <article>
                  <div>
                    <strong>
                      {event.event_type ||
                        event.outcome ||
                        event.status ||
                        "Event"}
                    </strong>
                    <small>
                      {date(
                        event.occurred_at ||
                          event.created_at ||
                          event.last_attempt_at,
                      )}
                    </small>
                    <JsonDetails value={event} />
                  </div>
                  <Show when={props.replay}>
                    <button
                      class="button small"
                      onClick={() =>
                        props.replay!([event.delivery_id || event.id])
                      }
                    >
                      Replay
                    </button>
                  </Show>
                </article>
              )}
            </For>
          </div>
        </Show>
        <PageFooter page={page} />
      </Show>
    </section>
  );
}
