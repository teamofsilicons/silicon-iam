import { createSignal, For, Show } from "solid-js";
import {
  ApiError,
  mutation,
  segment,
  type Configuration,
  type RecordValue,
} from "./api";
import { BundleLogo } from "./BundleLogo";
import {
  bundleFormPayload,
  displayLogoUrl,
  type BundleFields,
} from "./bundle-model";
import {
  Empty,
  ErrorBox,
  Field,
  Loading,
  Modal,
  PageFooter,
  PageTitle,
  usePage,
} from "./ui";

export default function Bundles(props: {
  config: Configuration;
  organization?: RecordValue;
  selectedOrg: string;
  refreshAvailability: () => unknown;
}) {
  const page = usePage(
    () => `/api/v1/application-bundles?org_id=${segment(props.selectedOrg)}`,
  );
  const [editing, setEditing] = createSignal<RecordValue>(),
    [creating, setCreating] = createSignal(false);
  const link = (bundle: RecordValue) => {
    const url = new URL("/login", props.config.authOrigin);
    url.searchParams.set("bundle_id", bundle.bundle_id);
    return url.href;
  };
  return (
    <>
      <PageTitle
        title="Application bundles"
        subtitle="One sign-in experience for a group of your applications."
      >
        <button class="button primary" onClick={() => setCreating(true)}>
          Create bundle
        </button>
      </PageTitle>
      <section class="panel">
        <ErrorBox error={page.data.error} retry={page.refresh} />
        <Show when={!page.data.loading} fallback={<Loading />}>
          <Show
            when={page.data()?.items.length}
            fallback={
              <Empty title="No application bundles">
                A bundle presents one identity at login and issues a separate
                short-lived token to each member application.
              </Empty>
            }
          >
            <div class="event-list">
              <For
                each={page
                  .data()
                  ?.items.filter(
                    (bundle) => bundle.org_id === props.selectedOrg,
                  )}
              >
                {(bundle) => (
                  <article>
                    <div class="actions">
                      <BundleLogo url={bundle.app_logo} />
                      <div>
                        <strong>{bundle.app_name || bundle.bundle_id}</strong>
                        <small>{bundle.bundle_id}</small>
                        <p>{bundle.app_ids.length} applications</p>
                        <a href={link(bundle)}>Open bundle login →</a>
                      </div>
                    </div>
                    <button
                      class="button small"
                      onClick={() => setEditing(bundle)}
                    >
                      Manage
                    </button>
                  </article>
                )}
              </For>
            </div>
          </Show>
          <PageFooter page={page} />
        </Show>
      </section>
      <Show when={creating() || editing()}>
        <BundleForm
          {...props}
          value={editing()}
          close={() => {
            setCreating(false);
            setEditing();
          }}
          saved={() => {
            setCreating(false);
            setEditing();
            void page.refresh();
          }}
        />
      </Show>
    </>
  );
}

function BundleForm(props: {
  organization?: RecordValue;
  selectedOrg: string;
  refreshAvailability: () => unknown;
  value?: RecordValue;
  close: () => void;
  saved: () => void;
}) {
  const [handle, setHandle] = createSignal(""),
    [name, setName] = createSignal(props.value?.app_name || ""),
    [logo, setLogo] = createSignal(props.value?.app_logo || ""),
    [ids, setIds] = createSignal<string[]>([...(props.value?.app_ids || [])]),
    [busy, setBusy] = createSignal(false),
    [error, setError] = createSignal<unknown>(),
    [removing, setRemoving] = createSignal(false);
  const apps = usePage(
    () => `/api/v1/applications?org_id=${segment(props.selectedOrg)}`,
  );
  const send = mutation();
  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy()) return;
    setBusy(true);
    setError();
    try {
      if (
        !props.selectedOrg ||
        (props.value && props.value.org_id !== props.selectedOrg)
      )
        throw new Error("Select the bundle’s organization before saving.");
      const fields = bundleFormPayload(
        { name: name(), logo: logo(), appIds: ids() },
        props.value as BundleFields | undefined,
      );
      if (props.value && !Object.keys(fields).length)
        throw new Error("Change at least one value to save.");
      await send(
        props.value ? "PATCH" : "POST",
        props.value
          ? `/api/v1/application-bundles/${segment(props.value.bundle_id)}`
          : "/api/v1/application-bundles",
        {
          ...(props.value
            ? {}
            : { org_id: props.selectedOrg, app_id: handle() }),
          ...fields,
        },
        { version: props.value?.version },
      );
      props.saved();
    } catch (cause) {
      setError(cause);
      if (cause instanceof ApiError && [403, 404].includes(cause.status))
        void props.refreshAvailability();
    } finally {
      setBusy(false);
    }
  }
  async function remove() {
    if (!props.value || busy()) return;
    setBusy(true);
    setError();
    try {
      await send(
        "DELETE",
        `/api/v1/application-bundles/${segment(props.value.bundle_id)}`,
        undefined,
        { version: props.value.version },
      );
      props.saved();
    } catch (cause) {
      setError(cause);
      if (cause instanceof ApiError && [403, 404].includes(cause.status))
        void props.refreshAvailability();
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title={props.value ? "Manage bundle" : "Create bundle"}
      close={props.close}
      wide
    >
      <form class="stack" onSubmit={submit}>
        <p>
          Each application remains independently usable and exchanges its own
          token with its own secret. Bundle members must belong to the same
          organization.
        </p>
        <Field name="Organization">
          <input
            readonly
            value={
              props.organization?.name
                ? `${props.organization.name} (${props.selectedOrg})`
                : props.selectedOrg
            }
          />
        </Field>
        <Show when={!props.value}>
          <Field
            name="Bundle handle"
            required
            hint="IAM adds the organization prefix."
          >
            <input
              required
              maxlength={80}
              pattern="[a-z][a-z0-9_-]{0,79}"
              value={handle()}
              onInput={(e) => setHandle(e.currentTarget.value)}
            />
          </Field>
        </Show>
        <Field name="Bundle name">
          <input
            maxlength={200}
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
          />
        </Field>
        <Field
          name="Bundle logo URL"
          hint="Optional HTTPS image URL. Leave blank to remove the current logo."
        >
          <input
            type="url"
            maxlength={2048}
            value={logo()}
            placeholder="https://example.com/images/bundle.png"
            onInput={(event) => setLogo(event.currentTarget.value)}
          />
        </Field>
        <Show when={displayLogoUrl(logo())}>
          <BundleLogo
            url={logo()}
            alt="Bundle logo preview"
            fallback={
              <p class="muted" role="status">
                Image preview unavailable. Check the URL.
              </p>
            }
          />
        </Show>
        <fieldset disabled={busy()} class="stack">
          <legend>Member applications</legend>
          <ErrorBox error={apps.data.error} retry={apps.refresh} />
          <Show when={apps.data.loading}>
            <Loading />
          </Show>
          <For
            each={
              !apps.data.loading
                ? apps
                    .data()
                    ?.items.filter((app) => app.org_id === props.selectedOrg)
                : []
            }
          >
            {(app) => (
              <label class="organization-choice">
                <input
                  type="checkbox"
                  checked={ids().includes(app.app_id)}
                  onChange={(e) =>
                    setIds((values) =>
                      e.currentTarget.checked
                        ? [...new Set([...values, app.app_id])]
                        : values.filter((id) => id !== app.app_id),
                    )
                  }
                />
                <span>
                  <strong>{app.app_name || app.app_id}</strong>
                  <small>{app.app_id}</small>
                </span>
              </label>
            )}
          </For>
          <Show when={!apps.data.loading}>
            <PageFooter page={apps} />
          </Show>
        </fieldset>
        <Show when={props.value}>
          <Show
            when={removing()}
            fallback={
              <button
                type="button"
                class="text-button destructive"
                onClick={() => setRemoving(true)}
              >
                Delete bundle
              </button>
            }
          >
            <div class="notice">
              <p>
                Retire this bundle and stop new bundle sign-ins? Its member
                applications remain available.
              </p>
              <button
                class="button danger"
                type="button"
                disabled={busy()}
                onClick={() => void remove()}
              >
                Confirm bundle deletion
              </button>
            </div>
          </Show>
        </Show>
        <ErrorBox error={error()} />
        <div class="form-actions">
          <button class="button" type="button" onClick={props.close}>
            Cancel
          </button>
          <button class="button primary" disabled={busy() || !ids().length}>
            {busy() ? "Saving…" : "Save bundle"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
