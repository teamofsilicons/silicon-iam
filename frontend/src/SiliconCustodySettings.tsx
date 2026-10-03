import { createSignal, For, Show } from "solid-js";
import { createResource } from "./resource";
import { mutation, request, orgPath, segment } from "./api";
import { Empty, ErrorBox, Loading } from "./ui";
type Custody = {
  silicon_id: string;
  display_name: string;
  can_create_organizations: boolean;
  version: number;
};
export default function SiliconCustodySettings() {
  const [custodies, { refetch }] = createResource(() =>
    request<{ items: Custody[] }>("/api/v1/me/silicon-custodies"),
  );
  return (
    <section class="panel padded stack">
      <div>
        <h2>Your Silicon partnerships</h2>
        <p class="muted">
          Manage the accounts for which you are the custodian.
        </p>
      </div>
      <ErrorBox error={custodies.error} retry={() => void refetch()} />
      <Show when={!custodies.loading} fallback={<Loading />}>
        <For
          each={custodies()?.items}
          fallback={
            !custodies.error && (
              <Empty title="No Silicon partnerships yet">
                Accepted custody requests appear here.
              </Empty>
            )
          }
        >
          {(item) => <CustodyRow item={item} changed={() => void refetch()} />}
        </For>
      </Show>
    </section>
  );
}
export function OrganizationSiliconCustody(props: {
  org: string;
  silicon: string;
}) {
  const path = () =>
    `${orgPath(props.org)}/silicons/${segment(props.silicon)}/custody`;
  const [custody, { refetch }] = createResource(path, (url) =>
    request<Custody>(url).catch((cause) => {
      if (cause.status === 404) return null;
      throw cause;
    }),
  );
  return (
    <section class="stack">
      <h3>Organization custody</h3>
      <ErrorBox error={custody.error} retry={() => void refetch()} />
      <Show when={!custody.loading} fallback={<Loading />}>
        <Show
          when={custody()}
          keyed
          fallback={
            !custody.error && (
              <p class="muted">
                This Silicon keeps its original custodian. Joining this
                organization does not transfer custody.
              </p>
            )
          }
        >
          {(value) => (
            <>
              <p class="muted">
                This organization is the custodian for this Silicon.
              </p>
              <CustodyRow
                item={value}
                path={path()}
                changed={() => void refetch()}
              />
            </>
          )}
        </Show>
      </Show>
    </section>
  );
}
function CustodyRow(props: {
  item: Custody;
  path?: string;
  changed: () => void;
}) {
  const [allow, setAllow] = createSignal(props.item.can_create_organizations),
    [busy, setBusy] = createSignal(false),
    [error, setError] = createSignal<unknown>();
  const send = mutation();
  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (busy()) return;
    setBusy(true);
    setError();
    try {
      const result = await send<{
        silicon_id: string;
        can_create_organizations: boolean;
        version: number;
      }>(
        "PATCH",
        props.path ||
          `/api/v1/me/silicon-custodies/${encodeURIComponent(props.item.silicon_id)}`,
        { can_create_organizations: allow() },
        { version: props.item.version },
      );
      if (
        result.silicon_id !== props.item.silicon_id ||
        result.can_create_organizations !== allow()
      )
        throw new Error(
          "IAM could not confirm this setting. Reload before trying again.",
        );
      props.changed();
    } catch (cause) {
      setError(cause);
    } finally {
      setBusy(false);
    }
  }
  return (
    <form class="custody-setting stack" onSubmit={save}>
      <div>
        <strong>{props.item.display_name}</strong>
        <small>{props.item.silicon_id}</small>
      </div>
      <label class="choice">
        <input
          type="checkbox"
          checked={allow()}
          onChange={(e) => setAllow(e.currentTarget.checked)}
        />{" "}
        Allow this Silicon to create organizations
      </label>
      <ErrorBox error={error()} />
      <button
        class="button small align-start"
        disabled={busy() || allow() === props.item.can_create_organizations}
      >
        {busy() ? "Saving…" : "Save setting"}
      </button>
    </form>
  );
}
