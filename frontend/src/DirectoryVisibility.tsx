import { createSignal, For, Show } from "solid-js";
import { createResource } from "./resource";
import { mutation, orgPath, request, segment, type RecordValue } from "./api";
import { ErrorBox, Field, Loading } from "./ui";

type Policy = {
  version: number;
  mode: string;
  visible_membership_ids: string[];
  effective_mode: string;
  effective_visible_membership_ids: string[];
};
const labels: Record<string, string> = {
  inherit: "Use organization default",
  all: "Everyone in this organization",
  self: "Only themselves",
  selected: "Selected people and Silicons",
};

export function DirectoryVisibility(props: {
  org: string;
  membership?: string;
  revision: number;
}) {
  const path = () =>
    `${orgPath(props.org)}${props.membership ? `/members/${segment(props.membership)}` : ""}/directory-visibility`;
  const [policy, control] = createResource(
    () => [path(), props.revision] as const,
    ([url]) => request<Policy>(url),
  );
  return (
    <section class="panel padded stack">
      <h2>
        {props.membership ? "Who this member can see" : "Directory visibility"}
      </h2>
      <p class="muted">
        {props.membership
          ? "Choose which people and Silicons appear in this member’s directory. This does not change what others can see."
          : "Set who members can see by default. Individual member settings can override this choice."}{" "}
        Members can always see their own identity.
      </p>
      <ErrorBox error={policy.error} retry={control.refetch} />
      <Show when={policy.loading}>
        <Loading />
      </Show>
      <Show when={policy()} keyed>
        {(value) => (
          <VisibilityEditor
            org={props.org}
            membership={props.membership}
            path={path()}
            policy={value}
            saved={() => {
              void control.refetch();
            }}
          />
        )}
      </Show>
    </section>
  );
}

function VisibilityEditor(props: {
  org: string;
  membership?: string;
  path: string;
  policy: Policy;
  saved: () => void;
}) {
  const [mode, setMode] = createSignal(props.policy.mode);
  const [selected, setSelected] = createSignal(
    props.policy.visible_membership_ids,
  );
  const [query, setQuery] = createSignal("");
  const [busy, setBusy] = createSignal(false),
    [error, setError] = createSignal<unknown>();
  const [notice, setNotice] = createSignal("");
  const send = mutation();
  const [candidates, controls] = createResource(
    () => (mode() === "selected" ? props.org : undefined),
    (org) =>
      request<{ items: RecordValue[] }>(
        `${orgPath(org)}/directory-visibility/candidates`,
      ),
  );
  const items = () =>
    (candidates()?.items || []).filter((item) =>
      `${item.display_name} ${item.public_id}`
        .toLowerCase()
        .includes(query().toLowerCase()),
    );
  const toggle = (id: string, checked: boolean) =>
    setSelected((current) =>
      checked
        ? [...new Set([...current, id])]
        : current.filter((value) => value !== id),
    );
  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (busy()) return;
    setBusy(true);
    setError();
    setNotice("");
    try {
      await send(
        "PUT",
        props.path,
        {
          mode: mode(),
          visible_membership_ids: mode() === "selected" ? selected() : [],
        },
        { version: props.policy.version },
      );
      setNotice("Visibility updated.");
      props.saved();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <form class="stack" onSubmit={save}>
      <Field name="Directory access">
        <select
          value={mode()}
          onChange={(event) => {
            setMode(event.currentTarget.value);
            setNotice("");
          }}
        >
          <For
            each={
              props.membership
                ? ["inherit", "all", "self", "selected"]
                : ["all", "self", "selected"]
            }
          >
            {(value) => <option value={value}>{labels[value]}</option>}
          </For>
        </select>
      </Field>
      <Show when={mode() === "inherit"}>
        <p class="muted">
          Current organization default:{" "}
          {labels[props.policy.effective_mode] || props.policy.effective_mode}.
        </p>
      </Show>
      <Show when={mode() === "selected"}>
        <Field name="Find members">
          <input
            type="search"
            value={query()}
            onInput={(event) => setQuery(event.currentTarget.value)}
            placeholder="Search names or IDs"
          />
        </Field>
        <ErrorBox error={candidates.error} retry={controls.refetch} />
        <Show when={candidates.loading}>
          <Loading />
        </Show>
        <p class="muted">{selected().length} selected</p>
        <div class="stack" style={{ "max-height": "20rem", overflow: "auto" }}>
          <For
            each={items()}
            fallback={<p class="muted">No matching members.</p>}
          >
            {(item) => (
              <label class="check">
                <input
                  type="checkbox"
                  checked={selected().includes(item.membership_id)}
                  onChange={(event) =>
                    toggle(item.membership_id, event.currentTarget.checked)
                  }
                />
                <span>
                  {item.display_name || item.public_id}{" "}
                  <span class="muted">
                    {item.public_id} ·{" "}
                    {item.type === "silicon" ? "Silicon" : "Carbon"}
                  </span>
                </span>
              </label>
            )}
          </For>
        </div>
      </Show>
      <ErrorBox error={error()} />
      <Show when={notice()}>
        <p role="status" class="notice success">
          {notice()}
        </p>
      </Show>
      <div class="actions">
        <button
          class="button primary"
          disabled={
            busy() ||
            (mode() === "selected" &&
              (!!candidates.error || candidates.loading))
          }
        >
          {busy() ? "Saving…" : "Save visibility"}
        </button>
      </div>
    </form>
  );
}
