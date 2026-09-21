import { createSignal, For, Show } from "solid-js";
import { createResource } from "./resource";
import {
  date,
  mutation,
  orgPath,
  request,
  segment,
  type RecordValue,
} from "./api";
import { ErrorBox, Field, Loading, Modal, RecordDetails } from "./ui";

const actorLabels: Record<string, string> = {
  any_member: "Any member",
  only_admins: "Only admins",
  only_owner: "Only owner",
};
const approvalLabels: Record<string, string> = {
  none: "No approval",
  admin: "Admin approval",
  owner: "Owner approval",
};
const ids = (value: string) => [
  ...new Set(
    value
      .split(/[\s,]+/)
      .map((id) => id.trim())
      .filter(Boolean),
  ),
];

export function ActionPolicies(props: { org: string; revision: number }) {
  const [policies, controls] = createResource(
    () => [props.org, props.revision] as const,
    ([org]) => request(`${orgPath(org)}/action-policies`),
  );
  const [selected, setSelected] = createSignal<RecordValue>();
  return (
    <section class="panel padded stack">
      <div class="section-heading">
        <h2>Sensitive actions</h2>
      </div>
      <p class="muted">
        Choose who can perform each action and how requests are approved. The
        owner can always act. An authorized approver can perform the action
        directly.
      </p>
      <ErrorBox error={policies.error} retry={controls.refetch} />
      <Show when={policies.loading}>
        <Loading />
      </Show>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Action</th>
              <th>Who can act</th>
              <th>Approval</th>
              <th>Automatic approval</th>
              <th />
            </tr>
          </thead>
          <tbody>
            <For each={policies()?.items || []}>
              {(rule) => (
                <tr>
                  <td>{rule.label || rule.action}</td>
                  <td>{actorLabels[rule.allowed_actors]}</td>
                  <td>{approvalLabels[rule.approval]}</td>
                  <td>
                    {(rule.auto_approve?.carbon_ids?.length || 0) +
                      (rule.auto_approve?.silicon_ids?.length || 0) +
                      (rule.auto_approve?.tag_ids?.length || 0)}{" "}
                    selectors
                  </td>
                  <td>
                    <Show when={policies()?.can_manage}>
                      <button
                        class="button small"
                        onClick={() => setSelected(rule)}
                      >
                        Configure
                      </button>
                    </Show>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </div>
      <Show when={selected()} keyed>
        {(rule) => (
          <PolicyEditor
            org={props.org}
            rule={rule}
            close={() => setSelected()}
            saved={() => {
              setSelected();
              void controls.refetch();
            }}
          />
        )}
      </Show>
    </section>
  );
}

function PolicyEditor(props: {
  org: string;
  rule: RecordValue;
  close: () => void;
  saved: () => void;
}) {
  const [actors, setActors] = createSignal(props.rule.allowed_actors);
  const [approval, setApproval] = createSignal(props.rule.approval);
  const [carbons, setCarbons] = createSignal(
    (props.rule.auto_approve?.carbon_ids || []).join("\n"),
  );
  const [silicons, setSilicons] = createSignal(
    (props.rule.auto_approve?.silicon_ids || []).join("\n"),
  );
  const [tags, setTags] = createSignal(
    (props.rule.auto_approve?.tag_ids || []).join("\n"),
  );
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  const send = mutation();
  async function save(event: SubmitEvent) {
    event.preventDefault();
    setBusy(true);
    setError();
    try {
      await send(
        "PUT",
        `${orgPath(props.org)}/action-policies/${segment(props.rule.action)}`,
        {
          allowed_actors: actors(),
          approval: approval(),
          auto_approve: {
            carbon_ids: ids(carbons()),
            silicon_ids: ids(silicons()),
            tag_ids: ids(tags()),
          },
        },
        { version: props.rule.version },
      );
      props.saved();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title={`Configure ${props.rule.label || props.rule.action}`}
      close={props.close}
    >
      <form class="stack" onSubmit={save}>
        <Field name="Who can perform this action">
          <select
            value={actors()}
            onChange={(event) => setActors(event.currentTarget.value)}
          >
            <For each={Object.entries(actorLabels)}>
              {([value, label]) => <option value={value}>{label}</option>}
            </For>
          </select>
        </Field>
        <Field name="Required approval">
          <select
            value={approval()}
            onChange={(event) => setApproval(event.currentTarget.value)}
          >
            <For each={Object.entries(approvalLabels)}>
              {([value, label]) => <option value={value}>{label}</option>}
            </For>
          </select>
        </Field>
        <p class="muted">
          Automatically approve requests made by any listed Carbon, Silicon, or
          member of a listed tag. These exceptions do not grant permission to
          perform the action. When approval is required, leave all lists blank
          to require manual review.
        </p>
        <Field name="Carbon IDs">
          <textarea
            rows={3}
            placeholder="saket"
            value={carbons()}
            onInput={(event) => setCarbons(event.currentTarget.value)}
          />
        </Field>
        <Field name="Silicon IDs">
          <textarea
            rows={3}
            placeholder="chef:bricks"
            value={silicons()}
            onInput={(event) => setSilicons(event.currentTarget.value)}
          />
        </Field>
        <Field name="Tag IDs">
          <textarea
            rows={3}
            value={tags()}
            onInput={(event) => setTags(event.currentTarget.value)}
          />
        </Field>
        <p class="muted">Enter one ID per line, or separate IDs with commas.</p>
        <ErrorBox error={error()} />
        <button class="button primary" disabled={busy()}>
          {busy() ? "Saving…" : "Save rule"}
        </button>
      </form>
    </Modal>
  );
}

export function ActionApprovals(props: { org: string; revision: number }) {
  const [approvals, controls] = createResource(
    () => [props.org, props.revision] as const,
    ([org]) => request(`${orgPath(org)}/action-approvals`),
  );
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal<string>();
  const [selected, setSelected] = createSignal<RecordValue>();
  const send = mutation();
  async function decide(row: RecordValue, decision: string) {
    setBusy(row.id);
    setError();
    try {
      await send(
        "POST",
        `${orgPath(props.org)}/action-approvals/${segment(row.id)}/decisions`,
        { decision },
        { version: row.version },
      );
      setSelected();
      await controls.refetch();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy();
    }
  }
  return (
    <section class="panel padded stack">
      <div class="section-heading">
        <h2>Sensitive action requests</h2>
        <button class="button small" onClick={() => controls.refetch()}>
          Refresh
        </button>
      </div>
      <p class="muted">
        Review the exact proposed change before approving it. Approval lets the
        requester retry that same change.
      </p>
      <ErrorBox error={approvals.error || error()} retry={controls.refetch} />
      <Show when={approvals.loading}>
        <Loading />
      </Show>
      <For each={approvals()?.items || []}>
        {(row) => (
          <div class="section-heading">
            <div>
              <strong>{row.action}</strong>
              <p class="muted">
                {row.requested_by?.public_id} · {row.status} ·{" "}
                {date(row.created_at)}
              </p>
            </div>
            <button class="button small" onClick={() => setSelected(row)}>
              Review
            </button>
          </div>
        )}
      </For>
      <Show when={approvals() && !approvals()!.items.length}>
        <p class="muted">No sensitive action requests.</p>
      </Show>
      <Show when={selected()} keyed>
        {(row) => (
          <Modal title="Review sensitive action" close={() => setSelected()}>
            <div class="stack">
              <RecordDetails
                value={row}
                fields={[
                  "action",
                  "requested_by",
                  "status",
                  "method",
                  "path",
                  "request_body",
                  "expected_version",
                  "created_at",
                ]}
              />
              <Show when={row.can_decide && row.status === "pending"}>
                <div class="actions">
                  <button
                    class="button"
                    disabled={!!busy()}
                    onClick={() => decide(row, "reject")}
                  >
                    Reject
                  </button>
                  <button
                    class="button primary"
                    disabled={!!busy()}
                    onClick={() => decide(row, "approve")}
                  >
                    Approve this change
                  </button>
                </div>
              </Show>
            </div>
          </Modal>
        )}
      </Show>
    </section>
  );
}
