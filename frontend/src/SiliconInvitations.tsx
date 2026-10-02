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
import { Empty, ErrorBox, Field, Loading } from "./ui";

export function SiliconInvitations(props: { org: string; revision: number }) {
  const base = () => `${orgPath(props.org)}/silicon-invitations`;
  const [items, control] = createResource(
    () => [base(), props.revision] as const,
    ([path]) => request<{ items: RecordValue[] }>(path),
  );
  const [candidates, candidateControl] = createResource(
    () => [base(), props.revision] as const,
    ([path]) => request<{ items: RecordValue[] }>(`${path}/candidates`),
  );
  const [silicon, setSilicon] = createSignal(""),
    [busy, setBusy] = createSignal(false),
    [error, setError] = createSignal<unknown>();
  const send = mutation();
  async function invite(event: SubmitEvent) {
    event.preventDefault();
    if (busy() || !silicon()) return;
    setBusy(true);
    setError();
    try {
      await send("POST", base(), { silicon_id: silicon() });
      setSilicon("");
      await control.refetch();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  async function revoke(id: string) {
    if (busy()) return;
    setBusy(true);
    setError();
    try {
      await send("POST", `${base()}/${segment(id)}/revoke`, {});
      await Promise.all([control.refetch(), candidateControl.refetch()]);
    } catch (cause) {
      setError(cause);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section class="panel padded stack">
      <h2>Invite an existing Silicon</h2>
      <p class="muted">
        Invite a Silicon you can see in an organization you belong to. The
        Silicon accepts the invitation, and its existing custodian stays the
        same.
      </p>
      <ErrorBox error={candidates.error} retry={candidateControl.refetch} />
      <form class="stack" onSubmit={invite}>
        <Field name="Silicon" required>
          <select
            required
            value={silicon()}
            onChange={(event) => setSilicon(event.currentTarget.value)}
            disabled={candidates.loading || !!candidates.error}
          >
            <option value="">Select a Silicon</option>
            <For each={candidates()?.items || []}>
              {(item) => (
                <option value={item.silicon_id}>
                  {item.display_name || item.silicon_id} · {item.silicon_id}
                </option>
              )}
            </For>
          </select>
        </Field>
        <Show
          when={
            !candidates.loading &&
            !candidates.error &&
            candidates()?.items.length === 0
          }
        >
          <p class="muted">
            No eligible Silicons are available in your other organizations.
          </p>
        </Show>
        <ErrorBox error={error()} />
        <div class="actions">
          <button class="button primary" disabled={!silicon() || busy()}>
            {busy() ? "Sending invitation…" : "Invite Silicon"}
          </button>
        </div>
      </form>
      <ErrorBox error={items.error} retry={control.refetch} />
      <Show when={items.loading}>
        <Loading />
      </Show>
      <For each={items()?.items || []}>
        {(item) => (
          <div class="session-row">
            <div>
              <strong>{item.display_name || item.silicon_id}</strong>
              <small>
                {item.silicon_id} · {item.status} · Sent {date(item.created_at)}
              </small>
            </div>
            <Show when={item.status === "pending"}>
              <button
                class="button"
                disabled={busy()}
                onClick={() => void revoke(item.id)}
              >
                Revoke invitation
              </button>
            </Show>
          </div>
        )}
      </For>
    </section>
  );
}

export function SiliconInvitationInbox(props: { changed: () => unknown }) {
  const [items, control] = createResource(() =>
    request<{ items: RecordValue[] }>("/api/v1/me/silicon-invitations"),
  );
  const [busy, setBusy] = createSignal(""),
    [error, setError] = createSignal<unknown>();
  const send = mutation();
  async function decide(id: string, decision: "accept" | "decline") {
    if (busy()) return;
    setBusy(id);
    setError();
    try {
      await send(
        "POST",
        `/api/v1/me/silicon-invitations/${segment(id)}/decision`,
        { decision },
      );
      await control.refetch();
      if (decision === "accept") props.changed();
    } catch (e) {
      setError(e);
    } finally {
      setBusy("");
    }
  }
  return (
    <section class="panel padded stack">
      <h2>Organization invitations</h2>
      <p class="muted">Choose which organizations this Silicon joins.</p>
      <ErrorBox error={items.error} retry={control.refetch} />
      <ErrorBox error={error()} />
      <Show when={items.loading}>
        <Loading />
      </Show>
      <For
        each={items()?.items.filter((item) => item.status === "pending") || []}
        fallback={
          <Show when={!items.loading && !items.error}>
            <Empty title="No pending invitations">
              New organization invitations will appear here.
            </Empty>
          </Show>
        }
      >
        {(item) => (
          <article class="stack">
            <div>
              <strong>{item.organization_name}</strong>
              <p class="muted">
                {item.org_id} · Expires {date(item.expires_at)}
              </p>
            </div>
            <div class="actions">
              <button
                class="button primary"
                disabled={!!busy()}
                onClick={() => void decide(item.id, "accept")}
              >
                {busy() === item.id ? "Saving…" : "Join organization"}
              </button>
              <button
                class="button"
                disabled={!!busy()}
                onClick={() => void decide(item.id, "decline")}
              >
                Decline
              </button>
            </div>
          </article>
        )}
      </For>
    </section>
  );
}
