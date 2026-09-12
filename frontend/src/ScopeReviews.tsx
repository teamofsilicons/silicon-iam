import { createSignal, For, Show } from "solid-js";
import { createResource } from "./resource";
import { date, mutation, request, segment } from "./api";
import {
  Badge,
  Empty,
  ErrorBox,
  Field,
  Loading,
  PageFooter,
  PageTitle,
  usePage,
} from "./ui";

export default function ScopeReviews() {
  const [status, setStatus] = createSignal("pending"),
    [selected, setSelected] = createSignal(
      new URL(location.href).searchParams.get("request") || "",
    );
  const page = usePage(
    () =>
      `/api/v1/application-scope-requests${status() ? `?status=${status()}` : ""}`,
  );
  return (
    <>
      <PageTitle
        title="Scope reviews"
        subtitle="Review critical permissions and keep the conversation in one place."
      />
      <div class="scope-review-layout">
        <section class="panel">
          <div class="panel-toolbar">
            <h2>Requests</h2>
            <select
              aria-label="Filter scope reviews"
              value={status()}
              onChange={(e) => setStatus(e.currentTarget.value)}
            >
              <option value="pending">Pending</option>
              <option value="approved">Approved</option>
              <option value="denied">Denied</option>
              <option value="">All requests</option>
            </select>
          </div>
          <ErrorBox error={page.data.error} retry={page.refresh} />
          <Show when={!page.data.loading} fallback={<Loading />}>
            <Show
              when={page.data()?.items.length}
              fallback={
                <Empty title="No scope reviews">
                  Requests from your applications and applications requesting
                  access to your endpoints appear here.
                </Empty>
              }
            >
              <div class="review-inbox">
                <For each={page.data()?.items}>
                  {(review) => (
                    <button
                      class="review-inbox-item"
                      classList={{ selected: selected() === review.id }}
                      onClick={() => {
                        setSelected(review.id);
                        const url = new URL(location.href);
                        url.searchParams.set("request", review.id);
                        history.replaceState(null, "", url);
                      }}
                    >
                      <strong>{review.app_id}</strong>
                      <small>
                        Requests access to{" "}
                        {review.target_app_id || "Silicon IAM"}
                      </small>
                      <span>
                        <Badge value={review.status} />{" "}
                        <small>{date(review.updated_at)}</small>
                      </span>
                    </button>
                  )}
                </For>
              </div>
            </Show>
            <PageFooter page={page} />
          </Show>
        </section>
        <Show
          keyed
          when={selected()}
          fallback={
            <section class="panel">
              <Empty title="Select a request">
                Read the requested permissions, discussion, and decision here.
              </Empty>
            </section>
          }
        >
          {(id) => <ReviewThread id={id} refresh={page.refresh} />}
        </Show>
      </div>
    </>
  );
}

function ReviewThread(props: { id: string; refresh: () => unknown }) {
  const path = `/api/v1/application-scope-requests/${segment(props.id)}`;
  const [review, { refetch }] = createResource(() => request(path));
  const [message, setMessage] = createSignal(""),
    [reason, setReason] = createSignal(""),
    [busy, setBusy] = createSignal(false),
    [error, setError] = createSignal<unknown>();
  const send = mutation();
  async function submit(decision?: "approve" | "deny") {
    if (busy() || !review()) return;
    setBusy(true);
    setError();
    try {
      if (decision === "deny" && !reason().trim())
        throw new Error(
          "Give a reason so the requester understands what needs to change.",
        );
      if (!decision && !message().trim())
        throw new Error("Write a message before sending it.");
      await send(
        "POST",
        `${path}/${decision ? "decisions" : "messages"}`,
        decision
          ? {
              decision,
              ...(reason().trim() ? { reason: reason().trim() } : {}),
            }
          : { message: message().trim() },
        { version: review()!.version },
      );
      if (decision) setReason("");
      else setMessage("");
      await refetch();
      await props.refresh();
    } catch (cause) {
      setError(cause);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section class="panel padded stack">
      <ErrorBox error={review.error || error()} retry={refetch} />
      <Show
        when={review()}
        fallback={
          <Show when={review.loading}>
            <Loading />
          </Show>
        }
      >
        {(value) => (
          <>
            <div class="section-heading">
              <div>
                <h2>{value().app_id}</h2>
                <p>
                  Critical access to {value().target_app_id || "Silicon IAM"}
                </p>
              </div>
              <Badge value={value().status} />
            </div>
            <ul>
              <For each={value().scopes}>
                {(scope: string) => (
                  <li>
                    <code>{scope}</code>
                  </li>
                )}
              </For>
            </ul>
            <div class="review-thread" aria-label="Review discussion">
              <For each={value().messages}>
                {(item) => (
                  <article>
                    <header>
                      <strong>
                        {item.author?.public_id ||
                          (item.author ? "Reviewer" : "Review instructions")}
                      </strong>
                      <time>{date(item.created_at)}</time>
                    </header>
                    <p>{item.message}</p>
                  </article>
                )}
              </For>
            </div>
            <Show when={value().reason}>
              <div class="notice">
                <strong>Decision reason</strong>
                <p class="review-text">{value().reason}</p>
              </div>
            </Show>
            <form
              class="stack"
              onSubmit={(e) => {
                e.preventDefault();
                void submit();
              }}
            >
              <Field name="Reply">
                <textarea
                  required
                  maxlength={10000}
                  rows={4}
                  value={message()}
                  onInput={(e) => setMessage(e.currentTarget.value)}
                />
              </Field>
              <button
                class="button align-start"
                disabled={busy() || !message().trim()}
              >
                Send reply
              </button>
              <small>
                Participants receive email notifications for new replies and
                decisions.
              </small>
            </form>
            <Show when={value().can_decide && value().status === "pending"}>
              <fieldset disabled={busy()} class="stack">
                <legend>Review decision</legend>
                <Field
                  name="Reason"
                  hint="Required when denying; explain the changes needed before approval."
                >
                  <textarea
                    maxlength={10000}
                    rows={3}
                    value={reason()}
                    onInput={(e) => setReason(e.currentTarget.value)}
                  />
                </Field>
                <div class="actions">
                  <button
                    class="button primary"
                    onClick={() => void submit("approve")}
                  >
                    Approve these scopes
                  </button>
                  <button
                    class="button danger"
                    disabled={!reason().trim()}
                    onClick={() => void submit("deny")}
                  >
                    Deny with reason
                  </button>
                </div>
              </fieldset>
            </Show>
          </>
        )}
      </Show>
    </section>
  );
}
