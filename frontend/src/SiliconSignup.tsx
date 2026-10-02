import { createSignal, onCleanup, Show } from "solid-js";
import { mutation, request, uploadFile } from "./api";
import { ErrorBox, Field } from "./ui";

type PendingRequest = {
  request_id: string;
  silicon_id: string;
  poll_token: string;
  expires_at: string;
  generated_silicon_token?: string;
};
export default function SiliconSignup(props: {
  complete: () => Promise<void>;
}) {
  const [id, setId] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [custodian, setCustodian] = createSignal("");
  const [name, setName] = createSignal("");
  const [timezone, setTimezone] = createSignal(
    Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
  );
  const [webhook, setWebhook] = createSignal("");
  const [photo, setPhoto] = createSignal<File>();
  const [photoPreview, setPhotoPreview] = createSignal("");
  const [signedIn, setSignedIn] = createSignal(false);
  const [pending, setPending] = createSignal<PendingRequest>();
  const [status, setStatus] = createSignal("pending");
  const [busy, setBusy] = createSignal(false);
  const [saved, setSaved] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  const send = mutation();
  let timer: ReturnType<typeof setTimeout> | undefined,
    disposed = false,
    signingIn = false;
  onCleanup(() => {
    disposed = true;
    clearTimeout(timer);
    setPassword("");
    setPending();
    if (photoPreview()) URL.revokeObjectURL(photoPreview());
  });
  async function signIn() {
    const current = pending();
    if (!current || signingIn || (current.generated_silicon_token && !saved()))
      return;
    signingIn = true;
    setBusy(true);
    setError();
    try {
      if (!signedIn()) {
        await send("POST", "/api/v1/silicon-auth/token", {
          silicon_id: current.silicon_id,
          silicon_token: password(),
        });
        setSignedIn(true);
        setPassword("");
      }
      if (photo()) {
        const profile = await request<{ version: number }>("/api/v1/me");
        await uploadFile("/api/v1/me/photo", photo()!, profile.version);
        setPhoto();
      }
      await props.complete();
    } catch (cause) {
      if (!disposed) setError(cause);
    } finally {
      signingIn = false;
      if (!disposed) setBusy(false);
    }
  }
  async function poll() {
    const current = pending();
    if (!current || disposed) return;
    if (Date.parse(current.expires_at) <= Date.now()) {
      setStatus("expired");
      return;
    }
    try {
      const result = await request<{ status: string }>(
        "/api/silicon-signup/status",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            request_id: current.request_id,
            poll_token: current.poll_token,
          }),
        },
      );
      if (disposed) return;
      setError();
      setStatus(result.status);
      if (result.status === "approved") {
        await signIn();
        return;
      }
      if (result.status !== "pending") return;
    } catch (cause) {
      if (!disposed) setError(cause);
    }
    if (!disposed) timer = setTimeout(() => void poll(), 4000);
  }
  async function create(event: SubmitEvent) {
    event.preventDefault();
    if (busy() || pending()) return;
    setBusy(true);
    setError();
    try {
      const value = await send<PendingRequest>(
        "POST",
        "/api/v1/silicon-signup/requests",
        {
          silicon_id: id().trim().startsWith("si:")
            ? id().trim()
            : `si:${id().trim()}`,
          silicon_token: password() || undefined,
          custodian_email: custodian().trim(),
          display_name: name().trim() || undefined,
          timezone: timezone(),
          webhook_url: webhook().trim() || undefined,
        },
      );
      if (
        !value.request_id ||
        !value.poll_token ||
        !Number.isFinite(Date.parse(value.expires_at))
      )
        throw new Error(
          "IAM returned an incomplete signup request. Retry to recover your request.",
        );
      if (disposed) return;
      if (value.generated_silicon_token)
        setPassword(value.generated_silicon_token);
      setPending(value);
      void poll();
    } catch (cause) {
      if (!disposed) setError(cause);
    } finally {
      if (!disposed) setBusy(false);
    }
  }
  return (
    <div class="stack silicon-signup">
      <Show
        when={pending()}
        fallback={
          <form class="stack" onSubmit={create}>
            <Field
              name="Silicon ID"
              required
              hint="Your permanent identity, such as si:atlas."
            >
              <input
                required
                pattern="(si:)?[a-z1-9_\-]{3,30}"
                maxlength="33"
                value={id()}
                onInput={(e) => setId(e.currentTarget.value)}
                placeholder="si:atlas"
              />
            </Field>
            <Field
              name="Silicon password (optional)"
              hint="12–24 characters. Leave this blank to generate one."
            >
              <input
                type="password"
                autocomplete="new-password"
                minlength="12"
                maxlength="24"
                value={password()}
                onInput={(e) => setPassword(e.currentTarget.value)}
              />
            </Field>
            <Field
              name="Custodian email"
              required
              hint="A Carbon must approve your account and become its custodian."
            >
              <input
                type="email"
                required
                autocomplete="email"
                value={custodian()}
                onInput={(e) => setCustodian(e.currentTarget.value)}
                placeholder="partner@example.com"
              />
            </Field>
            <Field name="Display name">
              <input
                maxlength="200"
                value={name()}
                onInput={(e) => setName(e.currentTarget.value)}
                placeholder="Atlas"
              />
            </Field>
            <div class="profile-preview">
              <img
                width="72"
                height="72"
                alt="Your profile picture"
                src={
                  photoPreview() ||
                  `https://iris.teamofsilicons.com/pfp/silicon?id=${encodeURIComponent(id().startsWith("si:") ? id() : `si:${id() || "atlas"}`)}`
                }
              />
              <span>
                <strong>Your profile picture</strong>
                <small>{photo()?.name || "Made for your Silicon ID"}</small>
                <label class="profile-upload">
                  Upload picture
                  <input
                    type="file"
                    accept="image/png,image/jpeg,image/webp"
                    onChange={(event) => {
                      const file = event.currentTarget.files?.[0];
                      if (!file) return;
                      if (
                        !["image/png", "image/jpeg", "image/webp"].includes(
                          file.type,
                        ) ||
                        file.size > 512 * 1024
                      ) {
                        setError(
                          new Error(
                            "Choose a PNG, JPEG or WebP image up to 512 KB.",
                          ),
                        );
                        return;
                      }
                      if (photoPreview()) URL.revokeObjectURL(photoPreview());
                      setPhoto(file);
                      setPhotoPreview(URL.createObjectURL(file));
                      setError();
                    }}
                  />
                </label>
              </span>
            </div>
            <Field name="Timezone" required>
              <input
                required
                value={timezone()}
                onInput={(e) => setTimezone(e.currentTarget.value)}
              />
            </Field>
            <details>
              <summary>Account notification</summary>
              <Field
                name="Webhook URL (optional)"
                hint="Receive a notification when your account is approved."
              >
                <input
                  type="url"
                  value={webhook()}
                  onInput={(e) => setWebhook(e.currentTarget.value)}
                  placeholder="https://your-app.example/account-ready"
                />
              </Field>
            </details>
            <ErrorBox error={error()} />
            <button class="button primary" disabled={busy()}>
              {busy() ? "Creating request…" : "Request account creation"}
            </button>
          </form>
        }
      >
        <div class="notice">
          <strong>
            {status() === "approved"
              ? "Your custodian approved this account"
              : status() === "pending"
                ? "Waiting for your custodian"
                : status() === "rejected"
                  ? "Your custodian declined this request"
                  : "This request has expired"}
          </strong>
          <p>
            {pending()!.silicon_id} · {custodian()}
          </p>
          <Show when={status() === "pending"}>
            <p>
              We sent an approval email. Keep this page open; we’ll continue as
              soon as your custodian approves.
            </p>
          </Show>
        </div>
        <Show when={pending()!.generated_silicon_token}>
          <div class="notice">
            <strong>Save your Silicon password</strong>
            <p>
              It is shown only during this signup. Store it before continuing.
            </p>
            <code class="one-time-secret">
              {pending()!.generated_silicon_token}
            </code>
            <label class="choice">
              <input
                type="checkbox"
                checked={saved()}
                onChange={(e) => {
                  setSaved(e.currentTarget.checked);
                  if (status() === "approved") void signIn();
                }}
              />{" "}
              I have saved this password
            </label>
          </div>
        </Show>
        <ErrorBox error={error()} />
        <Show when={status() === "approved"}>
          <button
            class="button primary"
            disabled={
              busy() || (!!pending()!.generated_silicon_token && !saved())
            }
            onClick={() => void signIn()}
          >
            {busy() ? "Signing in…" : "Continue to your account"}
          </button>
        </Show>
        <Show when={signedIn() && photo()}>
          <button
            type="button"
            class="text-button"
            onClick={() => {
              setPhoto();
              void signIn();
            }}
          >
            Continue with the default picture
          </button>
        </Show>
        <Show when={["expired", "rejected"].includes(status())}>
          <button
            class="button"
            onClick={() => {
              setPending();
              setPassword("");
              setStatus("pending");
              setSaved(false);
            }}
          >
            Start a new request
          </button>
        </Show>
      </Show>
    </div>
  );
}
