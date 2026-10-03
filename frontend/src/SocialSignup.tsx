import { createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { ApiError, mutation, request } from "./api";
import { ErrorBox } from "./ui";
import { socialAttempt, type Provider, type SocialStatus } from "./social-flow";
export default function SocialSignup(props: {
  disabled: boolean;
  complete: (value: SocialStatus) => Promise<void>;
  busy: (value: boolean) => void;
}) {
  const [providers, setProviders] = createSignal<Provider[]>([]);
  const [loaded, setLoaded] = createSignal(false);
  const [active, setActive] = createSignal<Provider>();
  const [authorization, setAuthorization] = createSignal("");
  const [error, setError] = createSignal<unknown>();
  const send = mutation();
  let timer: ReturnType<typeof setTimeout> | undefined,
    generation = 0,
    disposed = false;
  onMount(async () => {
    try {
      const value = await request<{
        providers: {
          id: Provider;
          enabled: boolean;
          login_enabled?: boolean;
        }[];
      }>("/api/v1/signup/social/providers");
      if (!disposed)
        setProviders(
          value.providers
            .filter(
              (item) =>
                item.enabled &&
                item.login_enabled === true &&
                ["google", "apple"].includes(item.id),
            )
            .map((item) => item.id),
        );
    } catch {
      /* Email signup stays available when provider discovery is unavailable. */
    } finally {
      if (!disposed) setLoaded(true);
    }
  });
  function stop() {
    generation++;
    clearTimeout(timer);
    setActive();
    setAuthorization("");
    props.busy(false);
  }
  async function deliver(value: SocialStatus) {
    stop();
    try {
      await props.complete(value);
    } catch (cause) {
      if (!disposed) setError(cause);
    }
  }
  onCleanup(() => {
    disposed = true;
    generation++;
    clearTimeout(timer);
  });
  async function start(provider: Provider) {
    if (props.disabled || active() || !providers().includes(provider)) return;
    const current = ++generation;
    const popup = window.open(
      "about:blank",
      "iam-social-authentication",
      "popup,width=520,height=700",
    );
    if (popup) popup.opener = null;
    setError();
    setActive(provider);
    props.busy(true);
    try {
      const value = await send<{
        request_id: string;
        authorization_url: string;
        poll_token: string;
        expires_at: string;
      }>("POST", `/api/v1/login/social/${provider}/start`, {});
      const url = new URL(value.authorization_url);
      if (
        url.protocol !== "https:" ||
        url.username ||
        url.password ||
        url.hostname !==
          (provider === "google" ? "accounts.google.com" : "appleid.apple.com")
      )
        throw new Error(
          "IAM returned an invalid provider destination. Please try again.",
        );
      if (disposed || current !== generation) {
        popup?.close();
        return;
      }
      setAuthorization(url.href);
      if (popup) popup.location.href = url.href;
      const expires = Date.parse(value.expires_at);
      if (!Number.isFinite(expires))
        throw new Error(
          "IAM returned an invalid sign-in lifetime. Please try again.",
        );
      const attempt = socialAttempt(
        provider,
        { request_id: value.request_id, poll_token: value.poll_token },
        (path, proof) => send("POST", path, proof),
      );
      const poll = async () => {
        if (disposed || current !== generation) return;
        if (Date.now() >= expires) {
          setError(
            new Error(
              "This provider verification expired. Start again to continue.",
            ),
          );
          stop();
          return;
        }
        try {
          const result = await attempt();
          if (disposed || current !== generation) return;
          if (result.status === "pending") {
            timer = setTimeout(() => void poll(), 2000);
            return;
          }
          if (result.status === "signed_in") {
            await deliver(result);
            return;
          }
          if (result.status === "verified") {
            await props.complete(result);
            stop();
            return;
          }
        } catch (cause) {
          if (disposed || current !== generation) return;
          if (
            !(cause instanceof ApiError) ||
            (cause instanceof ApiError &&
              cause.status >= 400 &&
              cause.status < 500 &&
              ![408, 425, 429].includes(cause.status))
          ) {
            setError(cause);
            stop();
            return;
          }
          setError(
            new Error(
              "Waiting to confirm your provider verification. Keep this page open, or continue with email.",
            ),
          );
          timer = setTimeout(() => void poll(), 5000);
        }
      };
      void poll();
    } catch (cause) {
      popup?.close();
      if (!disposed && current === generation) {
        setError(cause);
        stop();
      }
    }
  }
  return (
    <>
      <div class="social-signin" aria-label="Google and Apple account options">
        <For each={["google", "apple"] as Provider[]}>
          {(provider) => (
            <button
              type="button"
              class="button"
              disabled={
                !loaded() ||
                props.disabled ||
                !!active() ||
                !providers().includes(provider)
              }
              title={
                !providers().includes(provider)
                  ? "This provider is not available yet."
                  : undefined
              }
              aria-describedby="social-availability"
              onClick={() => void start(provider)}
            >
              {provider === "google" ? "Google" : "Apple"}
            </button>
          )}
        </For>
      </div>
      <Show when={loaded() && !providers().length}>
        <p id="social-availability" class="muted social-availability">
          Google and Apple are not available yet. Continue with your email.
        </p>
      </Show>
      <Show when={active()}>
        <div class="notice" role="status">
          <p>
            Continue with {active() === "google" ? "Google" : "Apple"} in the
            opened window.
          </p>
          <Show when={authorization()}>
            <a href={authorization()} target="_blank" rel="noopener noreferrer">
              Open provider verification
            </a>
          </Show>
          <button type="button" class="text-button" onClick={stop}>
            Use email instead
          </button>
        </div>
      </Show>
      <ErrorBox error={error()} />
    </>
  );
}
