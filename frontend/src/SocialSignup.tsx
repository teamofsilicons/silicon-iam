import { createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { ApiError, mutation, request } from "./api";
import { ErrorBox } from "./ui";
type Provider = "google" | "apple";
export type SocialStatus = {
  status:
    | "pending"
    | "verified"
    | "already_registered"
    | "failed"
    | "expired"
    | "login_ready"
    | "link_required"
    | "signed_in";
  link?: { provider: Provider; request_id: string; poll_token: string };
  signup_session_id?: string;
  email?: string;
  display_name?: string;
};
export default function SocialSignup(props: {
  disabled: boolean;
  login?: boolean;
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
                (props.login ? item.login_enabled === true : item.enabled) &&
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
    const purpose = props.login ? "login" : "signup";
    const popup = window.open(
      "about:blank",
      "iam-social-signup",
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
      }>("POST", `/api/v1/${purpose}/social/${provider}/start`, {});
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
          "IAM returned an invalid sign-up lifetime. Please try again.",
        );
      let completing = false;
      const proof = {
        request_id: value.request_id,
        poll_token: value.poll_token,
      };
      const finishLogin = async () => {
        await send("POST", `/api/v1/login/social/${provider}/complete`, proof);
        if (disposed || current !== generation) return;
        await deliver({ status: "signed_in" });
      };
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
          if (completing) {
            await finishLogin();
            return;
          }
          const result = await send<SocialStatus>(
            "POST",
            `/api/v1/${purpose}/social/${provider}/status`,
            proof,
          );
          if (disposed || current !== generation) return;
          if (result.status === "pending") {
            timer = setTimeout(() => void poll(), 2000);
            return;
          }
          if (props.login && result.status === "login_ready") {
            completing = true;
            await finishLogin();
            return;
          }
          if (
            props.login &&
            result.status === "link_required" &&
            result.email
          ) {
            await deliver({ ...result, link: { provider, ...proof } });
            return;
          }
          if (
            result.status === "verified" ||
            result.status === "already_registered"
          ) {
            if (
              !result.email ||
              (result.status === "verified" && !result.signup_session_id)
            )
              throw new Error(
                "IAM could not confirm your verified profile. Please start again.",
              );
            await props.complete(result);
            stop();
            return;
          }
          setError(
            new Error(
              result.status === "expired"
                ? "This verification expired. Start again to continue."
                : "The provider could not complete verification. Try again or use your email.",
            ),
          );
          stop();
        } catch (cause) {
          if (disposed || current !== generation) return;
          if (
            cause instanceof ApiError &&
            cause.status >= 400 &&
            cause.status < 500 &&
            ![408, 425, 429].includes(cause.status)
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
          {props.login
            ? "Google and Apple sign-in are not available yet. Use your email, phone number or Carbon ID."
            : "Google and Apple sign-up are not configured yet. Continue with email to create your account."}
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
