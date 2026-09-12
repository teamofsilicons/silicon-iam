import { createSignal, Match, onCleanup, Show, Switch } from "solid-js";
import {
  authDestination,
  continueDestination,
  mutation,
  type Configuration,
  type RecordValue,
  type SessionState,
} from "./api";
import { Brand, ErrorBox, Field, LocalOtp } from "./ui";
import ApplicationLogin from "./ApplicationLogin";

export default function Auth(props: {
  config: Configuration;
  session: SessionState;
}) {
  const signup = location.pathname === "/signup";
  const [identity, setIdentity] = createSignal(""),
    [challenge, setChallenge] = createSignal<RecordValue>(),
    [code, setCode] = createSignal("");
  const [step, setStep] = createSignal<
    "email" | "email-code" | "phone" | "phone-code" | "profile" | "created"
  >("email");
  const [email, setEmail] = createSignal(""),
    [phone, setPhone] = createSignal(""),
    [carbon, setCarbon] = createSignal(""),
    [name, setName] = createSignal("");
  const [busy, setBusy] = createSignal(false),
    [error, setError] = createSignal<unknown>(),
    [signupId, setSignupId] = createSignal(""),
    [localCode, setLocalCode] = createSignal("");
  const send = mutation(),
    appId = new URL(location.href).searchParams.get("app_id"),
    appIds = new URL(location.href).searchParams.get("app_ids"),
    bundleId = new URL(location.href).searchParams.get("bundle_id"),
    appLogin =
      new URL(location.href).searchParams.has("app_id") ||
      new URL(location.href).searchParams.has("app_ids") ||
      new URL(location.href).searchParams.has("bundle_id");
  const [handoff, setHandoff] = createSignal<"idle" | "loading" | "ready">(
    "idle",
  );
  let disposed = false;
  onCleanup(() => {
    disposed = true;
  });
  const pause = (ms: number) =>
    new Promise<void>((resolve) => setTimeout(resolve, ms));
  async function continueLogin() {
    if (handoff() !== "idle") return;
    if (appLogin) {
      // After OTP verification reload IAM's consent surface with its new
      // HttpOnly session. Never navigate to an app until selection is approved.
      location.assign(authDestination(props.config));
      return;
    }
    location.assign(continueDestination());
  }
  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (busy() || handoff() !== "idle") return;
    setBusy(true);
    setError();
    try {
      if (!signup || step() === "created") {
        if (challenge()) {
          await send(
            "POST",
            `/api/v1/login/challenges/${challenge()!.session_id}/verify`,
            { code: code() },
          );
          await continueLogin();
        } else {
          const value =
            step() === "created" ? email().trim() : identity().trim();
          setChallenge(
            await send(
              "POST",
              "/api/v1/login/challenges",
              value.includes("@")
                ? { email: value }
                : value.startsWith("+")
                  ? { phone_number: value }
                  : { carbon_id: value },
            ),
          );
        }
      } else {
        let id = signupId();
        if (!id) {
          const value = await send("POST", "/api/v1/signup/sessions");
          id = value.session_id;
          setSignupId(id);
        }
        const path = `/api/v1/signup/sessions/${id}`;
        if (step() === "email") {
          const value = await send("POST", `${path}/email`, {
            email: email().trim(),
          });
          if (value.already_exists)
            throw new Error(
              "This email already has an account. Sign in instead.",
            );
          setLocalCode(value.local_otp || "");
          setStep("email-code");
        } else if (step() === "phone") {
          const value = await send("POST", `${path}/phone`, {
            phone_number: phone().trim(),
          });
          if (value.already_exists)
            throw new Error(
              "This phone already has an account. Sign in instead.",
            );
          setLocalCode(value.local_otp || "");
          setStep("phone-code");
        } else if (step() === "email-code" || step() === "phone-code") {
          const contact = step() === "email-code" ? "email" : "phone";
          await send("POST", `${path}/${contact}/verify`, { code: code() });
          setCode("");
          setLocalCode("");
          setStep(contact === "email" ? "phone" : "profile");
        } else if (step() === "profile") {
          await send("POST", `${path}/complete`, {
            carbon_id: carbon(),
            display_name: name().trim(),
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          });
          setStep("created");
          setCode("");
        }
      }
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }
  const isCode = () => !!challenge() || step().endsWith("-code");
  const heading = () =>
    props.session.authenticated
      ? "You’re signed in"
      : isCode()
        ? "Check your messages"
        : !signup
          ? "Welcome back"
          : step() === "created"
            ? "Your account is ready"
            : step() === "profile"
              ? "Make it yours"
              : step() === "phone"
                ? "Verify your phone"
                : "Create your account";
  return (
    <main class="auth-layout">
      <aside class="auth-brand">
        <div class="auth-plate" aria-hidden="true">
          <span class="plate-grid" />
          <span class="plate-disc" />
          <span class="plate-dither" />
          <span class="plate-cross plate-cross-a" />
          <span class="plate-cross plate-cross-b" />
          <span class="plate-rule" />
          <span class="plate-index">SIL·IAM</span>
          <span class="plate-seq">AUTH /01</span>
        </div>
        <Brand />
        <div class="auth-statement">
          <p class="eyebrow">IDENTITY & ACCESS</p>
          <h1>
            One identity.
            <br />
            Your workspace.
          </h1>
          <p>
            Sign in to your account, manage your organizations, and connect your
            applications.
          </p>
        </div>
        <div class="auth-foot">
          <span class="status-dot" />
          Your identity stays with IAM.
        </div>
      </aside>
      <section class="auth-panel">
        <div class="auth-card">
          <p class="eyebrow">SILICON ACCOUNT</p>
          <h2>{heading()}</h2>
          <p class="muted">
            {props.session.authenticated
              ? `Continue as ${props.session.user?.display_name || props.session.user?.carbon_id}.`
              : isCode()
                ? "Enter the six-digit verification code. Codes expire; use the newest one."
                : !signup
                  ? "Use your email, phone number, or Carbon ID."
                  : step() === "created"
                    ? "Sign in with a fresh email code to start using IAM."
                    : step() === "profile"
                      ? "Choose a permanent Carbon ID and your display name."
                      : "Both your email and phone must be verified."}
          </p>
          <Show when={appLogin}>
            <div class="notice handoff-notice">
              <small>CONTINUING TO</small>
              <strong>
                {bundleId ||
                  (appIds ? `${appIds.split(",").length} applications` : appId)}
              </strong>
              <p>
                Your credentials stay here. Each application receives its own
                single-use, short-lived token.
              </p>
            </div>
          </Show>
          <Show when={new URL(location.href).searchParams.has("auth_error")}>
            <div class="notice error handoff-notice" role="alert">
              IAM could not complete this sign-in or organization join. Check
              the application, organization and callback settings, or try again.
              <small>
                Code:{" "}
                {new URL(location.href).searchParams
                  .get("auth_error")
                  ?.slice(0, 100)}
              </small>
            </div>
          </Show>
          <Show
            when={!props.session.authenticated}
            fallback={
              <Show
                when={appLogin}
                fallback={
                  <div class="stack">
                    <button
                      type="button"
                      class="button primary handoff-button"
                      classList={{ "handoff-ready": handoff() === "ready" }}
                      disabled={handoff() !== "idle"}
                      aria-busy={handoff() === "loading"}
                      onClick={() => void continueLogin()}
                    >
                      <span
                        role="status"
                        aria-live="polite"
                        class="handoff-label"
                      >
                        <Show when={handoff() === "loading"}>
                          <span class="handoff-spinner" aria-hidden="true" />
                        </Show>
                        <Show when={handoff() === "ready"}>
                          <svg
                            width="20"
                            height="20"
                            viewBox="0 0 24 24"
                            fill="none"
                            aria-hidden="true"
                          >
                            <path
                              d="m5 12 4 4L19 6"
                              stroke="currentColor"
                              stroke-width="2.5"
                              stroke-linecap="round"
                              stroke-linejoin="round"
                            />
                          </svg>
                        </Show>
                        {handoff() === "loading"
                          ? "Preparing your sign-in…"
                          : handoff() === "ready"
                            ? "Ready — continuing to application"
                            : appId
                              ? "Continue to application"
                              : "Open IAM console"}
                      </span>
                    </button>
                    <a href={props.config.consoleOrigin}>Manage your account</a>
                  </div>
                }
              >
                <ApplicationLogin />
              </Show>
            }
          >
            <form onSubmit={submit} class="stack">
              <Switch>
                <Match when={isCode()}>
                  <Field name="Verification code" required>
                    <input
                      autofocus
                      inputmode="numeric"
                      autocomplete="one-time-code"
                      pattern="[0-9]{6}"
                      maxlength="6"
                      required
                      value={code()}
                      onInput={(e) => setCode(e.currentTarget.value)}
                      placeholder="000000"
                    />
                  </Field>
                  <LocalOtp
                    code={challenge()?.local_otp || localCode()}
                    config={props.config}
                  />
                </Match>
                <Match when={!signup}>
                  <Field name="Email, phone, or Carbon ID" required>
                    <input
                      autofocus
                      autocomplete="username"
                      required
                      value={identity()}
                      onInput={(e) => setIdentity(e.currentTarget.value)}
                      placeholder="you@example.com"
                    />
                  </Field>
                </Match>
                <Match when={step() === "email"}>
                  <Field name="Email address" required>
                    <input
                      autofocus
                      type="email"
                      autocomplete="email"
                      required
                      value={email()}
                      onInput={(e) => setEmail(e.currentTarget.value)}
                      placeholder="you@example.com"
                    />
                  </Field>
                </Match>
                <Match when={step() === "phone"}>
                  <Field
                    name="Phone number"
                    hint="International format, including the country code."
                    required
                  >
                    <input
                      autofocus
                      type="tel"
                      autocomplete="tel"
                      pattern="\+[1-9][0-9]{7,14}"
                      required
                      value={phone()}
                      onInput={(e) => setPhone(e.currentTarget.value)}
                      placeholder="+919876543210"
                    />
                  </Field>
                </Match>
                <Match when={step() === "profile"}>
                  <Field
                    name="Carbon ID"
                    required
                    hint="3–30 lowercase letters, digits 1–9, underscores or hyphens. This cannot be changed."
                  >
                    <input
                      autofocus
                      required
                      pattern="[a-z1-9_\-]{3,30}"
                      maxlength="30"
                      value={carbon()}
                      onInput={(e) => setCarbon(e.currentTarget.value)}
                      placeholder="your-handle"
                    />
                  </Field>
                  <Field name="Display name" required>
                    <input
                      required
                      maxlength="200"
                      autocomplete="name"
                      value={name()}
                      onInput={(e) => setName(e.currentTarget.value)}
                    />
                  </Field>
                </Match>
              </Switch>
              <ErrorBox error={error()} />
              <button
                class="button primary handoff-button"
                classList={{ "handoff-ready": handoff() === "ready" }}
                disabled={busy() || handoff() !== "idle"}
                aria-busy={busy() && handoff() !== "ready"}
              >
                <span role="status" aria-live="polite" class="handoff-label">
                  <Show when={handoff() === "loading"}>
                    <span class="handoff-spinner" aria-hidden="true" />
                  </Show>
                  <Show when={handoff() === "ready"}>
                    <span aria-hidden="true">✓</span>
                  </Show>
                  {handoff() === "ready"
                    ? "Ready — continuing to application"
                    : handoff() === "loading"
                      ? "Preparing your sign-in…"
                      : busy()
                        ? "Please wait…"
                        : isCode()
                          ? challenge()
                            ? "Verify & sign in"
                            : "Verify code"
                          : signup && step() === "profile"
                            ? "Create account"
                            : signup && step() === "created"
                              ? "Send sign-in code"
                              : "Continue"}
                </span>
              </button>
              <Show when={isCode()}>
                <button
                  class="text-button"
                  type="button"
                  disabled={busy()}
                  onClick={() => {
                    setCode("");
                    setError();
                    if (challenge()) setChallenge();
                    else setStep(step() === "email-code" ? "email" : "phone");
                  }}
                >
                  Change contact or request a new code
                </button>
              </Show>
            </form>
            <p class="auth-switch">
              {signup ? "Already have an account?" : "New to Silicon?"}{" "}
              <a href={authDestination(props.config, !signup)}>
                {signup ? "Sign in" : "Create an account"}
              </a>
            </p>
          </Show>
          <div class="auth-note">
            {props.config.environment !== "Production"
              ? `${props.config.environment} · `
              : ""}
            No passwords. A verification code is sent to your verified contact.
          </div>
        </div>
        <footer class="auth-footer">
          Silicon IAM<span>Identity, without the overhead.</span>
        </footer>
      </section>
    </main>
  );
}
