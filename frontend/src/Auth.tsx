import { createSignal, Match, onCleanup, Show, Switch } from "solid-js";
import {
  authDestination,
  continueDestination,
  mutation,
  request,
  uploadFile,
  type Configuration,
  type RecordValue,
  type SessionState,
} from "./api";
import { Brand, ErrorBox, Field, LocalOtp } from "./ui";
import ApplicationLogin from "./ApplicationLogin";
import SocialSignup from "./SocialSignup";
import SiliconSignup from "./SiliconSignup";
import OboConsent from "./OboConsent";
import { isOboConsentLocation } from "./obo-consent-link";

export default function Auth(props: {
  config: Configuration;
  session: SessionState;
}) {
  const signup = location.pathname === "/signup";
  const addingAccount = new URL(location.href).searchParams.has("add_account");
  const authenticated = () => props.session.authenticated && !addingAccount;
  const [kind, setKind] = createSignal<"carbon" | "silicon">(
    new URL(location.href).searchParams.get("type") === "silicon"
      ? "silicon"
      : "carbon",
  );
  const [siliconToken, setSiliconToken] = createSignal("");
  const [timezone, setTimezone] = createSignal(
    Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
  );
  const [existingAccount, setExistingAccount] = createSignal(false);
  const [photo, setPhoto] = createSignal<File>();
  const [photoPreview, setPhotoPreview] = createSignal("");
  onCleanup(() => {
    if (photoPreview()) URL.revokeObjectURL(photoPreview());
  });
  function choosePhoto(event: Event) {
    const file = (event.currentTarget as HTMLInputElement).files?.[0];
    if (!file) return;
    if (
      !["image/png", "image/jpeg", "image/webp"].includes(file.type) ||
      file.size > 512 * 1024
    ) {
      setError(new Error("Choose a PNG, JPEG or WebP image up to 512 KB."));
      return;
    }
    if (photoPreview()) URL.revokeObjectURL(photoPreview());
    setPhoto(file);
    setPhotoPreview(URL.createObjectURL(file));
    setError();
  }
  async function finishProfile() {
    if (photo()) {
      const profile = await request<{ version: number }>("/api/v1/me");
      await uploadFile("/api/v1/me/photo", photo()!, profile.version);
      setPhoto();
    }
    await continueLogin();
  }
  const oboLogin = isOboConsentLocation(new URL(location.href));
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
      !oboLogin &&
      (new URL(location.href).searchParams.has("app_id") ||
        new URL(location.href).searchParams.has("app_ids") ||
        new URL(location.href).searchParams.has("bundle_id"));
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
      const destination = new URL(authDestination(props.config));
      destination.searchParams.delete("add_account");
      destination.searchParams.delete("type");
      location.assign(destination);
      return;
    }
    location.assign(continueDestination());
  }
  async function prepareProfile(contactEmail: string, suggestedName?: string) {
    const local = contactEmail.split("@")[0].split("+")[0];
    setName(
      suggestedName ||
        local
          .replace(/[._-]+/g, " ")
          .replace(/\b\w/g, (value) => value.toUpperCase()),
    );
    let handle = local
      .toLowerCase()
      .replace(/\./g, "_")
      .replace(/[^a-z1-9_-]/g, "")
      .slice(0, 24);
    if (handle.length < 3) handle += "member";
    setCarbon(handle);
    for (let attempt = 0; attempt < 8; attempt++) {
      const candidate = attempt ? `${handle}${attempt}` : handle;
      const available = await request<{ available: boolean }>(
        `/api/v1/carbon-ids/${encodeURIComponent(`c:${candidate}`)}/availability`,
      ).catch(() => ({ available: true }));
      if (available.available) {
        setCarbon(candidate);
        break;
      }
    }
  }
  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (busy() || handoff() !== "idle") return;
    setBusy(true);
    setError();
    try {
      if (signup && step() === "created") {
        await finishProfile();
      } else if (kind() === "silicon" && !signup) {
        await send("POST", "/api/v1/silicon-auth/token", {
          silicon_id: identity().trim(),
          silicon_token: siliconToken(),
        });
        setSiliconToken("");
        await continueLogin();
      } else if (!signup || step() === "created") {
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
          if (value.already_exists) {
            setExistingAccount(true);
            return;
          }
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
          if (contact === "email") {
            await prepareProfile(email());
          }
          setStep(contact === "email" ? "phone" : "profile");
        } else if (step() === "profile") {
          await send("POST", `${path}/complete`, {
            carbon_id: carbon().startsWith("c:") ? carbon() : `c:${carbon()}`,
            display_name: name().trim(),
            timezone: timezone(),
          });
          setCode("");
          setStep("created");
          await finishProfile();
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
    authenticated()
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
                ? "Add your phone"
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
        <div
          class="auth-card"
          classList={{
            "obo-auth-card": oboLogin && authenticated(),
          }}
        >
          <p class="eyebrow">SILICON ACCOUNT</p>
          <Show when={!oboLogin || !authenticated()}>
            <h2>{heading()}</h2>
            <p class="muted">
              {authenticated()
                ? `Continue as ${props.session.user?.display_name || props.session.user?.carbon_id}.`
                : isCode()
                  ? "Enter the six-digit verification code. Codes expire; use the newest one."
                  : !signup
                    ? kind() === "silicon"
                      ? "Use your Silicon ID and password to continue."
                      : "Use your email, phone number, or Carbon ID."
                    : step() === "created"
                      ? "Your account is ready to use."
                      : step() === "profile"
                        ? "Choose a permanent Carbon ID and your display name."
                        : kind() === "silicon"
                          ? "Create your identity with a Carbon custodian."
                          : "Start with your email. You can add a phone number later."}
            </p>
          </Show>
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
            when={!authenticated()}
            fallback={
              <Show
                when={appLogin || oboLogin}
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
                    <a
                      href={(() => {
                        const destination = new URL(
                          authDestination(props.config),
                        );
                        destination.searchParams.set("add_account", "1");
                        return destination.href;
                      })()}
                    >
                      Add another account
                    </a>
                  </div>
                }
              >
                <Show when={oboLogin} fallback={<ApplicationLogin />}>
                  <OboConsent />
                </Show>
              </Show>
            }
          >
            <Show when={!isCode() && (!signup || step() === "email")}>
              <div
                class="identity-tabs"
                role="tablist"
                aria-label="Account type"
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={kind() === "carbon"}
                  onClick={() => setKind("carbon")}
                >
                  Continue as Carbon
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={kind() === "silicon"}
                  onClick={() => setKind("silicon")}
                >
                  Continue as Silicon
                </button>
              </div>
            </Show>
            <Show
              when={signup && kind() === "silicon"}
              fallback={
                <>
                  <Show
                    when={signup && step() === "email" && kind() === "carbon"}
                  >
                    <SocialSignup
                      disabled={busy()}
                      busy={setBusy}
                      complete={async (value) => {
                        setEmail(value.email!);
                        if (value.status === "already_registered") {
                          setExistingAccount(true);
                          return;
                        }
                        setSignupId(value.signup_session_id!);
                        setExistingAccount(false);
                        await prepareProfile(value.email!, value.display_name);
                        setStep("phone");
                      }}
                    />
                  </Show>
                  <Show when={existingAccount()}>
                    <div class="notice">
                      <strong>This email is already registered.</strong>
                      <p>Sign in to your existing account to continue.</p>
                      <a
                        class="button"
                        href={(() => {
                          const url = new URL(authDestination(props.config));
                          if (addingAccount)
                            url.searchParams.set("add_account", "1");
                          return url.href;
                        })()}
                      >
                        Sign in to this account
                      </a>
                    </div>
                  </Show>
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
                      <Match when={!signup && kind() === "silicon"}>
                        <Field name="Silicon ID" required>
                          <input
                            required
                            autofocus
                            autocomplete="username"
                            value={identity()}
                            onInput={(event) =>
                              setIdentity(event.currentTarget.value)
                            }
                            placeholder="si:atlas"
                          />
                        </Field>
                        <Field name="Silicon password (STK)" required>
                          <input
                            type="password"
                            required
                            autocomplete="current-password"
                            value={siliconToken()}
                            onInput={(event) =>
                              setSiliconToken(event.currentTarget.value)
                            }
                          />
                        </Field>
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
                          name="Phone number (optional)"
                          hint="Verify your number if you add one. You can also skip this step."
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
                      <Match when={step() === "created"}>
                        <p>
                          Your account is ready. Finish uploading your picture
                          to continue.
                        </p>
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
                            pattern="(c:)?[a-z1-9_\-]{3,30}"
                            maxlength="30"
                            value={carbon()}
                            onInput={(e) => setCarbon(e.currentTarget.value)}
                            placeholder="your-handle"
                          />
                        </Field>
                        <div class="profile-preview">
                          <img
                            src={
                              photoPreview() ||
                              `https://iris.teamofsilicons.com/pfp/carbon?id=${encodeURIComponent(`c:${carbon()}`)}`
                            }
                            alt="Your profile picture"
                            width="72"
                            height="72"
                          />
                          <span>
                            <strong>Your profile picture</strong>
                            <small>
                              {photo()
                                ? photo()!.name
                                : "Made for your Carbon ID"}
                            </small>
                            <label class="profile-upload">
                              Upload picture
                              <input
                                type="file"
                                accept="image/png,image/jpeg,image/webp"
                                onChange={choosePhoto}
                              />
                            </label>
                          </span>
                        </div>
                        <Field name="Display name" required>
                          <input
                            required
                            maxlength="200"
                            autocomplete="name"
                            value={name()}
                            onInput={(e) => setName(e.currentTarget.value)}
                          />
                        </Field>
                        <Field name="Timezone" required>
                          <input
                            required
                            list="timezone-options"
                            value={timezone()}
                            onInput={(event) =>
                              setTimezone(event.currentTarget.value)
                            }
                          />
                          <datalist id="timezone-options">
                            <option
                              value={
                                Intl.DateTimeFormat().resolvedOptions().timeZone
                              }
                            />
                            <option value="UTC" />
                          </datalist>
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
                      <span
                        role="status"
                        aria-live="polite"
                        class="handoff-label"
                      >
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
                                    ? "Finish setup"
                                    : "Continue"}
                      </span>
                    </button>
                    <Show when={signup && step() === "created" && photo()}>
                      <button
                        class="text-button"
                        type="button"
                        onClick={() => {
                          setPhoto();
                          void continueLogin();
                        }}
                      >
                        Continue with the default picture
                      </button>
                    </Show>
                    <Show
                      when={
                        signup &&
                        (step() === "phone" || step() === "phone-code")
                      }
                    >
                      <button
                        type="button"
                        class="text-button"
                        disabled={busy()}
                        onClick={async () => {
                          setBusy(true);
                          setError();
                          try {
                            if (phone().trim())
                              await send(
                                "DELETE",
                                `/api/v1/signup/sessions/${signupId()}/phone`,
                              );
                            setPhone("");
                            setCode("");
                            setStep("profile");
                          } catch (cause) {
                            setError(cause);
                          } finally {
                            setBusy(false);
                          }
                        }}
                      >
                        Skip for now
                      </button>
                    </Show>
                    <Show when={isCode()}>
                      <button
                        class="text-button"
                        type="button"
                        disabled={busy()}
                        onClick={() => {
                          setCode("");
                          setError();
                          if (challenge()) setChallenge();
                          else
                            setStep(
                              step() === "email-code" ? "email" : "phone",
                            );
                        }}
                      >
                        Change contact or request a new code
                      </button>
                    </Show>
                  </form>
                </>
              }
            >
              <SiliconSignup complete={continueLogin} />
            </Show>
            <p class="auth-switch">
              {signup ? "Already have an account?" : "New to Silicon?"}{" "}
              <a
                href={(() => {
                  const url = new URL(authDestination(props.config, !signup));
                  if (addingAccount) url.searchParams.set("add_account", "1");
                  url.searchParams.set("type", kind());
                  return url.href;
                })()}
              >
                {signup ? "Sign in" : "Create an account"}
              </a>
            </p>
          </Show>
          <div class="auth-note">
            {props.config.environment !== "Production"
              ? `${props.config.environment} · `
              : ""}
            {kind() === "carbon"
              ? "Your account, protected with verified contact details."
              : "Your Silicon credentials stay securely in IAM."}
          </div>
        </div>
        <footer class="auth-footer">
          Silicon IAM<span>Identity, without the overhead.</span>
        </footer>
      </section>
    </main>
  );
}
