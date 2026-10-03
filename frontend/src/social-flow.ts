export type Provider = "google" | "apple";
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
  signup_session_id?: string;
  email?: string;
  display_name?: string;
};

/** Both entry points authenticate provider email using the same proof ceremony. */
export function socialContinuation(
  value: SocialStatus,
): "wait" | "login" | "signup" {
  if (value.status === "pending") return "wait";
  if (value.status === "login_ready") return "login";
  if (value.status === "verified" && value.email && value.signup_session_id)
    return "signup";
  if (value.status === "link_required" || value.status === "already_registered")
    throw new Error(
      "This sign-in request used an older flow. Start again to continue.",
    );
  if (value.status === "expired")
    throw new Error("This verification expired. Start again to continue.");
  throw new Error(
    "The provider could not verify your email. Start again or use an email code.",
  );
}

export type SocialProof = { request_id: string; poll_token: string };
/** Retain the completion phase after an uncertain response; never consume a proof twice. */
export function socialAttempt(
  provider: Provider,
  proof: SocialProof,
  send: (path: string, proof: SocialProof) => Promise<unknown>,
) {
  let completing = false;
  return async (): Promise<SocialStatus> => {
    if (!completing) {
      const value = (await send(
        `/api/v1/login/social/${provider}/status`,
        proof,
      )) as SocialStatus;
      const next = socialContinuation(value);
      if (next !== "login") return value;
      completing = true;
    }
    await send(`/api/v1/login/social/${provider}/complete`, proof);
    return { status: "signed_in" };
  };
}
