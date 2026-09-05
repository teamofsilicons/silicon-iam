# Rust client webhook verification

Silicon IAM pushes directory changes to every Application authorized for the affected resource. The SDK verifies the signature over the exact bytes and hands you a parsed event; deduplication is yours, because only your database can do it durably.

## Verifying a delivery

```
use silicon_iam_client::{WebhookSecret, WebhookSecretKeyring, WebhookVerifier};

let keyring = WebhookSecretKeyring::new(7, WebhookSecret::new(secret)?)?;
let verified = WebhookVerifier::new(keyring).verify(&headers, &body)?;

// In ONE database transaction: insert this ID into a unique
// deduplication table, and apply the event's local side effect.
let event_id = verified.event_id();
let event = verified.event();
```

**Pass the framework's exact, unparsed body bytes.** The signature covers `{timestamp}.{exact body}`. Re-serialising the JSON changes whitespace and key order, and the signature will never match. Capture the body as bytes in your framework's earliest hook, before any middleware deserialises it.

What the verifier does before you see anything:

- authenticates the HMAC over the timestamp and the raw body, in constant time;

- rejects duplicate security headers, which is how a proxy-confusion attack starts;

- rejects stale timestamps, which is what stops a replay;

- bounds the body to 1 MiB by default;

- only then parses JSON.

`X-Silicon-IAM-Signature` must have the exact canonical form `v1=<64 lowercase hexadecimal characters>`. It is HMAC-SHA256 over `{timestamp}.{exact body bytes}`; the version prefix is part of the header format, not part of the digest.

## Secret versions

The Application supplies its initial secret during registration. Explicit `rotate_webhook_secret` accepts a caller-chosen successor and immediately uses it for new deliveries. IAM never generates Application webhook secrets. Rotation requires the current Application version and a verified-channel step-up assertion for `application.webhook_secret.rotate`.

Replacing the webhook URL normally does **not** rotate the key: IAM rebinds the same secret under an incremented version. The exception is an imported test Application still using an inherited production key. Its first test URL replacement must supply a test-only `webhook_secret`; the v1 response echoes it as `webhook_signing_secret` with `secret_replay_expires_at`. Those optional fields are absent from ordinary replacement responses.

Keep every version that can still have an in-flight delivery:

```
let mut keyring = WebhookSecretKeyring::new(7, WebhookSecret::new(secret)?)?;

// A URL replacement created version 8 while v7 deliveries can still retry.
keyring.rebind_version(7, 8)?;
```

An explicit secret rotation uses the different key material you supplied. Install that with `keyring.insert(new_version, WebhookSecret::new(new_secret)?)` and retain the prior entry until its complete retry window has elapsed.

Deliveries carry `X-Silicon-IAM-Key-Version`, so the verifier selects by version rather than trying each secret in turn. Without the rebind, in-flight v7 retries fail verification and dead-letter — a self-inflicted outage that looks like an IAM problem.

## Deduplicate, and order by version

Delivery is **at least once**. A duplicate is normal, not exceptional, and arrival order is not guaranteed.

## Testing-environment deliveries

A test delivery is not shaped like a production event. Its exact signed body has one top-level `test` object containing `testing_key`, `metadata`, and `data`. Verify the signature over those outer bytes first; then deduplicate on `test.metadata.event_id` and order on `test.metadata.aggregate.version`.

```
let verified = verifier.verify(&headers, &body)?;
if verified.is_testing() {
    // Constant-time comparison. The received key is never exposed by the SDK.
    verified.verify_testing_environment(&expected_environment_key)?;
}

// event() is normalized to WebhookEvent for both wire shapes.
let event = verified.event();
```

**`testing_key` is live root authority.** Compare it with the expected environment key without timing leakage, route the event to the isolated test run, and redact it. Never log it or persist it with the event payload.

The complete setup, import, login, negative-boundary assertions, and cleanup sequence is in Testing environments (`iam docs client/testing-environments`).

| Use | For |
| --- | --- |
| `verified.event_id()` | Deduplication. Insert into a unique index in the same transaction as the side effect. |
| The aggregate version on the event | Ordering. It is the only reliable sequencing signal. |

Respond `2xx` quickly and do the work asynchronously. A slow endpoint becomes a retrying endpoint, and a retrying endpoint becomes a dead-lettered one.

## Event types

The authenticated event name is available as `verified.event().event_type`. Treat it as a versioned public vocabulary and keep an unknown-type branch: adding a new event must not make your receiver reject an otherwise valid delivery or skip the quick `2xx` response.

## Recovering missed deliveries

Anything that exhausts its retry cycle is dead-lettered and stays readable and replayable through the API. Replays preserve the original event ID, so your existing deduplication table handles them without any special case — see the contract's webhook section (`iam docs api/webhooks`) for the replay semantics.
