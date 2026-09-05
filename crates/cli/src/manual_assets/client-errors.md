# Rust client errors and safe retry policy

Match the error variant first, then match a service error's stable `code`; never branch on human-readable prose.

## The taxonomy

| Variant | Means | Recovery |
| --- | --- | --- |
| `Error::Invalid` | A local value cannot form a request, such as an invalid URL, environment key or idempotency key. | Fix the input; do not retry it unchanged. |
| `Error::ApiVersionUnsupported` | The service offers no API major this crate implements. | Upgrade the client or correct the service target. |
| `Error::Transport` | No complete response arrived because of a connection, TLS, timeout, or failure while reading the response. | The outcome may be unknown. A mutation may be retried only with its original `Mutation`. |
| `Error::Decode` | A response arrived but its body did not match the expected contract, or negotiation invariants disagreed. | Do not blindly retry. Retain the mutation key and request ID, then investigate a client/service compatibility bug. |
| `Error::UnstructuredResponse` | An HTTP failure arrived without IAM's error envelope, for example an edge-generated HTML `403`. This does not establish an IAM authorization decision. | Check the service URL and edge/proxy logs using the HTTP status and optional response request ID. Do not retry blindly or assume another login will fix it. |
| `Error::ResponseTooLarge` | A response body exceeded the fixed 4 MiB client bound, whether or not it declared a length first. | Do not blindly retry. Retain the mutation key and investigate the service or intermediary response. |
| `Error::Api` | IAM returned its structured error envelope. | Use the status, stable code and classifiers on `ApiError`. |
| `Error::RateLimited` | IAM returned `429`; the variant holds the retry delay, optional counts and service envelope. | Wait at least `retry_after`, then resend unchanged with the same mutation when applicable. |

## Reading an API error

```
use silicon_iam_client::{Error, Mutation};

let refreshing = Mutation::new();
match application
    .oauth()
    .refresh(app_id, refresh_token, &refreshing)
    .await
{
    Ok(replacement) => { /* store it atomically */ }
    Err(Error::Api(api)) => {
        eprintln!("IAM {} {} request={:?}",
            api.status, api.code, api.request_id);

        if api.is_version_conflict() {
            // Re-read the resource before deciding on a new mutation.
        } else if api.requires_step_up() {
            // Complete step-up for the documented action and resource UUID.
        }
    }
    Err(Error::RateLimited { retry_after, source, .. }) => {
        eprintln!("wait {:?}; request={:?}", retry_after, source.request_id);
    }
    Err(other) => return Err(other),
}
```

`ApiError` exposes `status`, `code`, `message`, optional `details`, and optional `request_id`. Helpers classify unauthenticated, forbidden, hidden/not-found, version conflict, step-up, idempotency conflict and retryable service responses. The outer `Error::request_id()` and `Error::api()` work for both ordinary API and rate-limit errors.

`Error::UnstructuredResponse` retains the observed HTTP `status` and a well-formed UUID `X-Request-Id` when present; `Error::request_id()` exposes that correlation hint, while `Error::api()` returns `None`. The client does not retain or print HTML, other raw error bodies, or arbitrary response headers. A missing request ID remains missing: neither a status nor a proxy-branded page identifies a particular firewall rule or proves whether the backend processed the operation.

## Retry and recovery

**The SDK does not retry requests automatically.** For a mutating call whose outcome is uncertain, retain the exact input and reconstruct the same `Mutation` from its saved idempotency key. A fresh key represents a new operation and can duplicate a side effect or trigger refresh-reuse protection.

- `error.is_retryable()` is true for transport failures, `Error::RateLimited`, and API statuses `429`, `502`, `503`, and `504`. It is guidance, not an automatic retry.

- A `4xx` API error is authoritative. Change the request, re-authenticate, step up, or stop according to its stable code.

- `Error::Decode` is intentionally not classified as retryable. The server may have applied a successful mutation before the client failed to decode its body.

- `Error::ResponseTooLarge` is also not retryable: IAM may have applied the mutation before the client rejected its response. Preserve the original key while investigating.

- `Error::UnstructuredResponse` is not classified as retryable. Preserve the original mutation key and investigate the deployment boundary before deciding whether to retry.

- OBO proof verification accepts no idempotency key and is single-use. Never retry it after an ambiguous outcome.

## Transport guardrails

Client construction requires HTTPS except for literal local loopbacks and rejects service URLs with embedded credentials, a zero port, query, fragment, or no host. Requests never follow a redirect, so a credential is not forwarded away from the configured IAM endpoint. The 4 MiB response bound is enforced while streaming as well as from `Content-Length`.

## What to log

| Log | Do not log |
| --- | --- |
| Request ID, status, stable code, operation name, your correlation ID, and the idempotency key identifier when your policy permits it | Access, refresh, short-lived or OBO tokens; Application client or webhook secrets; testing root keys; raw callback query strings; successful secret-bearing response models |

Credential wrapper types redact their secret material from `Debug`, but successful response models deliberately expose values your application must store. Do not infer that every arbitrary string or model is safe to log.
