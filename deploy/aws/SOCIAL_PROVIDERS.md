# Social provider operations

This is internal IAM deployment guidance. Applications continue using the same typed IAM popup and SLT protocol; they do not configure Google or Apple credentials.

## Configuration

Enable a provider only after the matching backend, schema, grants and frontend are deployed and their release gates pass. Provider discovery is server-controlled. The new login UI requires `login_enabled: true`; an older backend advertising signup alone cannot accidentally enable existing-account login.

| Provider | Runtime secret fields | Production callback |
| --- | --- | --- |
| Google | `IAM_GOOGLE_CLIENT_ID`, `IAM_GOOGLE_CLIENT_SECRET` | `https://backend.iam.teamofsilicons.com/api/v1/signup/social/google/callback` |
| Apple | `IAM_APPLE_CLIENT_ID`, `IAM_APPLE_CLIENT_SECRET` | `https://backend.iam.teamofsilicons.com/api/v1/signup/social/apple/callback` |

Each pair must be configured together. An absent pair keeps that provider unavailable. A partially configured pair fails configuration validation. Store values only in the protected runtime secret; never commit downloads, secret JSON, client secrets, Apple signing keys, provider authorization codes or poll proofs. Preserve all unrelated runtime fields when updating credentials.

The Google client is a Web application. Its authorized redirect URI must exactly match the callback, including scheme and path. IAM uses authorization code flow with S256 PKCE and requests email/profile. Apple uses the Services ID as client ID and a valid Apple client-secret JWT; register the exact HTTPS return URL and relevant verified domain. Apple posts the callback with `form_post`. Rotate its expiring client-secret JWT before expiry. Neither provider requires consumer applications to register callbacks.

The callback path intentionally retains `signup/social` for both signup and login. IAM stores the initiating intent and opaque state before redirecting; a browser must not change the callback or choose an account at callback time. `IAM_PUBLIC_BASE_URL` is the backend origin and `IAM_AUTH_BASE_URL` is the public IAM authentication origin. Verify these exact active values before changing provider console registration.

Apple private-relay delivery must allow IAM's actual verified mail sender. Current production sender is `iam@teamofsilicons.com`; register the appropriate sender/domain in Apple's relay configuration and preserve the verified Postmark sender configuration. Do not infer delivery success from provider login: verify relay email delivery separately.

## Apple client-secret generation and rotation

Use `deploy/aws/apple-client-secret.py` with Python 3 and `cryptography` installed. It performs local signing only: no provider requests, AWS calls, runtime updates, private-key changes or service restarts. Keep the Apple-downloaded PKCS#8 `.p8` file in an existing private directory owned by the operator (0700); the regular key file must have no group/world permissions (normally 0600) and no hard links. Input and output paths, including directory components, must not be symlinks. On systems where `/tmp` is a symlink, use its real directory path or a private folder under the operator's home.

Prepare a fresh candidate in a private output directory:

```sh
python3 deploy/aws/apple-client-secret.py generate \
  --key /absolute/private/apple/AuthKey_KEYID.p8 \
  --team-id APPLE_TEAM_ID \
  --key-id APPLE_KEY_ID \
  --services-id com.example.service \
  --output /absolute/private/apple/apple-candidate-YYYYMMDD.json
```

Replace the example IDs with the exact Apple registration values. Team ID and Key ID are ten uppercase alphanumeric characters; Services ID is case-sensitive. `--lifetime-days` defaults to 90 and accepts 1 through 180. The helper requires P-256 and produces ES256 with `kid`, `iss` equal to Team ID, `sub` equal to Services ID and `aud` equal to `https://appleid.apple.com`, then independently verifies the encoded signature. Apple's [client-secret specification](https://developer.apple.com/documentation/AccountOrganizationalDataSharing/creating-a-client-secret) limits expiry to six months; this operator's 180-day maximum stays within that limit.

The new candidate contains only `IAM_APPLE_CLIENT_ID` and `IAM_APPLE_CLIENT_SECRET`. Its adjacent `.receipt.json` contains nonsecret JWT header/claims, generation and expiry dates, public-key fingerprint, local signature-verification result and rotation due date. Both files are created with mode 0600. Standard output includes only the output paths and expiry/rotation dates; never `cat` the candidate into logs or pass its JWT as a command argument. The helper refuses existing files, including dangling symlinks, and atomically publishes each file without replacement after flushing both temporary files. An ordinary publication failure removes only files it created. A process or host crash can leave a partial file pair: treat that attempt as incomplete, preserve or privately remove its files, and regenerate with new names. Require both files and a successful exit before consuming the candidate.

For rotation, run the same command with `rotate` instead of `generate` and a **new** output filename. The existing key, previous candidate and live credential are preserved. Rotation is due 14 days before expiry; for lifetimes shorter than 28 days the lead is half the lifetime. Arrange operational tracking from the nonsecret receipt. The helper does not create an automatic rotation schedule or activate credentials. A valid local signature does not prove that the key is still enabled in Apple or that its Services ID/return URL is configured correctly.

After review, merge only the candidate's two fields into the current protected runtime configuration through the separate deployment operator. Preserve unrelated fields, record the previous/new secret version IDs and retain the previous version for rollback. Run the normal release and live provider acceptance checks below. Do not replace the whole runtime secret with this two-field candidate. Keep the `.p8` as the protected signing source for future rotations; do not upload it as a runtime variable or commit any generated file.

Synthetic-key validation (does not read a real Apple key):

```sh
python3 -B -m unittest discover -s deploy/aws -p test_apple_client_secret.py -v
```

## Account binding and recovery

IAM verifies provider token signature, issuer, audience, nonce and verified email before accepting the callback. Existing provider subjects authenticate only their bound active Carbon, even if a provider email changes. Suspended bindings cannot move to another account by matching an email. First-time provider linking to an existing IAM email requires a new, independent OTP session for that exact Carbon created after the provider request. Successful linking is audited and consumes the provider proof; the already-established OTP session continues the login.

A new verified email uses the existing signup session, optional phone verification and profile steps. A provider login never silently creates an account. Request proofs expire after ten minutes, remain private to the initiating client and are consumed once. Completion and linking support stable idempotent retries after uncertain responses. Security-epoch changes invalidate pending completion. Social providers remain unavailable in isolated testing environments; use testing identities for app integration tests.

## Release verification

1. Pass full CI, restricted-role PostgreSQL tests, frontend checks and the exact candidate image migration rehearsal on isolated copies of both live databases.
2. Preserve encrypted, versioned, checksum-verified paired quiesced backups and runtime configuration before applying the additive migrations and runtime grants.
3. Deploy the tested backend before the frontend, then merge only the intended provider fields into the protected runtime configuration. Restart the relevant services through the reviewed operator and verify exact source, health and provider discovery.
4. Verify a real provider login for an already-linked account and a fresh OTP first-link, plus new-account continuation where a dedicated test account is available. Synthetic callback fixtures prove UI/retry behavior, not real Google/Apple authorization.
5. Check user cancellation, expired proof, popup blocked/closed fallback, wrong OTP, idempotent retry and mail delivery. Keep an unconfigured provider visibly unavailable.

Do not change provider issuer/subject associations manually in SQL, bypass OTP linking, or advertise provider availability before its configuration and live acceptance checks are complete.
