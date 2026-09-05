# Local state and concurrent CLI use

The CLI stores profiles, sessions and updater state under `~/.silicon-iam`, or the directory selected by `SILICON_IAM_HOME`. A home may be shared by concurrent CLI processes; production sessions and each testing-environment session remain separate.

State changes lock the complete read/modify/write operation across processes and merge into the latest document. Readers see a complete old or new JSON document, never a truncated intermediate write. Each write creates a unique temporary file, syncs it, then atomically renames it into place. On Unix, new directories are `0700`, files are `0600` from creation, and the containing directory is synced after rename.

Each profile/environment session has its own transition lock. Refresh re-reads the session after acquiring that lock and keeps it through idempotency-key reservation, the network exchange and credential commit. A concurrent command uses the newly refreshed session instead of exchanging the old refresh token again. Login commits and local/remote logout use the same lock, so a refresh cannot resurrect a logged-out session or overwrite a later login. An uncertain refresh or remote logout retains its original idempotency key for an exact retry.

Do not delete `credentials.lock` or the `session-*.lock` files while CLI processes are running. Locks are released automatically when a process exits; the empty files are intentionally retained to keep a stable locking identity.

On Unix, the IAM home must be owned by the current user with mode `0700`. If an older CLI created it with broader permissions, first inspect that this is your intended directory, then run `chmod 700 "$SILICON_IAM_HOME"` (or `chmod 700 ~/.silicon-iam` for the default). Credential, config and lock paths must be regular files, not symbolic links, devices or hard links; they must be owned by the current user and not writable by others. IAM rejects unsafe paths without changing link targets. Directory-relative no-follow operations keep writes anchored to the verified home. Windows uses the user's profile-directory access controls and rejects symbolic-link/reparse-point state paths; Unix permission modes do not apply there.

Use a local filesystem with working file locks and atomic rename. Do not share one credential home through a sync service or a filesystem that does not preserve those semantics. Separate homes are also useful when agents should not share credentials.
