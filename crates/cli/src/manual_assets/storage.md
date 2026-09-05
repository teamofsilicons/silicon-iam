# Local state and concurrent CLI use

The CLI stores profiles, sessions and updater state under `~/.silicon-iam`, or the directory selected by `SILICON_IAM_HOME`. A home may be shared by concurrent CLI processes; production sessions and each testing-environment session remain separate.

State changes lock the complete read/modify/write operation across processes and merge into the latest document. Readers see a complete old or new JSON document, never a truncated intermediate write. Each write creates a unique temporary file, syncs it, then atomically renames it into place. On Unix, new directories are `0700`, files are `0600` from creation, and the containing directory is synced after rename.

Each profile/environment session has its own transition lock. Refresh re-reads the session after acquiring that lock and keeps it through idempotency-key reservation, the network exchange and credential commit. A concurrent command uses the newly refreshed session instead of exchanging the old refresh token again. Login commits and local/remote logout use the same lock, so a refresh cannot resurrect a logged-out session or overwrite a later login. An uncertain refresh or remote logout retains its original idempotency key for an exact retry.

Do not delete `credentials.lock` or the `session-*.lock` files while CLI processes are running. Locks are released automatically when a process exits; the empty files are intentionally retained to keep a stable locking identity.

## Upgrading an existing IAM home

On Unix, the IAM home must be owned by the current user with mode `0700`. Older
CLI installations may have created it with mode `0755`; 1.2.0 intentionally
rejects that directory even if its credential file is already `0600`. This
requires a one-time permission repair, not a new login or deleting credentials.

Before changing permissions, stop other CLI processes and inspect the exact
directory selected by `SILICON_IAM_HOME`, or `~/.silicon-iam` when it is unset.
Confirm it is the intended IAM-only directory, is not a symbolic link, and is
owned by your current user. Do not change permissions on a shared directory,
another user's home, or an unexpected link target. If the ownership or path is
wrong, resolve that deliberately or select a new private IAM home instead.

Only after those checks, repair the default home with:

```sh
chmod 700 ~/.silicon-iam
```

For a verified custom home, apply `chmod 700` to its exact quoted path instead.
Do not use recursive `chmod`, `sudo`, or broad paths for this repair. Retry the
original command after the repair; the stored profiles and sessions are kept.

Credential, config and lock paths must be regular files, not symbolic links,
devices or hard links; they must be owned by the current user and not writable
by others. IAM rejects unsafe paths without changing link targets.
Directory-relative no-follow operations keep writes anchored to the verified
home. Windows uses the user's profile-directory access controls and rejects
symbolic-link/reparse-point state paths; Unix permission modes do not apply
there.

Use a local filesystem with working file locks and atomic rename. Do not share one credential home through a sync service or a filesystem that does not preserve those semantics. Separate homes are also useful when agents should not share credentials.

## Diagnosing an unsuccessful logout

A local logout reports success only after the selected profile/environment's
credential removal has been persisted. A nonzero exit or a process terminated
by a signal is not a successful removal. A retained session after such a failure
is different from a session remaining after a confirmed successful removal.
Do not silently retry and discard the first failure's evidence.

The unreleased source adds phase-specific diagnostics: `Local credential
removal could not be confirmed.` identifies an unsuccessful local-removal
attempt, while `IAM confirmed remote logout, but local credential removal could
not be confirmed.` distinguishes a completed remote logout from a subsequent
local error. These messages preserve the underlying error and exit status;
they do not claim the local file remained unchanged, because a persistence
error can occur after the atomic rename.

For an individual failing command, retain:

- `iam --version`, the operating system, and whether the home uses a local
  filesystem or a shared/synced volume;
- the selected profile and production/test environment UUID, plus the logout
  mode (`logout`, `logout --all`, or `logout --local-only`);
- its exit code, any termination signal reported by the shell/process runner,
  and the exact success message if one was printed;
- its stderr, including any CLI context and service request ID, reviewed and
  sanitized before sharing; and
- whether another login, refresh, logout, or process was using that same home
  and selected session at the time.

In a shell, save `$?` immediately after the invocation, before running another
command. A process runner should retain each child's exit code or signal and
stderr separately, rather than only counting failures. Disable automatic
maintenance with `SILICON_IAM_AUTO_UPDATE=false` for a deliberate diagnostic
invocation if you need to isolate the command from post-command update output.
Do not run a remote logout again merely to gather diagnostics: it changes
server state. Preserve the original evidence first, then choose recovery based
on the reported failure.

Never share `credentials.json`, tokens, OTPs, testing-environment keys, raw
process environments, or unreviewed command lines. A test environment UUID is
not its secret environment key. Redact private profile/path names and personal
details from diagnostics while keeping different sessions distinguishable.

The 1.2.0 external audit recorded one unsuccessful concurrent logout without
its exit code or stderr; seven instrumented reruns then passed 672 calls. Its
cause remains unresolved. Those results do not establish a lost successful
write or prove that every concurrency/host failure is fixed.
