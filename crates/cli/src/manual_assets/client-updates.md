# Client and CLI automatic updates

`silicon-iam-client` compares its compiled version with the newest stable release on crates.io and maintains the consuming Cargo project's lockfile. The policy is automatic by default and explicitly opt-out.

## What automatic means for a Rust library

Code already compiled into a running process cannot be replaced safely. After an IAM request finishes and its response has been decoded, the client checks crates.io if it has never attempted a check or its last attempt was at least one hour ago. No idle timer or daemon runs; another completed request triggers the next due check. If a newer stable release exists, it finds the nearest `Cargo.toml` at or above the process working directory and runs the equivalent of:

```
cargo update --manifest-path /path/to/Cargo.toml \
  -p silicon-iam-client --precise <latest-version>
```

The current process completes with its compiled version. The next Cargo build uses the updated lockfile. This avoids making the false promise that a Rust library can hot-swap itself.

## Opt out

```
let client = Client::builder("https://backend.iam.teamofsilicons.com")?
    .auto_update(false)
    .build()?;
```

Or disable it for one deployment without rebuilding:

```
SILICON_IAM_CLIENT_AUTO_UPDATE=false ./your-application
```

Values `0`, `false`, `no`, and `off` disable the updater. The default is automatic. When an application starts outside its source directory, select the manifest explicitly with `.update_manifest("/path/to/Cargo.toml")`.

## Observe the result

After an IAM call, `client.update_status()` reports the latest result: `Current`, `Updated`, `Disabled`, `NoCargoProject`, or `Failed`. A registry timeout, absent manifest, incompatible version constraint, or failed Cargo command never changes the IAM request's result. The registry check has a three-second timeout. One client and its clones share an in-memory last-attempt time with only one check running at a time; concurrent requests do not wait for another request's check. The request performing due maintenance waits for it before returning, without changing its IAM result. Failed or cancelled attempts retain the hourly throttle. Cancellation releases the single-flight slot; a Cargo operation already started retains the slot until it finishes on a blocking worker. Separately constructed clients have independent schedules, and restarting the process resets that in-memory state. There is no maintenance while the client is idle.

**The CLI has its own updater.** After a normal command completes and prints its result, the `iam` binary checks its persisted last-attempt time and, when at least one hour has elapsed, can replace itself with `cargo install` for the next invocation. The first use checks immediately after completion. Failures also record an attempt, and a cross-process lock prevents concurrent checks or installations. The command's output and exit status are preserved. No idle daemon or timer runs. Use `iam config set auto-update off` to opt out, or `SILICON_IAM_AUTO_UPDATE=false` for one invocation. `iam system update` explicitly bypasses opt-out and the hourly throttle, while retaining the concurrent-update lock. Help, command discovery and offline docs never trigger automatic maintenance.
