# operations

All examples use the pinned toolchain and locked dependency graph.

## build

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Native tests load module libraries from `target/debug/deps`, so build the
workspace before running `crates/snolc/tests/native_session.rs` after an ABI or
module change.

## package root

```sh
install -d -m 700 "$HOME/.local/share/snolc/packages"
cp config/packages/snolpkg.toml "$HOME/.local/share/snolc/packages/"
cp config/packages/sources.toml "$HOME/.local/share/snolc/packages/"
export SNOLPKG_ROOT="$HOME/.local/share/snolc/packages"
```

Install each selected module from the trusted source:

```sh
snolpkg add -b https://github.com/owenewans/snolc.git carrier-tcp
snolpkg template owenewans/carrier-tcp@0.0.1 --role server --output modules/tcp.toml
```

The binary command requires published release assets. Use `-s` to build the
signed source revision with Rust 1.98.1. It does not fall back between modes.

## server setup

Copy `config/templates/snolc-server-low-memory.toml` with its referenced module
files into a private deployment directory. Install exact package locks. Create
Noise and SSH keys at the paths named by module TOML. Set state and key
directories to mode 0700 and secret files to 0600.

Validate before start:

```sh
snolc validate /etc/snolc/snolc.toml
snolc run /etc/snolc/snolc.toml
```

The CLI owns SIGINT and SIGTERM handling. It asks the library to stop and waits
up to the configured shutdown timeout.

## create a user

Create `user-create.toml` with every selected mode:

```toml
method = "user.create"
client_id = "panel-main"
seq = 1

[user]
status = "enabled"
burst_bytes = 65507
weight = 1
group = "default"
rule_profile = "default"

[user.expiration]
mode = "unlimited"

[user.quota]
mode = "limited"
bytes = 1073741824

[user.upload_rate]
mode = "limited"
bytes_per_second = 62500

[user.download_rate]
mode = "limited"
bytes_per_second = 62500

[user.combined_rate]
mode = "limited"
bytes_per_second = 125000

[user.max_sessions]
mode = "limited"
count = 2

[user.max_flows]
mode = "limited"
count = 16

[user.weekly_access]
mode = "unlimited"
```

Send it through the local control socket:

```sh
snolc control /run/snolc/snolc.sock policy-main user-create.toml
```

Save the returned user ID and revision. The peer credential check on the Unix
socket must pass before policy sees this request.

## issue access

Create a client-only provisioning profile without a credential. It contains
the endpoint, pin, and exact client module records. Issue one credential and
print one URI:

```sh
snolc provision /run/snolc/snolc.sock policy-main provision-profile.toml \
  <32-hex-user-id> panel-main 2
```

The helper generates 32 random bytes, sends their SHA-256 in `credential.add`,
checks the committed response, and places the bearer in the returned URI. The
server database never stores the bearer.

## quota and revoke

Add quota with the next sequence:

```toml
method = "quota.add"
client_id = "panel-main"
seq = 3
user_id = "00112233445566778899aabbccddeeff"
bytes = 1073741824
```

Revoke a credential by digest:

```toml
method = "credential.revoke"
client_id = "panel-main"
seq = 4
credential_sha256 = "<64-hex-sha256>"
```

Submit each file with `snolc control`. A repeated sequence with the same bytes
returns its stored result. Changed or skipped sequence input fails.

## backup and restore

Request a consistent backup:

```toml
method = "maintenance.backup"
destination = "/var/lib/snolc/backup/policy.redb"
```

Policy pauses new work, closes redb, copies and verifies the file, then reopens
the live database. Check free space for the source and copy. Restore requires a
stopped policy and the `restore_stopped_database` administrative API. Never
replace a live database or auto-restore old quota state.

## logs and diagnostics

The file logger appends. At its limit, it preserves a bounded newest tail in a
temporary file and atomically replaces the log. A stale temporary file never
replaces the target on startup.

Use `EngineHandle::snapshot` for lifecycle and latest reasons. Subscribe to
events for scoped flow, session, instance, log, and platform failures. Debug
logs omit payload and secrets. Packet capture is a separate test operation.

## code update

Verify and install the new immutable package beside the old one. Keep user
config unchanged unless the new signed template documents a required contract
change. Stop the engine, update exact locks and config, validate, then restart.
Retain the old store until rollback no longer needs it. Never overwrite a
loaded library.
