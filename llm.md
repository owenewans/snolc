# snolc repository guide

Use this file to locate contracts and source. Read the named contract before you
edit its implementation. The public compatibility generation is
`wire_version = 1`. Rust code uses edition 2024 and the toolchain in
`rust-toolchain.toml`.

## source order

Resolve conflicts in this order:

1. `include/snolc.h` defines C ABI layout.
2. `spec/wire.md` defines network bytes.
3. strict TOML templates define complete supported configuration.
4. tests and implementation define executable behavior.
5. `spec/` defines design, limits, operations and release gates.
6. this guide maps those sources.

Package versions do not change `wire_version`. A build does not prove runtime
support. Check `spec/acceptance.md` and release evidence before you mark a gate
as passed.

## repositories

The project uses four repositories:

| repository | owner |
| --- | --- |
| `owenewans/snolc` | C ABI, Rust SDK, engine, CLI, core config and release tools |
| `owenewans/snolc-modules` | ten official modules, templates, manifests and native E2E |
| `owenewans/snolpkg` | signed module installer and archive parser |
| `owenewans/snolcNG` | profiles, desktop UI, Android service and APK |

Each dependent repository pins a full core commit. snolcNG pins the module
repository as a submodule. Update a pin through a pull request and run the gates
in both repositories.

The core tree contains:

```text
crates/snolc-abi/       no_std C ABI representation
crates/snolc-sdk/       module I/O wrappers, handles, framing and Pump
crates/snolc/           engine, loader, stack, mux, events and control
crates/snolc-cli/       argument parsing and process behavior
config/templates/       complete main client and server TOML
include/snolc.h         C ABI source of truth
spec/                   contracts and operations
fuzz/                   wire and config fuzz targets
tools/                  release packaging and verification
```

Core must not import an official module crate, snolpkg or snolcNG.

## invariants

Keep these rules in each change:

- Payload follows `Adapter -> smoltcp -> yamux -> Protection -> Carrier`.
- Return traffic uses those layers in reverse order.
- SOCKS5, HTTP CONNECT, direct and TUN traffic enter smoltcp sockets.
- Core has no adapter-to-yamux bypass.
- Policy moves payload between smoltcp and yamux.
- Policy owns users, credentials, quota, rates, rules and account storage.
- A carrier exposes one ordered duplex byte stream.
- Protection wraps carrier `ByteIo` before yamux.
- Native modules run as trusted process code through the C ABI.
- Every queue, frame, buffer, table and archive read has a bound.
- Strict config rejects missing, duplicate and unknown fields.
- Module callbacks run on the engine network thread.
- A flow or session error closes its scope.
- Failure cannot activate direct networking.

## dependency direction

```text
snolc-abi <- snolc-sdk <- native modules
     ^
     +---- snolc engine <- snolc-cli
                        <- snolcNG

snolpkg has no engine dependency.
```

`snolc-sdk` must not depend on core. Modules use ABI values and SDK wrappers.
Core loads class tables without linking module implementations.

## engine lifecycle

The host uses this sequence:

```rust
let validated = Engine::validate(config, modules)?;
let (engine, handle) = Engine::build(validated, host)?;
engine.run()?;
```

`Engine::validate` checks limits, duplicate instances, four required classes,
tunnel references, class compatibility, policy family and derived I/O bounds.
It opens no listener.

`Engine::build` creates bounded command and event queues, logs, snapshots, the
selected control endpoint and `EngineHandle`.

`Engine::run` blocks its calling thread. It owns an
`async_executor::LocalExecutor`. An embedding host gives it a dedicated thread.
The lifecycle values are `Configured`, `Starting`, `Running`, `Stopping`,
`Stopped` and `Failed`.

The CLI owns signals and process exit. The library does not install signal
handlers, replace the host logger or call `exit`.

## thread and ownership rules

The engine thread owns mutable module instances, stack sockets, yamux streams
and flow state. `EngineHandle` sends bounded commands. It does not call modules
from the caller thread.

Foreign workers may retain wake handles. They publish completion and wake the
engine. They must not enter mutable module state.

Official blocking work uses bounded workers:

- core file logging uses one worker per engine;
- policy-local uses one redb worker per instance;
- adapter-direct uses one resolver worker per instance;
- carrier-ssh uses one current-thread Tokio worker per instance.

The engine thread performs no blocking DNS, filesystem access, thread join,
mutex wait or sleep.

Handles combine a slot index with a generation. Reject a stale generation after
slot reuse. A transferred I/O handle belongs to the receiver. A failed transfer
leaves ownership with the sender.

## stack path

`StackBridge` owns smoltcp interfaces, routes, socket sets and packet queues.
Stream adapters create loopback TCP pairs inside smoltcp. Packet adapters inject
and receive IP packets. Policy opens the peer stack socket and transfers bytes
to a yamux stream.

The engine applies `max_ingress_packets_per_tick` before it yields. TCP work
yields at `max_io_chunk`. UDP work preserves one datagram and its tuple. A full
queue returns backpressure or a scoped resource error.

Stopping virtual-device polling must stop stream payload progress. A direct
host-socket bypass violates the architecture.

Read `spec/stack-bridge.md` before you edit routing, packet ownership,
fragmentation, TCP pairs or TUN behavior.

## mux and wire

Core owns yamux sessions and stream dispatch. A stream starts with the bounded
header from `spec/wire.md`. The header selects POLICY, TCP or UDP and carries no
deployment path.

Protection wraps carrier bytes before yamux reads or writes them. Core treats
dummy and Noise through the same class table. Carrier or protection failure
closes the session. Core does not retry through another route.

Parsers must accept split input and joined frames. Reject unknown kinds,
oversized lengths, invalid UTF-8 where required and trailing bytes where the
contract forbids them.

## ABI work

Read `include/snolc.h` and `spec/abi.md` before an ABI edit.

The ABI uses fixed-width C types, explicit lengths, versioned descriptors and
reserved zero fields. Borrowed slices live through the call that receives them.
Owned handles use explicit retain, transfer and release rules.

Check descriptor size and offsets on each target ABI. Reject a short descriptor,
wrong ABI version, wrong wire version, unknown class, nonzero reserved field or
missing function before `create`.

Module calls may return `STATUS_PENDING`. Core polls pending control and
shutdown work on the engine thread until completion or timeout. Catch Rust
unwind at each exported boundary. A native crash can still terminate the
process.

## module classes

Adapters own external protocols and platform entry:

- `adapter-socks5` handles CONNECT and UDP ASSOCIATE;
- `adapter-http-connect` handles HTTP/1.1 CONNECT;
- `adapter-tun` handles Linux TUN and Android file descriptors;
- `adapter-direct` opens remote TCP or UDP and performs bounded DNS.

Protection modules wrap `ByteIo`:

- `protection-dummy` forwards bytes;
- `protection-noise` implements the bounded Noise NK record protocol.

Carriers create ordered byte streams:

- `carrier-tcp` connects or listens with TCP;
- `carrier-ssh` carries bytes through an SSH subsystem.

Policies own admission and payload transfer:

- `policy-dummy` accepts work and uses SDK `Pump`;
- `policy-local` owns users, credentials, quota, rates, rules, redb and control.

Keep module code and module-specific tests in `snolc-modules`.

## policy-local

Policy-local authenticates the protected POLICY stream before user data. It
stores credential digests, never bearer credentials. It precharges quota blocks
with immediate redb durability, accounts bytes from the reserved block and
refunds unused credit through its worker. A crash may overcharge at most the
documented active block. It must not create credit.

Admin requests use `client_id` and `seq`. Store the committed result before you
apply runtime state. Return the stored result for the same sequence and bytes.
Reject changed replay, old sequence and gaps.

Rate scheduling covers upload, download and combined limits. User weights share
available tokens. Rule evaluation covers direction, protocol, IP, domain, SNI,
Host, group and unknown values at the points in `spec/policy-local.md`.

Backup pauses new policy work, closes redb, copies and verifies the file, then
reopens the database. Restore requires a stopped policy.

## configuration

Main config and module config use strict TOML with
`#[serde(deny_unknown_fields)]`. Validation checks arithmetic before allocation.
Relative paths resolve against the file that contains them. Runtime config does
not change the process working directory.

Secret input names one source. Environment input requires a variable name. TOML
input carries the value. Missing input fails startup. Dumps redact credentials,
private keys and bearer URIs.

Core templates live in `config/templates`. Module templates live in
`snolc-modules/config/templates/modules`. Copy the complete tree and required
keys before validation.

## packaging

`snolpkg` reads a signed publication manifest from `snolc-modules/snolpkg`.
`config/sources.toml` supplies the trusted Ed25519 key. A manifest cannot add a
trust key.

Binary mode verifies signature, target, size and SHA-256 before extraction.
Source mode checks out the signed revision and runs locked Cargo with the named
toolchain. Neither mode falls back to the other.

The extractor accepts regular files and directories. It rejects absolute paths,
parent traversal, links, devices, duplicate paths, setuid bits, file-count
overflow and byte-limit overflow.

The immutable store key includes source, package identity, version, target and
content hash. The engine verifies package identity and library hash before load.
It keeps a loaded library until shutdown.

## profiles and clients

snolcNG owns `snolc://profile/` import, subscriptions, provisioning helpers,
desktop UI and Android bootstrap. Profiles contain exact module identities,
endpoint, server pin and bearer credential. Input cannot select local paths,
commands, package roots or trust keys.

Desktop writes private files through a temporary file and rename. Android keeps
credentials under an AndroidKeyStore AES-256-GCM key and passes its TUN file
descriptor to adapter-tun.

Keep profile and Android work in `snolcNG`. The core CLI supports `version`,
`validate`, `run` and `control`.

## failure rules

- Config failure stops startup before listeners open.
- Module config failure names its instance.
- Flow failure closes one flow.
- Session failure closes its yamux and carrier resources.
- Engine invariant failure selects `Failed`.
- Queue exhaustion returns a resource error or increments a bounded loss count.
- Events and snapshots contain no secret or payload.

Never add hidden defaults, unbounded retries or direct fallback.

## test ownership

Run these gates in core:

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --release --locked
cargo deny check
```

Run module build, unit tests, native E2E, policy fuzz and cargo-deny in
`snolc-modules`. Run installer tests and archive fuzz in `snolpkg`. Run desktop
tests, profile fuzz and the two-ABI APK build in `snolcNG`.

Use Podman for an independent Linux run. Record command, duration, commit,
target and host. Mark missing hardware `unverified`; do not convert it to pass.

## documentation index

- `spec/architecture.md`: component and ownership boundaries
- `spec/stack-bridge.md`: smoltcp path and packet ownership
- `spec/wire.md`: wire bytes and parser limits
- `spec/abi.md`: native contract and lifetimes
- `spec/module-authoring.md`: module implementation and publication
- `spec/config.md`: strict TOML and secrets
- `spec/policy-local.md`: users, quota, rates, rules and redb
- `spec/packaging.md`: signatures, archives and immutable stores
- `spec/uri.md`: profiles, subscriptions and client persistence
- `spec/platforms.md`: target tiers and platform limits
- `spec/operations.md`: deployment and maintenance
- `spec/acceptance.md`: required release evidence
- `spec/benchmarks.md`: stress methods and raw result policy
- `spec/xray-and-sing-vs-snolc.md`: matched comparison protocol

## change checklist

1. Name the owning repository and contract.
2. Preserve the packet path and ownership rules.
3. Add bounds before new allocation or queue work.
4. Test malformed input and resource exhaustion.
5. Run the owner repository gates.
6. Run dependent repository gates after a pin change.
7. Update the relevant specification.
8. Record unavailable runtime rows as `unverified`.
