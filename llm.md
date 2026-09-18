# SNOLC repository guide for language models

This file is the entry point for automated code analysis and implementation
work in this repository. It maps the source tree, contracts, ownership rules,
public APIs, runtime data flow, configuration, package format, clients, tests,
and normative documentation for SNOLC 0.0.1.

SNOLC is pronounced `snol`, `/snɔl/`. The release version is `0.0.1`. The only
public compatibility generation is `wire_version = 1`. Project code uses the
Unlicense. Rust code uses edition 2024 and the toolchain pinned in
`rust-toolchain.toml`.

## 1. Source-of-truth order

Use sources in this order when they differ:

1. `include/snolc.h` defines the native C ABI layout.
2. `spec/wire.md` defines the network wire format.
3. Strict checked-in TOML templates define complete supported configurations.
4. The implementation and tests define executable behavior.
5. Files under `spec/` define architecture, limits, operations, and acceptance.
6. This file indexes and explains those sources. It does not replace them.
7. `readme.md` is the short user-facing introduction.

Do not infer a second compatibility number from the Cargo package version.
Do not infer support from a type name, manifest entry, or build result when
`spec/acceptance.md` records a runtime gate as unverified.

## 2. Non-negotiable invariants

Keep these rules intact in every code change:

- User payload follows `Adapter -> smoltcp -> yamux -> Protection -> Carrier`.
- The reverse path uses the same layers in reverse order.
- SOCKS5, HTTP CONNECT, direct, and TUN traffic all enter real smoltcp sockets.
- Core has no adapter-to-yamux bypass and no second payload copy loop.
- Policy alone moves payload between a stack socket and a yamux stream.
- Core does not own users, credentials, quota, rates, destination rules, or an
  account database. `modules/policy-local` owns those features.
- A carrier exposes an ordered bidirectional byte stream. It does not provide
  a direct fallback.
- Protection wraps carrier `ByteIo` before yamux. Core does not special-case
  dummy or Noise by package name.
- Native modules are trusted in-process code loaded through a stable C ABI.
  They are not sandboxed.
- All queues, frames, buffers, tables, pending operations, and archive reads
  have explicit bounds.
- Runtime rejects unknown or missing TOML fields. It does not apply hidden
  defaults or mode fallback.
- Module callbacks run on the engine network thread. Foreign threads may retain
  and call a wake handle, but they may not enter a mutable module instance.
- A flow or session failure closes its scope. It does not terminate the engine
  unless the engine itself cannot continue.
- No failure activates direct networking.

## 3. Repository map

```text
Cargo.toml                         workspace and exact dependency policy
Cargo.lock                        pinned dependency graph
rust-toolchain.toml               Rust 1.98.1
include/snolc.h                   normative C ABI
crates/snolc-abi/                 no_std Rust representation of the C ABI
crates/snolc-sdk/                 safe module I/O, handles, Pump, FFI helpers
crates/snolc/                     library engine and network core
crates/snolc-cli/                 thin CLI over the library
crates/snolpkg/                   signed module installer
modules/adapter-socks5/           SOCKS5 CONNECT and UDP ASSOCIATE
modules/adapter-http-connect/     HTTP/1.1 CONNECT
modules/adapter-direct/           remote TCP/UDP connect and DNS
modules/adapter-tun/              Linux TUN and Android fd adapter
modules/protection-dummy/         transparent ByteIo wrapper
modules/protection-noise/         Noise NK record protocol
modules/carrier-tcp/              TCP connect/listen carrier
modules/carrier-ssh/              SSH subsystem carrier
modules/policy-dummy/             unrestricted shared-Pump policy
modules/policy-local/             users, quota, rates, rules, redb, control
clients/snolcNG/                  profile library, desktop UI, Android bridge
config/templates/                 validated main and module TOML templates
config/packages/                  snolpkg source and limit configuration
snolpkg/                          signed publication manifests
spec/                             normative design and operations documents
fuzz/                             five boundary fuzz targets
tools/                            release packaging and verification scripts
.github/workflows/                CI, release target, BSD, and Android jobs
```

The dependency direction is acyclic:

```text
snolc-abi <- snolc-sdk <- native modules
     ^
     +---- snolc core <- snolc-cli
                      <- snolcNG runtime

snolpkg is independent of the engine.
```

`snolc-sdk` does not depend on core. Modules do not link to private core types.
Core loads class tables without importing concrete official module crates.

## 4. Documentation index

### Architecture and network path

- [`spec/architecture.md`](spec/architecture.md): components, dependency graph,
  thread model, ownership, lifecycle, error scopes, and resource budgets.
- [`spec/stack-bridge.md`](spec/stack-bridge.md): StreamPort and PacketPort,
  smoltcp loopback pairs, AnyIP TUN handling, tuple ownership, fragmentation,
  polling bounds, and proof that stopping the virtual device stops traffic.
- [`spec/wire.md`](spec/wire.md): common yamux stream headers, POLICY handshake,
  TCP/UDP OPEN, OPEN response, UDP framing, limits, and parser rules.

### Extension contracts

- [`spec/abi.md`](spec/abi.md): descriptor layout, status and I/O semantics,
  borrowed memory, handles, wake ownership, thread rules, and unload lifetime.
- [`spec/module-authoring.md`](spec/module-authoring.md): module skeletons,
  strict config, async work, class responsibilities, errors, testing, and
  publication steps.
- [`include/snolc.h`](include/snolc.h): exact C declarations. Consult this file
  before changing any ABI structure or function table.

### Configuration and policy

- [`spec/config.md`](spec/config.md): strict main/module TOML, path resolution,
  secret sources, complete branches, templates, and logging contract.
- [`spec/policy-local.md`](spec/policy-local.md): identity, redb layout,
  idempotent administration, quota precharge, rate scheduling, filtering,
  POLICY channel, backup, and crash behavior.
- [`config/templates/`](config/templates/): inputs exercised by the runtime
  parser and module validators. These are executable documentation.

### Distribution and applications

- [`spec/packaging.md`](spec/packaging.md): signed manifests, immutable store,
  binary/source installs, archive safety, proxies, offline mode, templates,
  dependency locks, and release artifacts.
- [`spec/uri.md`](spec/uri.md): `snolc://` profiles, subscriptions, trust,
  generated client deployments, snolcNG state, desktop, and Android behavior.
- [`spec/platforms.md`](spec/platforms.md): support tiers, target triples,
  minimum systems, memory/disk budgets, and performance measurement rules.

### Operation and evidence

- [`spec/operations.md`](spec/operations.md): build, install, server/client
  setup, access issue, control requests, backup/restore, diagnostics, updates,
  and Android release use.
- [`spec/acceptance.md`](spec/acceptance.md): release gates and recorded 0.0.1
  evidence. Treat `unverified` as unverified, never as pass.
- [`readme.md`](readme.md): installation and basic commands.

## 5. Runtime architecture

### 5.1 Library lifecycle

The public engine sequence is:

```rust
let validated = Engine::validate(config, modules)?;
let (engine, handle) = Engine::build(validated, host)?;
engine.run()?;
```

`Engine::validate` checks main limits, duplicate instances, all four required
module classes, tunnel references, class compatibility, policy family, channel
security context, and derived I/O limits. It does not start listeners.

`Engine::build` creates bounded command/event channels, logging, the local Unix
control endpoint when selected, snapshots, host state, and an `EngineHandle`.

`Engine::run` blocks the calling thread. It owns one
`async_executor::LocalExecutor` and drives it through `async_io::block_on`.
Embedding programs must give `run` a dedicated thread. `async-io` may own its
reactor thread; SNOLC does not promise one OS thread for the process.

Lifecycle values are `Configured`, `Starting`, `Running`, `Stopping`,
`Stopped`, and `Failed`. Module instances are created on the engine thread.
Shutdown polls modules until completion or the configured timeout, destroys
instances, releases I/O owners, stops workers, and removes the control socket.

### 5.2 Session construction

For a client tunnel, core performs this chain:

1. The carrier module connects and returns `ByteIo`.
2. The protection module wraps that I/O and completes its handshake.
3. Core creates a yamux client session over the protected I/O.
4. The initiator opens one POLICY stream.
5. Both sides exchange the common POLICY header and policy family.
6. Core transfers the stream to the policy module.
7. Policy authenticates and admits the session.
8. Client adapters may then create user flows.

For a server tunnel, carrier accept replaces connect. All later layers and the
POLICY-first rule remain the same.

One carrier session contains one protection session and one yamux session.
Carrier loss closes associated user flows. Version 1 does not migrate live TCP
state to another session.

### 5.3 Flow construction

For a stream adapter such as SOCKS5 or HTTP CONNECT:

1. Adapter accepts and parses a bounded external request.
2. Core creates a smoltcp flow with real destination in `FlowMetadata`.
3. A loopback device joins adapter-side and policy-side smoltcp sockets.
4. Policy evaluates the OPEN request before remote connect.
5. Client core opens a yamux TCP or UDP stream and writes its OPEN frame.
6. Server policy admits the request.
7. `adapter-direct` resolves domains when selected, returns resolved addresses
   to policy for another check, then connects.
8. Server returns an OPEN response only after endpoint success or failure.
9. Policy owns both directions between `StackSocket` and `MuxStream`.

HTTP and SOCKS success responses wait for remote endpoint success. Domain names
cross the tunnel without local resolution. DNS performed by `adapter-direct`
uses its bounded worker, generation checks, timeout, and post-resolution policy
admission.

### 5.4 StackBridge

`crates/snolc/src/stack.rs` owns every smoltcp interface, `SocketSet`, socket,
virtual tuple, packet queue, and reassembly slot.

`SharedStackBridge` is the engine-facing owner. Its principal API is:

```rust
SharedStackBridge::new(config, max_flows, max_managed_bytes, ingress_limit)
open_tcp(metadata) -> (adapter_port, policy_port)
open_udp(metadata) -> (adapter_port, policy_port)
packet_port() -> PacketPort
accept_packet_tcp() -> Option<(FlowMetadata, PacketTcpPort)>
accept_packet_udp() -> Option<(FlowMetadata, PacketUdpPort)>
poll()
managed_bytes()
```

Stream TCP creates two smoltcp sockets and uses virtual `127.0.0.1` or `::1`
endpoints with ports from 1024 through 65535. The virtual tuple never replaces
the actual destination in metadata. smoltcp owns SYN, ACK, sequence numbers,
windows, retransmission, FIN, and reset.

Stream UDP creates paired smoltcp UDP sockets for one normalized destination.
Datagram boundaries and a zero-byte payload survive the path.

`PacketPort` receives actual IPv4/IPv6 packets from TUN. The bridge uses AnyIP,
internal routes, full TCP/UDP tuples, bounded SYN-created sockets, IPv4/IPv6
fragment handling, and fixed reassembly slots. It proxies TCP and UDP. Version
1 does not promise arbitrary GRE, ESP, or raw-IP forwarding.

The scheduler calls bounded ingress and egress work, then yields. TCP work uses
`max_io_chunk`; one UDP quantum is one whole datagram. A stopped policy may
stop payload while smoltcp still emits ACKs and handles timers.

### 5.5 Yamux and common wire

`crates/snolc/src/mux.rs` wraps `yamux 0.14.0` over futures I/O. A
`MuxSession<T>` owns the connection, enforces stream count, tracks one POLICY
stream, opens/accepts user streams, and releases flow capacity. The configured
`max_streams_per_session` includes POLICY. The low-memory value 17 means one
POLICY stream plus 16 user streams.

Every yamux stream starts with 12 protected bytes:

```text
offset  bytes  meaning
0       4      ASCII SNOL, 53 4e 4f 4c
4       4      u32_be wire_version, value 1
8       1      kind: 1 POLICY, 2 TCP, 3 UDP
9       3      zero reserved bytes
```

POLICY adds `u16_be family_length` and 1..64 ASCII family bytes. The responder
echoes the POLICY header and family. A second POLICY stream, family mismatch,
or user stream before admission is a protocol error.

TCP/UDP OPEN adds `u16_be body_length`, at most 4096 bytes. Its body is:

```text
u8 address_type
address: 4-byte IPv4, 16-byte IPv6, or u16 length + 1..253 ASCII domain
u16_be port
u16_be metadata_length
0..1024 opaque metadata bytes
```

Port zero, trailing bytes, uppercase/non-ASCII domain forms, unknown tags, and
oversized fields fail. OPEN response contains `status:u8`,
`reason_length:u16_be`, and at most 256 UTF-8 bytes. Status values are OK,
denied, connect_failed, unsupported, resource_limit, protocol_error, and
internal_error.

TCP carries raw bytes after OK and uses stream half-close/reset. UDP carries
`u16_be payload_length + payload`; payload length is 0..65507 and the OPEN
destination remains fixed.

## 6. Public Rust APIs

### 6.1 `snolc` engine API

The root crate re-exports `Engine`, `EngineHandle`, `Host`, `ResponseFuture`,
`ValidatedConfig`, engine errors, deployment types, events, snapshots, and ABI
class/version constants.

```rust
pub trait Host: Send + Sync + 'static {
    fn engine_event(&self, event: &Event);
    fn protect_socket(&self, socket: i64) -> bool;
}

Engine::validate(Config, Vec<LoadedModule>) -> Result<ValidatedConfig, EngineError>
Engine::build(validated, host) -> Result<(Engine, EngineHandle), EngineError>
Engine::run(self) -> Result<(), EngineError>

EngineHandle::control(instance, request) -> ResponseFuture
EngineHandle::snapshot() -> Snapshot
EngineHandle::subscribe() -> Result<EventReceiver, EngineError>
EngineHandle::shutdown() -> Result<(), EngineError>
EngineHandle::platform_event(event) -> Result<(), EngineError>
```

`control` and `shutdown` enqueue commands; they do not call modules from the
caller thread. The command queue is bounded. A module may return Pending from
control or shutdown; core polls it on the network thread until completion or
timeout. `subscribe` transfers the single event receiver once. `snapshot` uses
atomics and returns lifecycle, session count, flow count, and lost event count.

Events are:

```text
Lifecycle(state)
Module { instance, payload }
ModuleError { instance, message }
Tunnel { name, state }
ResourceExhausted { resource }
Platform(NetworkChanged | VpnPermissionRevoked)
```

`Deployment::load(path)` parses the main file, follows referenced module files,
resolves immutable package locks, verifies content hash and source identity,
loads each library, validates its descriptor/options, and produces the Config
plus `LoadedModule` values consumed by `Engine::validate`.

### 6.2 SDK I/O API

`snolc-sdk` exposes Rust interfaces over ABI-owned objects:

```rust
pub trait ByteIo {
    poll_read(context, output) -> Poll<io::Result<usize>>;
    poll_write(context, input) -> Poll<io::Result<usize>>;
    poll_flush(context) -> Poll<io::Result<()>>;
    poll_shutdown_write(context) -> Poll<io::Result<()>>;
    close() -> io::Result<()>;
}

pub trait DatagramIo {
    poll_recv_datagram(context, output)
        -> Poll<io::Result<DatagramRecv>>;
    poll_send_datagram(context, datagram) -> Poll<io::Result<()>>;
    close() -> io::Result<()>;
}
```

`DatagramRecv` is `Datagram(length)`, `BufferTooSmall(required)`, or `Closed`.
A too-small receive buffer reports the required size without consuming the
datagram. Zero-byte datagrams are data, not EOF.

`Pump` handles one byte direction with a bounded pending buffer, partial
writes, flush, source EOF, and destination half-close. `DatagramPump` stores at
most one pending full datagram and preserves atomic sends. Pump reports contain
actual read/written or received/sent counts. Policies use those counts for
accounting; Pump contains no quota or rate algorithm.

`HandleTable<T>` and `TypedHandle` encode slot index and generation. Removing a
slot invalidates stale handles. `ForeignByteIo` and `ForeignDatagramIo` validate
ABI tables and translate tagged results into Rust polling behavior.

`HostApi` exposes socket protection to modules. On Android every official
external transport socket must pass `protect_socket` before connect.

Runnable module examples live under `crates/snolc-sdk/examples/` for adapter,
protection, carrier, and policy classes.

### 6.3 `snolpkg` library API

The installer crate exposes strict publication/config structures and these
principal operations:

```text
Sources::parse / Sources::find
PublicationManifest::parse / validate
verify_manifest
validate_relative_path
extract_tar_gz
load_publication
checkout_revision
install_binary
install_source
delete_package
write_template
```

`InstallOptions` selects absolute root, exact target, extraction limits, and
offline state. `InstallResult` returns package identity, immutable store path,
and lock path. `ExtractLimits` bounds file count, total bytes, and per-file
bytes.

### 6.4 `snolcNG` library API

`clients/snolcNG` exports profile and UI state types:

- `Profile`, `ProfileModule`, `ModuleClass`, and redacted `Secret`;
- `AccessProvisioning`, `ProvisionProfile`, and `ProvisionedAccess`;
- `AppState`, `Screen`, `ConnectionState`, and `ServerStatus`;
- `EngineRuntime` in `runtime.rs`;
- profile parse/validation and URI encode/decode;
- subscription fetch/parse;
- client config generation and persistence;
- bundled module installation.

`EngineRuntime` starts the same library `Engine` on a worker thread, delivers
engine events to the UI, supports Android socket protection, sends platform
events, and requests shutdown. The GUI thread does not block on module control.

## 7. Native module ABI

### 7.1 Entry point and descriptor

Each platform-specific `cdylib` exports:

```c
const SnolModuleDescriptor *snolc_module_entry(void);
```

The immutable descriptor prefix is `struct_size`, `wire_version`, `class_mask`,
and zero `reserved`. Core checks the prefix before create. The descriptor then
contains module name, common lifecycle functions, generic byte/datagram I/O
tables, and optional adapter/protection/carrier/policy class tables.

Common lifecycle functions are:

```text
describe(output, written)
validate_config(config_toml, absolute_base_directory, error, written)
create(config_toml, absolute_base_directory, host_api, instance_out)
poll(instance, wake)
control(instance, request, response, written)
shutdown(instance)
destroy(instance)
```

Unsupported control returns `STATUS_UNSUPPORTED`. `STATUS_PENDING` means the
module retained a wake and core must poll later. Exported Rust functions catch
unwind and convert it to a status; segfault, abort, allocator corruption, and
OOM remain process failures.

### 7.2 Status, I/O, and memory rules

Status tags are `OK`, `UNSUPPORTED`, `INVALID`, `RESOURCE`, `IO`, `INTERNAL`,
`PENDING`, and `DENIED`.

I/O tags are `PROGRESS`, `PENDING`, `EOF`, `ERROR`, and
`BUFFER_TOO_SMALL`. A nonempty write may not return `PROGRESS(0)`. Pending must
register a wake instead of relying on spin polling. Byte EOF affects one
direction; it does not imply immediate destruction of the opposite direction.

ABI bytes are borrowed pointer-length pairs valid only during a call. A module
copies retained data into its own bounded storage. The allocator that creates
memory frees it. No Rust `Vec`, `String`, reference, future, trait object, or
`SocketSet` crosses the boundary.

`SnolHandle` is a `u64` generation handle. Every operation validates owner,
type, generation, and lifetime. Libraries stay loaded until engine shutdown and
all module-owned handles/callbacks are gone.

`SnolWakeHandle` contains context, wake, retain, and release callbacks. A worker
may call wake. Other host or module callbacks stay on the engine thread.

### 7.3 Host API

`SnolHostApiV1` provides:

```text
now_monotonic_nanos
set_timer(handle, deadline_nanos)
emit_event(bytes)
context_get(session, namespace)
context_set(session, namespace, value)
protect_socket(native_socket)
```

Session context uses module-owned names and opaque bytes. Official channel
security claims use `snolc.channel.security`, but core does not interpret that
namespace as a universal authentication model.

### 7.4 Class APIs

Adapter table:

```text
open / accept
attach byte flow
attach datagram flow
attach packet port
complete external request
close_flow
resolve
```

Protection table:

```text
wrap(lower ByteIo, local context) -> wrapped ByteIo
```

Carrier table:

```text
connect(endpoint) -> ByteIo
accept() -> ByteIo
```

Policy table:

```text
attach_session(policy stream, local context) -> policy session
admit_flow(session, metadata)
admit_resolved(session, resolved metadata)
attach_flow(session, StackSocket ByteIo, MuxStream ByteIo)
attach_datagram_flow(session, StackSocket DatagramIo, MuxStream DatagramIo)
```

`admit_flow` and `admit_resolved` may return Pending. Endpoint connect cannot
precede successful admission. Resolved addresses return to policy so a domain
cannot bypass IP rules.

## 8. Official modules

| package | class | roles | responsibility |
| --- | --- | --- | --- |
| `adapter-socks5` | adapter | client | CONNECT, UDP ASSOCIATE, IPv4/IPv6/domain; rejects BIND and fragmented SOCKS UDP |
| `adapter-http-connect` | adapter | client | bounded HTTP/1.1 CONNECT, IPv6 authority, preserves bytes after headers |
| `adapter-direct` | adapter | server | TCP/UDP endpoint connect, system DNS or domain rejection, resolved-IP readmission |
| `adapter-tun` | adapter | client | Linux TUN or Android-owned fd, bounded packet queues |
| `protection-dummy` | protection | client/server | transparent delegated ByteIo with no core exception |
| `protection-noise` | protection | client/server | `Noise_NK_25519_ChaChaPoly_BLAKE2s` and pinned server X25519 identity |
| `carrier-tcp` | carrier | client/server | bounded TCP connect/listen with explicit IP endpoint |
| `carrier-ssh` | carrier | client/server | `snolc` SSH subsystem, password/Ed25519 auth, pinned host key |
| `policy-dummy` | policy | client/server | admits flows and drives shared Pump without users or accounting |
| `policy-local` | policy | client/server | credentials, users, quota, rates, scheduling, rules, redb, POLICY status, admin control |

Module option schemas are strict. Canonical values and every selected field are
in `config/templates/modules/*.toml`.

### 8.1 Adapter options

- SOCKS5: `listen`, `max_connections`, `max_udp_associations`,
  `max_request_bytes`, `reject_fragments`.
- HTTP CONNECT: `listen`, `max_connections`, `max_header_bytes`.
- Direct: `dns_mode`, `max_pending_opens`, `max_resolved_addresses`,
  `resolve_timeout_ms`, `connect_timeout_ms`.
- TUN Linux: `mode = "linux"`, `interface`, `mtu`, `packet_queue_bytes`.
- TUN Android: `mode = "android-fd"`, `fd`, `mtu`, `packet_queue_bytes`.

### 8.2 Protection options

- Dummy has an explicit empty `[options]` table.
- Noise client selects `mode = "client"` and `server_public_key_file`.
- Noise server selects `mode = "server"` and `private_key_file`.

Noise uses prologue `snolc/protection-noise/1`. Each message has a u16 big-endian
length. Handshake records are at most 4096 bytes. Transport plaintext is at most
16384 bytes and ciphertext at most 16400 bytes. A direction closes before
`2^32` transport records. Invalid records close the session.

### 8.3 Carrier options

- TCP: `mode = connect|listen`, `endpoint_ip`, `max_connections`, `nodelay`.
- SSH common: mode, explicit IP endpoint, username, connection and queue
  limits, chunk size, and inactivity timeout.
- SSH client: pinned `server_host_key` plus password or Ed25519 private-key
  auth.
- SSH server: explicit `host_key` plus password or Ed25519 public-key auth.

The SSH server accepts one subsystem named `snolc`. It rejects shell, exec,
PTY, and agent forwarding. One instance owns one Tokio current-thread worker for
all its SSH sessions, not one runtime per connection.

### 8.4 Policy options

- Dummy: `pump_buffer_bytes`.
- Local common: server ID, protected credential transport, cache/admin/control
  bounds, status and grace intervals, sniff bounds, unknown action, checkpoint
  interval, storage, global rate, and rules.
- Local client adds an explicit TOML or environment credential source.

## 9. Policy-local internals and APIs

### 9.1 Identity and session binding

A user ID is 16 random bytes rendered as 32 lowercase hex characters. A bearer
credential is 32 random bytes rendered as 64 lowercase hex characters. The
server stores SHA-256 credential digest and user reference, never the bearer.
One authenticated yamux session binds to one policy-local user.

Credential mode `protected` requires confidentiality on both sides and
authenticated server identity on the client. Policy reads local claims from
`snolc.channel.security`. Dummy protection is not rejected by core; a policy
that requires security makes that decision.

### 9.2 Persistent storage

One `StorageWorker` owns one redb 4.3.0 database. The low-memory server template
uses `state/policy.redb`, 4 MiB cache, 128 MiB database limit, queue capacity 64,
and 1 MiB accounting blocks.

One redb table uses key prefixes:

```text
meta/         policy metadata
user/         postcard UserRecord
credential/   digest to user records
client/       last administrative receipt per client_id
```

Administrative changes and quota debit/refund commits use
`Durability::Immediate`. `LockedFileBackend` owns one exclusive file lock,
positional I/O, sync, length checks, and growth rejection. State directory mode
is 0700 and database mode is 0600.

Active records live in a bounded RAM cache. Payload forwarding does not query
redb per packet. Backup pauses policy operations, closes the database, copies
the stable file, verifies the copy, and reopens. Restore requires stopped
policy.

### 9.3 Administrative control

Requests and responses are strict UTF-8 TOML bytes passed through the generic
module `control` API. Methods are:

```text
user.create
user.update
user.disable
user.delete
credential.add
credential.revoke
quota.add
quota.new_period
usage.get
sessions.list
sessions.disconnect
rules.replace
maintenance.backup
```

Mutating methods contain `client_id` and monotonically increasing `seq`.
`user.update`, disable, and delete also carry expected revision. The worker
commits mutation and receipt atomically before returning success.

For each `client_id`, `seq = last + 1` executes. Repeating `last` with the same
SHA-256 request hash returns the stored response. A changed repeat, old value,
or gap fails. Responses stored in receipts contain no bearer secret.

`UserSpec` requires explicit status, expiration, quota, upload/download/
combined rates, burst, session and flow limits, weekly UTC access, weight,
group, and rule profile. Unlimited branches remain explicit. Burst must hold a
maximum UDP payload.

### 9.4 Quota accounting

The server charges user payload accepted by the next stage between StackSocket
and MuxStream. TCP charges actual successful write count. UDP charges a whole
accepted datagram. Wire, policy, Noise, SSH, and carrier retry overhead do not
consume user quota.

When a user has no in-memory credit, policy pauses that user and asks the
storage worker to increase durable charged bytes by at most one configured
accounting block. Policy releases bytes only after the Immediate commit. One
user may own one unfinished block and one in-flight debit.

Normal checkpoint or shutdown pauses the user and refunds unused credit with
an Immediate commit. A crash may count the unused part of the last committed
block as used; the overcount is bounded by one block per active user. An
ambiguous storage result stops issuance and reloads confirmed state instead of
blindly retrying.

### 9.5 Rates and rules

Policy-local uses integer token buckets with monotonic nanoseconds for upload,
download, and optional combined rate. Weighted deficit round robin schedules
active users; round robin schedules flows within one user. Opening more flows
does not increase a user's weight. A timer wakes the nearest eligible flow; the
policy does not spin.

Ordered first-match rules can test direction, observed protocol, CIDR, port,
exact/suffix domain, TLS SNI, HTTP Host, and user group. Protocol classes are
TLS, HTTP, SSH, QUIC, unknown, and any. Each observation-dependent rule states
an action when the value is unavailable. A terminal action is mandatory.

Sniffing uses at most configured bytes, 16384 in the template, and a timeout of
2000 ms. Policy does not decrypt HTTPS. QUIC and ECH do not promise a visible
domain. Rule replacement chooses `apply = new` or `active`; revocation always
affects active user flows.

### 9.6 Private POLICY protocol

Policy-local frames private messages as `u32_be length + UTF-8 TOML`, with a
configured maximum of 16384 bytes. It handles split and coalesced reads.

Client methods are `auth`, `status`, `subscribe`, and `disconnect_self`.
Administrative method names on this stream are rejected. Status contains
`used_bytes`, `limit_bytes`, upload/download rates, expiration, revision, and
reason. Snapshot delivery has capacity one and replaces stale snapshots;
responses and errors use a separate bounded path.

## 10. Configuration model

### 10.1 Main config

`Config` contains seven required parts:

```text
wire_version
paths { packages, state }
engine { session, flow, memory, queue, I/O, timeout limits }
stack { families, MTU, TCP/UDP buffers, packet/reassembly limits }
yamux { streams, receive window, split size, read-after-close }
logging { off or complete file branch }
control { off or complete Unix branch }
tunnels[] { name, role, adapters[], protection, carrier, policy }
```

Paths resolve against the containing file. Validation rejects duplicate tunnel
or instance names, cycles, missing classes, invalid references, incompatible
window/buffer limits, resource overflow, and unsupported mode/platform before
opening a listener.

The low-memory templates set 2 sessions, 32 total flows, 32 MiB core-managed
bytes, 16 KiB TCP RX/TX buffers, 128 KiB UDP RX/TX buffers, 8 UDP metadata
slots, MTU 1280, four reassembly slots, and 17 yamux streams per session.

### 10.2 Module config

Every module file has:

```toml
wire_version = 1
instance = "unique-id"
package = "owner/name@exact-version"
role = "client-or-server"

[options]
# module-owned strict schema
```

Core parses common fields and passes serialized options plus an absolute base
directory to `validate_config`. Core does not parse SSH, Noise, DNS, policy, or
adapter-specific values. Modules resolve relative paths against that base, not
the process working directory or home directory.

An inactive feature uses an explicit `mode = "off"` branch where supported.
Selected modes require all fields. Secrets come from an explicit TOML or env
source. Config dumps redact secret values.

### 10.3 Logging and local control

File logging uses one bounded worker and appends to an existing file. At limit,
it streams the newest complete tail to a temporary file in the same directory,
adds the new record, and atomically replaces the target. It does not read the
whole file into memory. Queue overflow drops oldest pending records and
increments `lost_log_records` without blocking traffic.

Decimal sizes support `b`, `kb`, `mb`, `gb`; binary sizes support `kib`, `mib`,
`gib`. Fractional input uses checked integer arithmetic and rounds down.

Unix control uses a 0600 socket under a 0700 directory, checks peer credentials
on supported POSIX systems, and enforces request/connection bounds. Its frame
contains instance length, request length, instance bytes, and request bytes;
the response contains status and response length before response bytes. It
dispatches through the same bounded engine command path as `EngineHandle`.

## 11. CLI surfaces

`snolc` is a thin caller of library APIs:

```text
snolc version
snolc validate <snolc.toml>
snolc run <snolc.toml>
snolc control <unix-socket> <instance> <request.toml>
snolc provision <unix-socket> <instance> <profile.toml> <user-id> <client-id> <seq>
```

The CLI owns process exit codes and SIGINT/SIGTERM. The library does not call
`exit`, install signal handlers, or replace the host's global logger.

`snolpkg` exposes:

```text
snolpkg add -b <git-url> <module-name>
snolpkg add -s <git-url> <module-name>
snolpkg del <installed-package>
snolpkg template <installed-package> --role <role> --output <path>
```

Binary and source modes never fall back to each other. Source mode executes
Cargo at the signed pinned commit with the pinned toolchain and `--locked`.

## 12. Packaging and trust

`snolpkg` reads `snolpkg/<module>.toml` and detached `.toml.sig` bytes from one
pinned HTTPS or local Git revision through gix object access. It verifies
Ed25519 against a key selected by local `sources.toml`; a package cannot trust
its own key.

The signed manifest binds package/version/wire/classes/family/roles,
capabilities, exact dependencies and hashes, source revision, toolchain, build
package, templates, target triples, minimum runtime/ISA, artifact URL, size,
and SHA-256.

Install order is load, verify signature, download or build, verify size/hash,
extract to staging, validate structure, move to content-addressed immutable
store, then atomically update lock. Failure leaves the old lock usable.

Archive extraction permits regular files and directories. It rejects absolute
paths, `..`, duplicate paths, symlinks, hardlinks, devices, setuid bits, staging
escape, excess files, and size-limit violations.

Proxy variables are handled consistently for Git, artifact HTTP, and source
builds. An explicit proxy failure does not trigger a direct connection. Offline
mode issues no network request and requires all signed metadata and content in
the bundle.

## 13. Profiles and snolcNG

A profile URI is:

```text
snolc://profile/<base64url-no-padding UTF-8 TOML>
```

Decoded data is at most 65536 bytes. The profile contains wire version,
server ID, endpoint, exact client module identities/options, server pin, and
credential. It cannot choose administrative sockets, arbitrary filesystem
paths, log destinations outside client data, storage, scripts, or commands.

Import validates a client-only schema, shows untrusted package sources, asks
for approval, and generates a complete local deployment. A subscription is a
bounded HTTPS document with at most 64 profiles. Every server keeps an
independent policy-local balance; the UI does not sum them into a global quota.

The desktop client uses egui, winit, egui-winit, and egui_glow. Profiles,
Connection, and Advanced share one `AppState`. The app requests repaint after
state changes instead of continuously redrawing an idle window.

Android uses the same Rust engine and UI. A small JNI/VpnService bridge owns
permission, lifecycle, foreground service, keystore encryption, TUN descriptor
duplication, and socket protection. Carrier failure keeps TUN held; SNOLC does
not let applications fall through to direct traffic.

## 14. Resource and thread model

Network work stays on the engine thread. The defined blocking owners are:

- one file worker per engine when file logging is enabled;
- one redb worker per policy-local instance;
- one bounded system resolver worker per adapter-direct instance;
- one Tokio current-thread SSH worker per carrier-ssh instance.

The network thread performs no synchronous DNS, regular file I/O, database
transaction, mutex wait, thread join, sleep, or blocking subprocess wait.

The normative low-memory environment is 256 MiB system RAM and one roughly
600 MHz core. Baseline gates are idle RSS at most 32 MiB, steady RSS at most
64 MiB for two sessions and 16 flows, and transient peak at most 96 MiB. See
`spec/platforms.md` and `spec/acceptance.md` for measured 0.0.1 evidence and
remaining hardware gates.

`max_managed_bytes` covers core-owned buffers. A third-party native module can
allocate outside that counter; official combinations must still pass process
RSS gates.

## 15. Test and verification map

Use the pinned toolchain and lockfile:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --release --locked
cargo deny check
```

Important test locations:

- unit tests beside core, SDK, installer, client, and module code;
- `crates/snolc/tests/native_session.rs` for native module sessions, real
  sockets, full stack path, Noise/SSH, policy, stalled-device, and resource
  profiles;
- `crates/snolc-abi/tests/header_layout.rs` for C/Rust ABI agreement;
- fuzz targets for wire, strict config, policy framing, profile URI, and archive
  paths;
- Python release tools for glibc limits, deterministic package creation,
  inventory, checksums, signatures, and archive verification;
- workflow files for Linux target matrix, native BSD VMs, Android APK, macOS,
  and Windows builds.

Build the workspace before native-session tests after changing an ABI or module
because the tests load dynamic libraries from the target directory. Use an
isolated `CARGO_TARGET_DIR` for old-glibc container validation so host artifacts
cannot contaminate the result.

Acceptance covers split/partial I/O, TCP half-close/reset/retransmit, UDP sizes
0/1/65507, fragments, stale handles, wrong wire, strict config, policy stalls,
quota crash points, administrative replay, storage failures, logging rollover,
package attacks, proxy/offline behavior, Android TUN/protect lifecycle, RSS,
and UI behavior. Read `spec/acceptance.md` before claiming a release gate.

## 16. Change guide for automated agents

### Change the wire

Update the parser/encoder in `crates/snolc/src/wire.rs`, normative
`spec/wire.md`, split and malformed-input tests, and `fuzz/fuzz_targets/wire.rs`.
An incompatible common wire change requires a new `wire_version` and matching
ABI/config publication review.

### Change the ABI

Edit `include/snolc.h` first, mirror it with `repr(C)` in `snolc-abi`, update
loader and SDK wrappers, module descriptors, C/Rust layout tests, stale-handle
tests, and authoring documentation. Never expose Rust-native layout.

### Change the stack path

Work in `crates/snolc/src/stack.rs` and engine ownership code. Preserve smoltcp
for stream and packet paths. Run stalled-device tests; payload progress while
the virtual device is stopped proves a bypass.

### Change a module schema

Keep `serde(deny_unknown_fields)`, update its validator, all role/platform
templates, signed publication template declarations, malformed config tests,
`spec/config.md` or the owning module spec, and package verification. Do not add
a core parser for module-private options.

### Change policy-local

Keep user concepts under `modules/policy-local`. Check serialization
compatibility, redb transaction boundaries, administrative receipt atomicity,
quota credit ownership, active-session application, Pump accounting, status
frames, storage failures, and crash tests.

### Add or change an official module

Implement a native class table through `snolc-sdk`, validate roles and platform
capabilities, add complete templates, native integration tests, publication
manifest/signature, exact artifact entries, dependency notices, package install
tests, and RSS accounting. Core must remain independent of package identity.

### Change snolpkg

Preserve fail-closed signature/hash/size checks, immutable store semantics,
atomic lock update, extraction limits, exact dependencies, proxy consistency,
offline isolation, and distinct binary/source modes. Fuzz path handling.

### Change snolcNG or Android

Keep one library engine, one `AppState`, redacted secrets, explicit package
approval, pinned server identity, event-driven repaint, UI-thread nonblocking
control, TUN ownership, and pre-connect socket protection.

## 17. Common wrong assumptions

- `policy-dummy` and `protection-dummy` are normal modules, not core modes.
- `adapter-direct` is the server endpoint adapter, not a direct fallback.
- Stream adapters still pass through smoltcp.
- yamux sits inside protection, so common stream magic is not a clear carrier
  prefix.
- Package version `0.0.1` does not replace `wire_version = 1`.
- A successful cross-build is not a runtime pass for that platform.
- A module signature proves selected origin and bytes, not code safety.
- The native ABI does not isolate crashes or malicious code.
- `max_managed_bytes` does not constrain arbitrary third-party allocations.
- Quota reports durable accounted payload, including at most one unspent
  precharged block after a crash, not exact application consumption.
- A domain admission decision does not replace checks on resolved IP addresses.
- TLS SNI, HTTP Host, QUIC, and ECH observations may be unavailable; rules must
  define that case.
- User POLICY streams cannot perform administrative methods.
- GUI and CLI call the library engine; they do not implement another engine.

## 18. Minimal reading plans

For a core networking change, read architecture, stack bridge, wire,
`engine.rs`, `stack.rs`, `mux.rs`, and `native_session.rs`.

For a native module change, read ABI, module authoring, `include/snolc.h`, SDK
I/O/module helpers, the module source, its templates, manifest, and native
tests.

For policy work, read policy-local, config, `modules/policy-local/src/`, policy
templates, operations control examples, and policy/storage/crash acceptance
rows.

For installer or release work, read packaging, platforms, acceptance,
`crates/snolpkg`, `snolpkg/*.toml`, release tools, and workflows.

For client work, read URI, operations, architecture, `clients/snolcNG`, client
templates, Android workflow, and UI/Android acceptance rows.

Before reporting completion, run the checks for the changed ownership boundary,
record command duration and output, distinguish pass from unverified, and keep
each logical change in its own commit.
