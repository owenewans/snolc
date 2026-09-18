# architecture

The `snolc` repository exposes a library engine and a thin CLI. The snolcNG
client imports the engine at a pinned commit.
The compatibility generation is `wire_version = 1`.

## packet path

User payload follows one path in each direction:

```text
Adapter -> smoltcp -> yamux -> Protection -> Carrier
```

`StackBridge` owns smoltcp interfaces and socket sets. An adapter receives an
external request or packet, then hands it to `StackBridge`. Policy owns the
transfer between a smoltcp socket and a yamux stream. Core has no second copy
loop and no direct adapter-to-yamux path.

## repositories and crates

- `snolc-abi` defines C-compatible values and function tables.
- `snolc-sdk` wraps ABI I/O, handles, wakes, framing, and `Pump`.
- `snolc` owns configuration, loading, stack, mux, events, and the engine.
- `snolc-cli` handles arguments, signals, control requests, and output.
- [`snolc-modules`](https://github.com/owenewans/snolc-modules) owns the ten
  official modules, templates, manifests and native E2E tests.
- [`snolpkg`](https://github.com/owenewans/snolpkg) installs signed packages.
- [`snolcNG`](https://github.com/owenewans/snolcNG) owns profile import, the
  desktop UI and Android bootstrap.

Core depends on ABI. SDK depends on ABI. The module repository pins one SDK
commit. Modules do not link to private core types. Concrete modules do not
appear in core.

## ownership and execution

`Engine::run` owns one `async_executor::LocalExecutor` on the calling thread.
`async-io` owns its reactor thread. Engine commands use a bounded queue and run
module callbacks on the network thread. `EngineHandle` never invokes a module
from its caller's thread.

Each mutable socket, stream, module instance, and flow has one owner. Handles
combine an index with a generation. A stale generation cannot select a reused
slot.

Blocking owners use bounded workers:

- one file-log worker per engine;
- one redb worker per policy-local instance;
- one system resolver worker per adapter-direct instance;
- one Tokio current-thread worker per carrier-ssh instance.

The network thread performs no filesystem access, blocking DNS, thread joins,
mutex waits, or sleeps.

## engine lifecycle

The engine moves through `Configured`, `Starting`, `Running`, `Stopping`, then
`Stopped`. A startup or engine-wide invariant failure selects `Failed`. A flow
or session error closes that scope and emits an event. It does not stop other
sessions.

The library does not install signal handlers, replace the host logger, or call
`exit`. The CLI owns process behavior. A host embeds the engine on a dedicated
thread and uses `EngineHandle` for control, snapshots, events, and shutdown.

## module boundaries

Adapters own external protocol and platform operations. Carriers provide an
ordered duplex byte stream. Protection wraps that byte stream. Policy admits
sessions and flows, transfers payload, accounts usage, schedules rates, and
applies user rules.

Core does not define users, credentials, quota, payment, destination rules, or
rate limits. `policy-local` owns those types and stores its records in redb.
`policy-dummy` accepts flows and uses SDK `Pump` without account logic.

Native modules are trusted process code. Hashes and signatures identify code;
they do not isolate it. Core catches Rust unwind at exported calls. A segfault,
abort, allocator failure, or memory corruption can terminate the process.

## resource failure

All queues and payload buffers have configured bounds. A new session or flow
gets a resource error when its allocation would exceed a bound. Existing flows
retain their allocations. Carrier, protection, or policy failure never enables
direct fallback.

TCP work yields after `max_io_chunk`. UDP work handles one full datagram.
smoltcp ingress handles at most `max_ingress_packets_per_tick` before yielding.
Timers wake the executor at the nearest deadline; idle instances do not spin.

## update model

The loader verifies package lock identity and content hash before loading a
library. It keeps each library loaded until the engine and all module-owned
handles stop. An update installs immutable content beside the old package. The
operator activates code through an engine restart. Policy data changes do not
require that restart.

## failure surfaces

- configuration errors stop startup before listeners open;
- a module config error names its instance;
- an incompatible descriptor fails before `create`;
- a flow error closes one flow;
- a session error closes its yamux and carrier resources;
- an engine invariant failure changes lifecycle to `Failed`;
- queue overflow returns a resource error or records a bounded loss counter.

Snapshots retain the latest scoped reason. Events report transitions without
containing secrets or payload.
