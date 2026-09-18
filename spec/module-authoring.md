# module authoring

A module is a Rust `cdylib` that implements one or more ABI class tables. Use
`snolc-abi` for layouts and `snolc-sdk` for safe wrappers. Do not link a module
to `snolc` private types.

Runnable skeletons live in:

- `crates/snolc-sdk/examples/adapter.rs`
- `crates/snolc-sdk/examples/protection.rs`
- `crates/snolc-sdk/examples/carrier.rs`
- `crates/snolc-sdk/examples/policy.rs`

Build an example with the pinned toolchain:

```sh
cargo run --locked -p snolc-sdk --example adapter
```

## descriptor

Export `snolc_module_entry` and return a process-lifetime descriptor. Set
`struct_size`, `wire_version = 1`, one or more class mask bits, and
`reserved = 0`. Populate every operation required by each advertised class.

`describe` returns bounded metadata. `validate_config` parses strict TOML and
checks the selected role and platform before listeners or workers start.
`create` allocates an instance after validation. `shutdown` may return Pending;
core polls it until completion or `shutdown_timeout_ms`. `destroy` releases the
stopped instance.

Wrap each exported Rust function with the SDK unwind boundary. Return a status
code for expected errors. Do not panic across C.

## configuration

Use `serde(deny_unknown_fields)` on every options branch. Require a mode field
when options select different behavior. Reject a role that the package did not
publish. Resolve relative paths against the absolute base directory supplied by
the host. Do not read the process current directory or search a home directory.

Secrets use an explicit TOML or environment source. Redact secret `Debug` and
error output. A module must not log keys, bearer tokens, credentials, user
payload, or private policy messages.

## asynchronous work

Module methods run on the engine network thread. A method performs bounded work
and returns Pending after registering a wake. It must not block on DNS, files,
database calls, child completion, mutex ownership, or sleep.

Create one bounded worker for blocking work owned by an instance. The worker
sends a completion message and calls only `WakeHandle::wake`. Tag work with a
generation so a late result cannot target a reused flow. Bound worker queues in
configuration and reject new work when full.

## I/O

Use SDK ByteIo and DatagramIo wrappers. Preserve partial progress, Pending,
half-close, flush, and message boundaries. For a nonempty write, return Pending
or positive progress. Never report progress of zero bytes.

Policy implementations receive `StackSocket` and `MuxStream`. Use SDK `Pump`
to move bounded chunks. The policy selects when and how much work Pump performs.
No other component may copy that flow's payload.

Carrier implementations produce an ordered duplex stream. Protection wraps the
carrier stream and exposes another ByteIo. An adapter receives StackPort and
flow metadata, not a direct yamux writer.

## control

Control payloads are opaque bytes to core. Define and document a bounded schema
inside the module. Unknown methods return `STATUS_UNSUPPORTED`. A control call
may return Pending and completes on the module thread. Keep administrative
authority separate from user policy streams.

## package

Publish `snolc-modules/snolpkg/<module>.toml` and its detached 64-byte Ed25519 signature. The
manifest identifies roles, platform capabilities, source commit, Rust package,
role templates, and target artifacts. Each artifact includes target triple,
minimum ISA or Android API, byte size, SHA-256, and build output.

An archive contains the declared library, `templates/<role>.toml`, project
license, and required dependency notices. The installer rejects links, devices,
absolute paths, parent traversal, duplicate paths, setuid bits, size overflow,
signature mismatch, and hash mismatch.

## tests

Test descriptor layout, wrong wire version, stale handles, every stream split,
partial writes, Pending wake registration, EOF in each direction, queue
exhaustion, shutdown timeout, and panic translation. Build separate 32-bit and
64-bit libraries where the target matrix requires them. Loading two Rust
toolchain builds through the same C header checks ABI use; it does not make Rust
ABI stable.
