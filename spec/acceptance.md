# acceptance

SNOLC 0.0.1 releases only when each required row has command output and an
artifact or log reference. `pass`, `fail`, `blocked`, and `unverified` are the
allowed results. A missing runner is `unverified`.

## local gates

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --release --locked
```

Run cargo-deny advisory, ban, license, and source checks. Run fuzz smoke for
wire, strict TOML boundaries, policy frames, profile URI, and archive paths.
Build release artifacts from `Cargo.lock`; record rustc, linker, target, source
commit, SHA-256, size, and dependency inventory.

## network gates

- SOCKS5 CONNECT and UDP ASSOCIATE cross smoltcp, yamux, protection, and carrier.
- HTTP CONNECT preserves bytes following the header.
- TUN passes IPv4 and IPv6 TCP/UDP with full tuple separation.
- Stalling the virtual device stops SOCKS5 and HTTP payload progress.
- TCP covers partial I/O, backpressure, half-close, reset, retransmission, and
  tuple reuse.
- UDP covers 0, 1, and 65,507 bytes, fixed destinations, fragments, and slot
  exhaustion.
- Noise and SSH run between separate processes with real sockets.
- Replacing a carrier does not modify core.

## contract gates

- C and Rust descriptor sizes and offsets match on each built ABI.
- Libraries from supported Rust toolchains obey the same C call contract.
- Wrong wire, short descriptors, nonzero reserved, stale handles, and short
  buffers fail without panic.
- Wire parsers handle every split, joined input, trailing bytes, unknown kind,
  and oversized length.
- Strict config and every checked-in template pass the runtime validation path.

## policy and storage gates

- Pump enforces measured rates while smoltcp remains serviced.
- Direction, IP, domain, SNI, Host, protocol, group, and unknown-value actions
  take effect at their documented point.
- User update and revoke under load close only affected work.
- Concurrent flows and sessions share one quota credit and one rate weight.
- Carrier retries do not charge payload twice.
- Kill before and after debit commit and during refund never reissues durable
  credit; crash overcharge stays within one block per active user.
- Admin sequence replay, conflict, old sequence, and gap return the specified
  result after commit and runtime apply.
- Corruption, full disk, lock denial, sync error, size cap, backup, restore, and
  native 32-bit file access have explicit results.

## package and UI gates

- Signature, hash, size, target, dependency, path, link, mode, and extraction
  limit failures preserve the old lock.
- Binary and source modes do not fall back to each other.
- Git, artifact download, and child Cargo honor explicit proxy failure.
- Offline mode performs no network request.
- snolcNG imports, requests package approval, connects one library engine,
  displays status, marks stale data, and handles revoke.
- URI input cannot select administrative paths or execute code.

## resource gates

Measure idle, steady, and peak RSS for every supported official module
combination. Run two users and sixteen TCP/UDP flows at 1 Mbit/s for 60 minutes
with 10,000 stored users and at most 256 cached users. Confirm RSS limits and
bounded queues under a slow peer and stalled policy.

Run the normative TCP profile after the release workspace build:

```sh
cargo build --workspace --release --locked
SNOLC_LONG_RUN_SECONDS=3600 SNOLC_STORED_USERS=10000 \
  cargo test --release -p snolc --test native_session \
  release_resource_profile --locked -- --ignored --nocapture --exact
```

The test prints duration, stored users, flows, payload throughput, RSS, and HWM.
It opens eight TCP and eight UDP flows across two users. It fails outside
0.95..1.05 Mbit/s or the 32/64/96 MiB RSS limits.

Measure the available host's unthrottled ceiling through the same path:

```sh
SNOLC_RESOURCE_CEILING=1 SNOLC_LONG_RUN_SECONDS=60 SNOLC_STORED_USERS=2 \
  cargo test --release -p snolc --test native_session \
  release_resource_profile --locked -- --ignored --nocapture --exact
```

Record the CPU and host with this result. Only a physical device near 600 MHz
satisfies the low-frequency hardware gate.

Measure ceiling throughput on an available physical device near 600 MHz. Label
virtual CPU measurements by their host and model. Check stripped installed
binaries against the 128 MiB allocation and report database, logs, staging, and
backup space separately.

## Tier 1 gates

Linux runs all network, crash, storage, package, UI, and resource cases on a
real kernel. Android runs APK install, profile import, Keystore persistence,
VPN permission, TUN lifecycle, both ABI libraries, protect on every transport,
network change, carrier loss, and permission revoke on a device or emulator.

The release report lists blocked rows. It does not convert them to pass. A
security audit is reported only with the auditor and report reference.

## release evidence

Publish:

- package and wire version;
- source commit and dirty-state result;
- Rust and build-tool versions;
- target triple and minimum OS, libc, API, and ISA;
- checksums, signatures, and dependency notices;
- exact test commands and durations;
- RSS, throughput, long-run, and disk measurements;
- failed, blocked, and unverified rows.

Compare two clean independent release builds before claiming reproducibility.
