# platforms and resource contract

snolc publishes target-specific binaries. One `.so` cannot represent another
libc, architecture, ABI, or Android API.

## support tiers

| tier | systems | project obligation |
| --- | --- | --- |
| 1 | Linux, Android | release E2E, long run, resource tests, priority fixes, security review |
| 2 | FreeBSD 14, OpenBSD 7.7, NetBSD 10, postmarketOS, Termux, WSL Linux target | supported profiles and most features, fewer hardware runs |
| 3 | Haiku, macOS 11+ | build and static checks; runtime reports may come from users |
| 4 | native Windows | compile where practical; use is discouraged |

The minimum Linux profile is kernel 4.19 and glibc 2.28. Android requires API
24. The release manifest records the target triple and minimum runtime for each
artifact.

Linux release jobs build inside the pinned Debian 10 container from the pinned
2024-06-12 package snapshot. `tools/check-glibc.py` rejects any ELF artifact
whose imported symbol versions exceed `GLIBC_2.28`.

## release targets

Linux targets are i586 GNU, i686 GNU, x86_64 GNU, aarch64 GNU,
armv7-gnueabihf, and riscv64gc GNU. Android targets are armv7 and aarch64. BSD,
macOS, Haiku, and Windows targets use triples supported by the pinned Rust
toolchain and runner. CI records a missing runner or target as unverified. It
does not mark that row passed.

The i586 build enables SSE and SSE2 because the pinned SSH cryptography stack
requires them; its published minimum ISA must say so. Rust 1.98.1 does not
distribute all BSD host toolchains. CI builds FreeBSD 14 x86_64/aarch64 and
NetBSD 10 x86_64 inside target-native VMs. The pinned distribution has no
OpenBSD or NetBSD aarch64 host toolchain. Those rows and Haiku x86_64 remain
unverified; CI does not mark them passed with another compiler version.

Official module manifests list measured artifacts for:

- `x86_64-unknown-linux-gnu`, x86-64, glibc 2.28;
- `aarch64-linux-android`, armv8-a, API 24;
- `armv7-linux-androideabi`, armv7-a, API 24.

Other matrix entries remain release blockers until their artifact and stated
checks exist.

## low-memory runtime

The reference host has 256 MiB RAM, one core near 600 MHz, and HDD storage.
Installed release binaries for CLI, library, and ten official modules must fit
128 MiB without debug symbols or toolchain. State, logs, staging, and backups
use separate disk allocation.

For any supported official module combination:

- idle RSS is at most 32 MiB;
- steady RSS is at most 64 MiB with two sessions and sixteen active flows;
- transient peak RSS is at most 96 MiB.

Measurements include module workers and child processes. GUI, Cargo, and
package installation are reported separately.

The verification profile uses two users, sixteen TCP and UDP flows, aggregate
payload rate capped at 1 Mbit/s, 10,000 stored users, at most 256 cached users,
and 60 minutes of transfer. A physical device near 600 MHz supplies the ceiling
throughput result. A virtual CPU result has its own label.

## memory accounting

The engine low-memory configuration permits 32 MiB managed bytes. It allocates
flow buffers when flows open and rejects a new flow before budget overflow.
This counter covers core-owned buffers. It cannot constrain arbitrary native
module allocation, so official modules share an RSS release gate.

Two yamux sessions times seventeen streams times a 256 KiB receive window
requires 8.5 MiB of window capacity. Socket buffers, UDP metadata, packet
queues, database cache, workers, and service channels add to RSS.

Resource exhaustion rejects the new session, flow, fragment, DNS request, or
command. Active traffic keeps bounded allocations. A stalled peer or policy
cannot create an unbounded queue.

## Android

The APK contains one Rust UI and engine plus all ten official modules for
`arm64-v8a` and `armeabi-v7a`. A small Java bridge owns `VpnService`, permission,
foreground notification, network change callbacks, Keystore, and fd handoff.

The app duplicates the TUN fd and closes only its descriptor. Every official
carrier socket calls `VpnService.protect` before connect, including SSH worker
sockets. Protect failure prevents connect. Carrier loss keeps TUN active and
does not route direct. VPN permission revoke arrives as a platform event.

The store build follows store executable-code rules. It does not download
arbitrary native libraries. Release APKs use a release signing key; debug APKs
are test artifacts.

`assembleRelease` requires `SNOLC_ANDROID_KEYSTORE`,
`SNOLC_ANDROID_STORE_PASSWORD`, `SNOLC_ANDROID_KEY_ALIAS`, and
`SNOLC_ANDROID_KEY_PASSWORD`. Gradle rejects incomplete signing input. Keep the
keystore and passwords outside the repository, then verify the APK with the
pinned build-tools `apksigner` before publication.
