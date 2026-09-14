<div align="center">

# snolc

userspace-stack proxy for linux and android, resistant to traffic filtering.
If you came here from olcRTC, you might be confused about what this is all about, and what you see in this repository now isn't the snolc it will become. The codebase is a draft that's only loosely related to olcrtc. In more detail, here's how it works: The kernel remains small and remains virtually unchanged. It contains a userspace TCP/IP stack (smoltcp), one yamux instance per carrier connection, and encryption. Nothing else. The kernel doesn't know which service is masking the traffic, doesn't know how it's encoded, and doesn't resolve dependencies between modules—it simply feeds bytes to the module's input and expects them to come out the other end in the same order. This separation is intentional: TLS fingerprints become obsolete within months, service APIs change without warning, but protocol primitives like TCP/IP and multiplexing don't. Only the things that are truly broken are updated. A module is a .so/.dylib file, which is included in the config file with a single line: module:/path/module.yaml . The module exports a minimal set of functions via extern "C" (or via abi_stable/ffi_rpc, to avoid segfaults due to layout mismatches between rustc versions; I haven't decided yet, frankly): initialization from YAML, sending bytes, and receiving bytes. Everything else—how the module encodes data into legitimate traffic, where it listens, and how it bypasses service rate limits—is entirely up to the module; the kernel doesn't care.The key point is that the delivery guarantee lies with the module, not the kernel. Yamux, which sits above the module, is designed for a reliable, ordered byte channel, like a regular TCP socket—it doesn't reorder or retrace by itself. This means that if the traffic inside a module is inherently unreliable (for example, posts in comments can get lost or arrive out of order), all ARQ logic (sequence numbers, retries, and the reorder buffer) is implemented within the module. The module is required to return the same thing to the kernel: a reliable, ordered pipe, no matter what's going on inside. Modules can call other modules. For example, the "YouTube proxying" module itself decides to split the traffic between the "via comments" sub-module and the "via video stream" sub-module, loading some data as comment text and some as video metadata. For the kernel, this is all a single top-level module; it's unaware that it's running its own small multiplexer between the two sources. The module itself loads the .so dependencies it needs and handles their versioning; the kernel doesn't interfere with this at all. No sandboxing. Modules aren't isolated via WASM or separate processes. This is a deliberate move away from unnecessary layering: the entire stack is in Rust, module authors adapt to the general kernel API, not a specific compiler version, and the cost of a module error (segfault instead of a crashed tunnel) is considered an acceptable price for simplicity and performance. For the user, this means installing modules from trusted sources, like regular binary dependencies, not as sandboxed plugins from an obscure marketplace. The practical implication of all this is that the tunnel can go through literally anything that can transfer bytes back and forth and legally operates on your network: not just classic HTTP/SSH/WebRTC carriers, but any public service for which someone might one day write a module. When a service changes its API or security, one .so file is broken, not the entire project, and an update is essentially replacing a single module, not releasing a new kernel binary. olcRTC solved a similar problem: disguising traffic as legitimate services (video calls), but providers (Jitsi, Telemost, WB Stream) were hardcoded into the project's core code. snolc takes the "proxy through a legitimate service" concept and puts it into a module, and theoretically, there could be as many modules as you want, without rewriting what's already working. I used machine translation, and I think it's all clearer now. I'd probably ask you not to submit PRs or ISSUES for now, because the code you see in the repo... isn't exactly related to snolc.

<a href="https://count.owenewans.org/owenewans/snolc?theme=moebooru-h&notitle"><img src="https://count.owenewans.org/owenewans/snolc?theme=moebooru-h&notitle" alt="repository views"></a>

`rust` `proxy` `linux`

</div>

## features

- userspace TCP/IP stack, the host OS never terminates tunneled flows
- inbounds: SOCKS4, SOCKS5 (including `UDP ASSOCIATE`), HTTP `CONNECT`, and
  `tun` with a real userspace stack for both TCP and UDP
- carriers: HTTP, SSH and WebRTC (ICE/DTLS/SCTP)
- TLS modes: none, `acme` for a real Let's Encrypt certificate, and `steal`
  for REALITY-style camouflage that splices unknown clients to a donor site
- browser TLS fingerprints: `chrome131` and `firefox133`
- traffic protection: ChaCha20-Poly1305, AES-GCM or none
- one yamux session per carrier connection, heartbeat and reconnect
- routing rules by domain and IP, with geoip/geosite conversion
- key revocation without a restart, and per-server connection limits

## install

```sh
curl -fsSL https://raw.githubusercontent.com/owenewans/snolc/master/scripts/install.sh | sh
```

Installs `snolc` and `snolc-geoconv` into `~/.local/bin`. Builds are
published for `x86_64` and `aarch64` Linux.

Override the version, directory or source:

```sh
SNOLC_VERSION=v0.1.0 SNOLC_INSTALL_DIR=/usr/local/bin \
    sh -c 'curl -fsSL https://raw.githubusercontent.com/owenewans/snolc/master/scripts/install.sh | sh'
```

Android builds one standalone arm64 binary:

```sh
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
./scripts/build-android.sh
```

## usage

```sh
snolc run <config.yml>
snolc version
snolc keygen
```

`keygen` prints a keypair. Keep `private` in the client config and put
`public` into the server's `clients` list:

```yaml
private: <base64 client private key>
public: <base64 client public key>
```

Convert domain and IP lists into routing rules:

```sh
snolc-geoconv geosite --action direct domain-list.txt > fragment.yml
snolc-geoconv geoip --action direct country-cidr.txt >> fragment.yml
```

Logging is off unless both `LOGS` and `FILE` are set. `LIMIT` accepts `kb`,
`mb` and `gb`, and rotates the oldest records once reached:

```sh
LOGS=warning,error,debug FILE=/tmp/snolc.log LIMIT=8mb snolc run client.yml
```

On success the runtime is silent; on failure stderr contains only
`error <code>`.

## configuration

One YAML file describes the whole role, so there is no client or server
flag. Inbound, routing, protection, multiplexing, carrier and TLS are
independent layers.

A client must enable `tun`, `socks` or `http` explicitly; there is no
default inbound.

For `tls: { mode: acme }`, `bind` and `remote` must both use port 443. For
`tls: { mode: steal }`, set `donor` to the site unknown clients should be
spliced to, and `fingerprint` to `none`, `chrome131` or `firefox133`.

For `tun` on Linux, leaving `descriptor` empty makes snolc create and
configure the interface itself, which needs root or `CAP_NET_ADMIN`.
`auto: true` captures all unmarked traffic; `auto: false` captures only the
prefixes in `include`. `exclude` prefixes fall through to normal host
routing. On Android an application must supply a `VpnService` descriptor in
`descriptor` instead.
