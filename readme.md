<div align="center">

# snolc

userspace-stack proxy for linux and android.

<a href="https://count.owenewans.org/owenewans/owenclave?theme=moebooru-h&notitle"><img src="https://count.owenewans.org/owenewans/owenclave?theme=moebooru-h&notitle" alt="repository views"></a>

`rust` `smoltcp` `tcp` `udp` `ipv4` `ipv6`

</div>

snolc moves TCP and UDP traffic through a userspace network stack. The host OS
does not terminate tunneled flows. Inbound, routing, protection,
multiplexing, carrier and TLS are independent layers selected by YAML.

The implementation is under active construction.

Working end to end today: `snolc run` client/server, the ephemeral
handshake, chacha/AES/no-op protection, one yamux session per carrier
connection, heartbeat + reconnect, server connection limits, hot key
revocation (config file re-read, applied in well under a second), the
unknown-client fallbacks (`error`/`file`/`site`/`service`), SOCKS4/5 and HTTP
proxy inbounds (including full SOCKS5 `UDP ASSOCIATE`), a `tun` inbound with
a real smoltcp TCP/IP stack for both TCP and UDP, plain-text routing rules,
and three HTTP-carrier TLS modes:

- `tls: null` -- no TLS, camouflaged only as an HTTP `CONNECT` proxy.
- `tls: { mode: acme }` -- a real, publicly trusted certificate obtained
  autonomously from Let's Encrypt (TLS-ALPN-01, via `rustls-acme`). `bind`
  and `remote` must use port 443: that is where the CA always validates the
  challenge, independent of the port the service would otherwise prefer.
  Verified live against a real domain: full trust chain to ISRG Root,
  client and server both terminate genuine TLS.
- `tls: { mode: steal }` -- REALITY-style camouflage. The client sends a
  syntactically valid TLS 1.3 `ClientHello` for `donor`'s SNI carrying a
  time-windowed HMAC tag in `session_id`. A server that recognizes the tag
  switches straight to the snolc protocol without ever completing a TLS
  handshake with the real client; anyone else -- a browser, a scanner, a
  censor actively probing the server -- is spliced byte-for-byte to `donor`
  and gets its genuine TLS session back, verified live against a real site
  (donor's real, browser-trusted certificate, full page content, response
  optionally cached for repeat requests). `fingerprint` (required) picks the
  shape of that outward-facing `ClientHello`:
  - `fingerprint: none` -- a small, plausible, hand-built cipher/extension
    set with no extra native dependency. Not a byte-perfect clone of any
    real browser.
  - `fingerprint: chrome131` / `firefox133` -- a real BoringSSL handshake
    (via `boring`, the same library real Chrome releases are built on),
    configured with that browser's real cipher list, curve list, signature
    algorithms, ALPN, GREASE, and (Chrome only, matching its real behavior
    since ~110) randomized extension order. No real TLS session is ever
    completed by the client -- this only reuses BoringSSL to produce the
    exact wire bytes of the first flight, then patches the same
    fixed-position `session_id` field the hand-built path does. Verified
    live end to end against a real VPS with both profiles, and against the
    real donor fallback (an unmodified, tag-less request to the same port
    still gets `example.com`'s genuine page back through the splice).
    `wreq` was evaluated as a second engine but its BoringSSL fork
    (`btls-sys`) and `boring`'s (`boring-sys`) both declare the same Cargo
    `links = "boringssl"` key, so linking both into one binary is not
    possible; `boring` was kept as the lower-level, more auditable option.

The `mirror` primitive behind `steal`'s donor fallback (point at any address,
get an exact byte-for-byte copy of its traffic, with optional in-memory
response caching) is also used by the `site`/`service` unknown-client
fallbacks.

The `ssh` carrier is also real: a genuine SSH key exchange, transport
encryption, and one opened "session" channel used as the transport. The
server accepts any SSH public key -- the real per-client check is the snolc
handshake carried inside the channel, the same camouflage-vs-real-auth split
used by `acme`/`steal`. The host key is generated once at server startup and
reused for the process lifetime, like a real `sshd`'s.

`snolc-geoconv`, a separate binary (not a `snolc` subcommand -- `snolc`
itself only ever accepts `run`/`version`/`keygen`), converts plain-text
geoip/geosite source lists into routing-rule fragments:

```sh
snolc-geoconv geosite --action direct domain-list-community-file.txt > fragment.yml
snolc-geoconv geoip --action direct ipdeny-country-file.txt >> fragment.yml
```

It reads the domain-list-community line format (`domain:`/`full:`, the
plain-text source sing-box and Xray themselves compile their binary geosite
databases from) and plain CIDR-per-line files (e.g. ipdeny.com's per-country
zone files) -- not sing-box's or Xray's own compiled binary databases, which
this tool does not parse. `keyword:`/`regexp:`/`include:` entries have no
equivalent in snolc's exact/suffix-only domain matching and are skipped, not
mistranslated; the output is meant to be assembled by hand under a `rules:`
key alongside a final `- match: any` rule, which the converter deliberately
leaves out (only the user knows whether the default should be `direct` or
`proxy`).

The `tun` inbound is a real smoltcp userspace TCP/IP stack over a virtual
interface. Every new outbound TCP SYN gets its own dedicated listening socket
bridged into the same `outbound::Connector` the SOCKS/HTTP inbounds use; UDP is connectionless, so
instead one smoltcp UDP socket is bound per distinct destination port seen,
and this module demultiplexes datagrams arriving on it by 4-tuple into their
own outbound flow. On Linux, a null `descriptor` makes snolc create and
configure the interface itself (root/`CAP_NET_ADMIN` required). `auto: true`
installs a default route (both address
families) into a dedicated policy-routing table so all otherwise-unmarked
traffic is captured; `auto: false` requires an explicit `include` list of
prefixes to capture instead. `exclude` prefixes, and (unless
`strict_route: true`) the usual multicast/broadcast/link-local ranges, get
`throw` routes in that same table so they fall through to the host's normal
routing instead of the tun device. snolc's own outbound sockets (carrier,
mirror, target, and WebRTC ICE) all carry a fixed `SO_MARK`, which is exactly
what stops the process from recapturing its own connection attempts back into
the tun device. An embedding application can install
`snolc::vpn::set_socket_protector`; that callback runs after each carrier,
direct-target or WebRTC TCP/UDP socket is created but before it connects or
sends traffic, which is where Android clients call
`VpnService.protect(int)`. `include`/`exclude`
capture with `auto: false` is verified live against a real VPS: an HTTP
`GET` and a raw DNS query both round-tripped correctly through the tunnel,
and every route/rule/interface/`rp_filter` change was fully undone on
shutdown. `auto: true`'s default-route capture and `strict_route` are
covered by unit tests on the route/rule construction only -- not yet
exercised live against a real default route, to avoid capturing an
in-use host's own unrelated traffic during testing.

When `descriptor` is an integer, snolc instead attaches to that already
configured IP-mode TUN descriptor. It does not invoke `ip`, change host
addresses/routes/rules or touch `rp_filter`; `auto`, `include`, `exclude` and
`strict_route` are therefore host-setup metadata only in this mode. The
configured `address` and `mtu` still drive smoltcp and must match the external
interface. snolc duplicates the descriptor before giving it to smoltcp, so
the caller retains ownership of the original descriptor.

The WebRTC carrier is real ICE/DTLS/SCTP built on `webrtc-rs/webrtc`, with a
custom UDP-based signaling protocol (`SNLCWRTC` offer/answer packets with
retransmission) carrying the SDP exchange, plus a minimal embedded STUN
Binding responder on that same signaling socket -- so a client behind NAT
gets a real server-reflexive candidate from the snolc server itself, with no
dependency on a third-party STUN service. Verified live end to end over the
real internet (not loopback): a SOCKS request through a local client
reached a real HTTPS site via ICE/DTLS/SCTP through a VPS server.

UDP end to end: SOCKS5 `UDP ASSOCIATE` relays arbitrary per-destination
datagrams (each destination gets its own outbound flow, direct or tunneled,
chosen by the same routing rules as `CONNECT`), and the wire protocol's
`Udp` stream type carries one datagram per frame in each direction on the
server side. `tun`'s own UDP support (above) reuses the same
`Connector::connect_udp`.

## commands

```text
snolc run <config.yml>
snolc version
snolc keygen
```

There is no default inbound. A client config must explicitly enable `tun`,
`socks` or `http`. The role is part of the config, not a CLI flag.

`keygen` writes one YAML document to stdout:

```yaml
private: <base64 client private key>
public: <base64 client public key>
```

Keep `private` only in the client config. Put `public` into the server's
`clients` list.

## android cli

The standalone arm64 CLI requires Android 7.0/API 24 or newer. Set the NDK
path and run the build script; libc++ is linked into the executable, so the
result is one file with no companion shared libraries.

```sh
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
./scripts/build-android.sh
```

The output is `target/aarch64-linux-android/release/snolc`. It can be smoke
tested on a connected device without installing an APK:

```sh
adb -s <serial> push target/aarch64-linux-android/release/snolc /data/local/tmp/snolc
adb -s <serial> shell chmod 755 /data/local/tmp/snolc
adb -s <serial> shell /data/local/tmp/snolc version
adb -s <serial> shell /data/local/tmp/snolc keygen
```

The standalone CLI cannot acquire Android's `VpnService` permission itself.
An Android application must create and configure the TUN with
`VpnService.Builder`, put its live descriptor in the `tun.descriptor` config
field, and keep the original descriptor open while snolc runs. Android
requires a descriptor whenever `tun` is enabled; snolc never invokes `ip` or
uses `SO_MARK` there.

The same application must install a `snolc::vpn::SocketProtector` before
starting the runtime. The callback may run concurrently on arbitrary runtime
threads, receives a borrowed socket descriptor, and must synchronously forward
it to `VpnService.protect(int)` without retaining or closing it. Returning an
error aborts that connection instead of allowing it to loop back into the
VPN. The JNI/FFI bridge belongs to the embedding application; the standalone
CLI intentionally has no Java-specific code.

Use an IP literal for the bootstrap `remote`, or resolve it through Android's
underlying `Network` before establishing the TUN. System DNS resolution does
not expose its socket descriptor to the protector hook.

## logs

Logging is disabled unless both `LOGS` and `FILE` are set.

```sh
LOGS=warning,error,debug FILE=/tmp/snolc.log LIMIT=8mb snolc run client.yml
```

`LIMIT` accepts `kb`, `mb` and `gb`, including decimal values such as `1.1gb`.
Existing logs are appended. Once the limit is reached, oldest complete records
are removed and new records continue.

On success the runtime is silent. On failure stderr contains only
`error <code>`; details are written to the log when enabled. `version` and
`keygen` produce their requested data on stdout.

## development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

Native Windows is not supported. Use WSL.
