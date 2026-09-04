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
proxy inbounds, plain-text routing rules, and three HTTP-carrier TLS modes:

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
  optionally cached for repeat requests). This is *not* a byte-perfect
  JA3/JA4 clone of a specific browser -- the cipher/extension list is a
  small, plausible, hand-built set, not a `wreq`/`boring`-level fingerprint
  emulation, which is not wired into the carrier layer yet.

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

Not wired up yet: `tun` inbound (no smoltcp integration -- a transparent TCP
proxy over a virtual interface needs root/CAP_NET_ADMIN and per-flow
connection tracking that has not been implemented and verified against a
real device) and the WebRTC carrier (real ICE/DTLS/SCTP data channels from
scratch). Selecting either in a config fails loudly at connection time
instead of silently doing nothing.

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
