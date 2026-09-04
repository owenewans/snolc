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
proxy inbounds, plain-text routing rules, and the HTTP carrier (no TLS yet,
disguised as an HTTP `CONNECT` proxy).

Not wired up yet: `tun` inbound (no smoltcp integration), SSH/WebRTC carriers,
HTTP carrier TLS (`acme`/`steal`), and the geoip/geosite rule converter.
Selecting any of these in a config fails loudly at connection time instead of
silently doing nothing.

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
