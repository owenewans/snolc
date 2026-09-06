<div align="center">

# snolc

userspace-stack proxy for linux and android, resistant to traffic filtering.

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
