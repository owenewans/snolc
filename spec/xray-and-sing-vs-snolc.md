# Xray, sing-box, Hysteria 2 and snolc

These numbers describe one test run on 2026-09-18. They do not establish a
general ranking. The implementations use different protocols and security
properties.

## versions

| program | version | binary SHA-256 |
| --- | --- | --- |
| snolc | source commit `c07d04a1f4957916c790edbafd122bb2756a9d50` | local release build |
| Xray | `v26.3.27`, Go 1.26.1 | `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` |
| sing-box | `v1.14.1` | `f7baedea92ebb338effcf329bee74dab55c142ccc7e6de6edb6dbf70e21f678d` |
| Hysteria | `v2.12.3` | `8c7a68a906998b747a0db87586e364f995fbfddb95693ae6e2fdb68a6e920d3e` |

The client host ran Linux 7.2.6 on a 24-thread Xeon E5-2670 v3 with curl
8.22.0. The server ran Ubuntu kernel 7.0 on one x86_64 CPU with 1.9 GiB RAM and
no swap at `31.76.28.157`.

## configurations

- snolc: SOCKS5, smoltcp, yamux, dummy or Noise NK protection, TCP carrier,
  dummy policy and direct server adapter.
- Xray: SOCKS5, VLESS, RAW TCP, with plaintext, mux concurrency 8, or TLS 1.3.
- sing-box: SOCKS5, VLESS TCP, with plaintext, smux, or TLS 1.3.
- Hysteria 2: SOCKS5 over QUIC and TLS with password authentication.

Xray and sing-box plaintext VLESS ran only on loopback or the named test link.
Their documentation requires transport security on an untrusted public link.
Xray TLS pinned the leaf certificate SHA-256. sing-box and Hysteria accepted the
same test certificate with their insecure test option. Production
configurations must validate a trusted certificate or a pin.

## loopback result

Each row used a 1 MiB cached payload, 30 one-byte latency requests, three
single-flow samples and eight concurrent flows. RSS covers one client or one
server process after the workload.

| stack | p50 | p95 | one TCP flow | eight TCP flows | client RSS | server RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| snolc dummy/TCP | 211.77 ms | 212.20 ms | 0.95 Mbit/s | 7.09 Mbit/s | 9.08 MiB | 9.64 MiB |
| snolc Noise/TCP | 211.93 ms | 212.74 ms | 0.95 Mbit/s | 7.00 Mbit/s | 9.98 MiB | 9.75 MiB |
| Xray VLESS/RAW | 2.04 ms | 2.40 ms | 2,410.52 Mbit/s | 3,565.79 Mbit/s | 38.88 MiB | 39.47 MiB |
| Xray VLESS/RAW mux | 1.86 ms | 2.21 ms | 1,499.04 Mbit/s | 1,980.81 Mbit/s | 36.94 MiB | 40.97 MiB |
| Xray VLESS/TLS | 10.99 ms | 11.66 ms | 542.95 Mbit/s | 1,906.92 Mbit/s | 43.22 MiB | 42.95 MiB |
| sing-box VLESS/TCP | 1.65 ms | 2.00 ms | 2,615.72 Mbit/s | 3,609.08 Mbit/s | 64.83 MiB | 67.20 MiB |
| sing-box VLESS/TCP smux | 1.75 ms | 2.14 ms | 2,063.11 Mbit/s | 3,211.18 Mbit/s | 67.32 MiB | 67.23 MiB |
| sing-box VLESS/TLS | 9.90 ms | 11.06 ms | 593.55 Mbit/s | 2,140.01 Mbit/s | 71.12 MiB | 70.93 MiB |
| Hysteria 2 | 1.83 ms | 2.26 ms | 900.55 Mbit/s | 1,494.25 Mbit/s | 32.57 MiB | 31.19 MiB |

snolc uses less memory in this workload. Its current pump limits a stream to
about 0.95 Mbit/s and adds about 210 ms before the first response byte. Xray,
sing-box and Hysteria finish the loopback workload faster.

## real-server result

The client used the same files and sample counts. The HTTP server listened on
the remote server's loopback address, so traffic crossed the proxy tunnel in
both directions. Server RSS is omitted because the SSH launcher PID does not
represent the remote process.

| stack | p50 | p95 | one TCP flow | eight TCP flows | client RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| snolc dummy/TCP | 322.77 ms | 342.90 ms | 0.94 Mbit/s | 6.76 Mbit/s | 9.23 MiB |
| snolc Noise/TCP | 303.06 ms | 333.23 ms | 0.93 Mbit/s | 6.71 Mbit/s | 9.80 MiB |
| Xray VLESS/RAW | 99.26 ms | 132.00 ms | 21.52 Mbit/s | 70.78 Mbit/s | 37.13 MiB |
| sing-box VLESS/TCP | 104.19 ms | 122.45 ms | 20.64 Mbit/s | 113.38 Mbit/s | 62.48 MiB |
| Hysteria 2 | 98.32 ms | 1,410.22 ms | 11.87 Mbit/s | 29.98 Mbit/s | 29.97 MiB |

Xray VLESS/RAW mux returned an empty response during warm-up. Xray VLESS/TLS
accepted the SOCKS request and then stalled. Both rows are `fail`; no throughput
number is reported. The local TLS row passed with the same certificate and pin.

## commands

Download the pinned release assets, verify their hashes, then validate each
configuration before testing:

```sh
xray run -test -config xray-server.json
xray run -test -config xray-client.json
sing-box check -c sing-server.json
sing-box check -c sing-client.json
snolc validate snolc-server.toml
snolc validate snolc-client.toml
```

Start the server-side HTTP target:

```sh
python3 -m http.server 18080 --bind 127.0.0.1 --directory data
```

Run each pair through [`tools/proxy-bench.py`](../tools/proxy-bench.py). Keep the
server, target, payload, curl version and sample count unchanged between rows.

## omitted rows

UDP throughput, packet loss, jitter, REALITY, WebSocket, gRPC, XHTTP, SSH
carrier and TUN need a packet generator and network shaping. Android runtime
also needs the phone. These rows remain `unverified`; the tables do not treat a
build or loopback test as a runtime pass.

Documentation used for the matrix:

- [Xray VLESS](https://xtls.github.io/en/config/inbounds/vless.html)
- [Xray transport and TLS](https://xtls.github.io/en/config/transport.html)
- [sing-box VLESS](https://sing-box.sagernet.org/configuration/inbound/vless/)
- [sing-box multiplex](https://sing-box.sagernet.org/configuration/shared/multiplex/)
- [Hysteria 2 server](https://v2.hysteria.network/docs/getting-started/Server/)
