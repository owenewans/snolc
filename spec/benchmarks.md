# benchmarks

The proxy benchmark uses a 1 MiB cached payload, 30 one-byte latency requests,
three single-flow transfers and eight concurrent transfers. RSS covers one
client or server process after the workload. All rows use release binaries with
logging disabled.

## snolc 0.0.4 loopback

This run used the published x86_64 core and module archives with four workers.

| stack | p50 | p95 | one TCP flow | eight TCP flows | client RSS | server RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| snolc dummy/TCP | 1.52 ms | 1.78 ms | 2,992.72 Mbit/s | 3,777.35 Mbit/s | 9.71 MiB | 10.45 MiB |
| Xray VLESS/RAW | 2.04 ms | 2.40 ms | 2,410.52 Mbit/s | 3,565.79 Mbit/s | 38.88 MiB | 39.47 MiB |
| Xray VLESS/RAW mux | 1.86 ms | 2.21 ms | 1,499.04 Mbit/s | 1,980.81 Mbit/s | 36.94 MiB | 40.97 MiB |
| Xray VLESS/TLS | 10.99 ms | 11.66 ms | 542.95 Mbit/s | 1,906.92 Mbit/s | 43.22 MiB | 42.95 MiB |
| sing-box VLESS/TCP | 1.65 ms | 2.00 ms | 2,615.72 Mbit/s | 3,609.08 Mbit/s | 64.83 MiB | 67.20 MiB |
| sing-box VLESS/TCP smux | 1.75 ms | 2.14 ms | 2,063.11 Mbit/s | 3,211.18 Mbit/s | 67.32 MiB | 67.23 MiB |
| sing-box VLESS/TLS | 9.90 ms | 11.06 ms | 593.55 Mbit/s | 2,140.01 Mbit/s | 71.12 MiB | 70.93 MiB |
| Hysteria 2 | 1.83 ms | 2.26 ms | 900.55 Mbit/s | 1,494.25 Mbit/s | 32.57 MiB | 31.19 MiB |

Two additional five-run snolc series produced eight-flow medians of 4,008.6
and 4,035.9 Mbit/s. The fastest run reached 4,367.9 Mbit/s. Noise/TCP reached a
2,965.7 Mbit/s five-run median.

## real server

The client and server ran on different hosts on 2026-09-18. The HTTP target
listened on the server loopback address, so each response crossed the tunnel in
both directions. Server RSS is omitted because the launcher PID does not
represent the remote process.

| stack | p50 | p95 | one TCP flow | eight TCP flows | client RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| snolc dummy/TCP | 166.62 ms | 187.66 ms | 12.60 Mbit/s | 86.45 Mbit/s | 11.02 MiB |
| Xray VLESS/RAW | 178.49 ms | 189.42 ms | 11.37 Mbit/s | 87.90 Mbit/s | 36.72 MiB |
| sing-box VLESS/TCP | 177.40 ms | 237.21 ms | 12.17 Mbit/s | 81.17 Mbit/s | 65.25 MiB |
| Hysteria 2 | 173.11 ms | 180.51 ms | 31.39 Mbit/s | 123.95 Mbit/s | 31.84 MiB |

The TCP stacks shared an 11–13 Mbit/s single-flow ceiling on this link.
Hysteria used QUIC.

## resource profile

The native profile runs eight TCP and eight UDP flows through SOCKS5, smoltcp,
Noise, TCP and policy-local.

| host | users | interval | payload | idle RSS | sampled RSS | HWM |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Xeon E5-2670 v3, Linux x86_64 | 10,000 | 60 s | 5,094,331 bit/s | 12.14 MiB | 19.73 MiB | 19.25 MiB |
| Celeron M 630 MHz, Alpine i686 | 10,000 | 60 s | 3,875,362 bit/s | 10.05 MiB | 23.88 MiB | 23.85 MiB |
| Xeon E5-2670 v3, Linux x86_64 | 100,000 | 30 s | 5,111,808 bit/s | 15.19 MiB | 22.80 MiB | 22.24 MiB |

Run the profile with:

```sh
SNOLC_RESOURCE_CEILING=1 SNOLC_LONG_RUN_SECONDS=60 \
SNOLC_STORED_USERS=10000 \
cargo test --release -p snolc-module-tests --test native_session \
  release_resource_profile --locked -- --ignored --nocapture --exact
```

Loopback throughput measures the software ceiling of one host. Compare network
results only when the binaries, hosts, link and workload match.
