# benchmarks

Run benchmarks from a release build with logging disabled. Record failed runs
and keep their logs. A result covers one binary, configuration, host and date.

## resource profile

The native profile starts a server and two clients in one process. Traffic
crosses SOCKS5, smoltcp, yamux, Noise, TCP and policy-local. Eight TCP flows and
eight UDP flows share two users. The test stores the requested user count in
redb before traffic starts.

```sh
SNOLC_RESOURCE_CEILING=1 SNOLC_LONG_RUN_SECONDS=60 \
SNOLC_STORED_USERS=10000 \
cargo test --release -p snolc-module-tests --test native_session \
  release_resource_profile --locked -- --ignored --nocapture --exact
```

| host | limit | users | interval | payload | idle RSS | sampled RSS | HWM |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Xeon E5-2670 v3, Linux x86_64 | none | 10,000 | 60 s | 5,094,331 bit/s | 12,730,368 B | 20,692,992 B | 20,185,088 B |
| ASUS Eee PC 701, Celeron M 630 MHz, Alpine 3.24 i686 | 256 MiB, no swap | 10,000 | 60 s | 3,875,362 bit/s | 10,543,104 B | 25,034,752 B | 25,006,080 B |
| Xeon E5-2670 v3, Linux x86_64 | none | 100,000 | 30 s | 5,111,808 bit/s | 15,929,344 B | 23,904,256 B | 23,322,624 B |

The Eee PC command ran inside cgroup v2:

```sh
mount -t cgroup2 none /sys/fs/cgroup
mkdir /sys/fs/cgroup/snolc-bench
echo 268435456 > /sys/fs/cgroup/snolc-bench/memory.max
echo 0 > /sys/fs/cgroup/snolc-bench/memory.swap.max
echo $$ > /sys/fs/cgroup/snolc-bench/cgroup.procs
```

The Eee PC traffic test took 186.30 seconds including setup and teardown. The
100,000-user run took 1,060.19 seconds. Database creation accounts for most of
that wall time.

## proxy workload

`tools/proxy-bench.py` drives a SOCKS5 endpoint with curl. Use a one-byte file
for 30 latency samples and a 1 MiB file for three single-flow transfers plus an
eight-flow transfer. The script passes `--noproxy ""`; without it, curl can
bypass a loopback proxy through `NO_PROXY`.

```sh
truncate -s 1048576 data/payload
printf x > data/tiny
python -m http.server 18080 --bind 127.0.0.1 --directory data

python tools/proxy-bench.py NAME PORT \
  '["SERVER", "ARGS"]' '["CLIENT", "ARGS"]' \
  --payload-url http://127.0.0.1:18080/payload \
  --latency-url http://127.0.0.1:18080/tiny \
  --payload-bytes 1048576 --flows 8 --samples 3
```

Sparse files and the page cache make loopback throughput a software ceiling.
Use the real-server table in
[`xray-and-sing-vs-snolc.md`](xray-and-sing-vs-snolc.md) for network results.

## 0.0.4 proxy result

The 0.0.4 release candidate used four workers, 128 KiB mux frames and adapter
buffers, and a 512 KiB adapter work budget. Two independent five-run loopback
series produced eight-flow medians of 4,008.6 and 4,035.9 Mbit/s. The peak was
4,367.9 Mbit/s. Median p50 latency across those runs was 1.30 ms. Client and
server RSS stayed between 9.9 and 10.6 MiB.

Noise/TCP used the same configuration. Its five-run median was 2,965.7 Mbit/s
with 1.46 ms p50 latency and about 10.5 MiB RSS.

The real-server correctness run used `93.95.228.248`, four workers at each end,
and the same payload and sample counts. It completed at 86.5 Mbit/s aggregate
with a 12.6 Mbit/s single-flow median and 166.6 ms p50 latency. The link, host
and date differ from the comparison table, so these values do not form a direct
ranking.

## required stress rows

Release evidence must include these rows:

| case | input |
| --- | --- |
| stored users | 10,000 and 100,000 |
| active flows | 1, 8 and 16 mixed TCP/UDP |
| duration | 60 seconds ceiling and 60 minutes at 1 Mbit/s |
| backpressure | slow reader and stalled policy |
| payload edges | UDP 0, 1 and 65,507 bytes; fragmented IPv4 and IPv6 |
| lifecycle | reconnect, revoke, half-close, reset and shutdown |
| storage | full disk, backup, restore and crash during quota debit |

The native E2E suite covers payload edges, lifecycle and storage faults. The
resource profile covers 16 flows and stored-user rows. Publish the 60-minute
row only after the full interval completes.
