#!/usr/bin/env python3
import argparse
import json
import statistics
import subprocess
import time


def rss(pid, field):
    with open(f"/proc/{pid}/status", encoding="ascii") as handle:
        for line in handle:
            if line.startswith(field + ":"):
                return int(line.split()[1]) * 1024
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("name")
    parser.add_argument("socks_port", type=int)
    parser.add_argument("server", help="JSON command array")
    parser.add_argument("client", help="JSON command array")
    parser.add_argument("--payload-url", required=True)
    parser.add_argument("--latency-url", required=True)
    parser.add_argument("--payload-bytes", type=int, required=True)
    parser.add_argument("--flows", type=int, default=8)
    parser.add_argument("--samples", type=int, default=3)
    args = parser.parse_args()
    proxy = f"socks5h://127.0.0.1:{args.socks_port}"

    def curl(output, target):
        value = subprocess.check_output(
            [
                "curl",
                "-fsS",
                "--noproxy",
                "",
                "--proxy",
                proxy,
                "-o",
                "/dev/null",
                "-w",
                output,
                target,
            ],
            text=True,
        )
        return float(value)

    server = subprocess.Popen(json.loads(args.server))
    client = subprocess.Popen(json.loads(args.client))
    try:
        time.sleep(1)
        curl("%{speed_download}", args.payload_url)
        latency = [
            curl("%{time_starttransfer}", args.latency_url) * 1000
            for _ in range(30)
        ]
        speeds = [
            curl("%{speed_download}", args.payload_url) * 8
            for _ in range(args.samples)
        ]
        start = time.monotonic()
        jobs = [
            subprocess.Popen(
                [
                    "curl",
                    "-fsS",
                    "--noproxy",
                    "",
                    "--proxy",
                    proxy,
                    "-o",
                    "/dev/null",
                    args.payload_url,
                ]
            )
            for _ in range(args.flows)
        ]
        if any(job.wait() != 0 for job in jobs):
            raise RuntimeError("concurrent curl failed")
        elapsed = time.monotonic() - start
        print(
            json.dumps(
                {
                    "name": args.name,
                    "latency_p50_ms": statistics.median(latency),
                    "latency_p95_ms": sorted(latency)[28],
                    "tcp_single_median_bps": statistics.median(speeds),
                    "tcp_single_min_bps": min(speeds),
                    "tcp_single_max_bps": max(speeds),
                    "tcp_concurrent_bps": (
                        args.flows * args.payload_bytes * 8 / elapsed
                    ),
                    "client_rss_bytes": rss(client.pid, "VmRSS"),
                    "server_rss_bytes": rss(server.pid, "VmRSS"),
                    "client_hwm_bytes": rss(client.pid, "VmHWM"),
                    "server_hwm_bytes": rss(server.pid, "VmHWM"),
                },
                sort_keys=True,
            )
        )
    finally:
        for process in (client, server):
            process.terminate()
        for process in (client, server):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    main()
