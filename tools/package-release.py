#!/usr/bin/env python3

from __future__ import annotations

import argparse
import gzip
import io
import json
import subprocess
import tarfile
from pathlib import Path


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--bundle-output", action="append", default=[], metavar="TARGET=DIR")
    parser.add_argument("--notices-output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    outputs = parse_outputs(args.bundle_output)
    if not source.is_dir():
        raise SystemExit("source checkout is missing")
    if not outputs and args.notices_output is None:
        raise SystemExit("at least one output is required")
    if outputs and args.dist is None:
        raise SystemExit("dist directory is required")

    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=source
        )
    )
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    local = {
        package["name"]: package["id"]
        for package in metadata["packages"]
        if package["source"] is None
    }
    version = packages[local["snolc-cli"]]["version"]
    notices = dependency_notices(["snolc-cli"], local, packages, nodes)

    if args.notices_output is not None:
        path = args.notices_output.resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(notices)

    if outputs:
        dist = args.dist.resolve()
        dist.mkdir(parents=True, exist_ok=True)
        if any(dist.iterdir()):
            raise SystemExit("dist directory must be empty")
        for target, output in sorted(outputs.items()):
            write_bundle(
                dist / f"snolc-{version}-{target}.tar.gz",
                source,
                target,
                output,
                notices,
            )
        print(f"created {len(outputs)} release artifacts")


def parse_outputs(values: list[str]) -> dict[str, Path]:
    outputs = {}
    for value in values:
        target, separator, directory = value.partition("=")
        if not separator or not target or not directory or target in outputs:
            raise SystemExit(f"invalid --bundle-output: {value}")
        outputs[target] = Path(directory).resolve()
    return outputs


def dependency_notices(
    crates: list[str], local: dict, packages: dict, nodes: dict
) -> bytes:
    pending = [local[crate] for crate in crates]
    seen = set()
    while pending:
        package = pending.pop()
        if package in seen:
            continue
        seen.add(package)
        pending.extend(dependency["pkg"] for dependency in nodes[package]["deps"])
    dependencies = sorted(
        (packages[package] for package in seen if packages[package]["source"] is not None),
        key=lambda package: (package["name"], package["version"]),
    )
    output = ["snolc third-party notices", ""]
    for package in dependencies:
        directory = Path(package["manifest_path"]).parent
        output.extend(
            [
                f"{package['name']} {package['version']}",
                f"license: {package.get('license') or 'see included license file'}",
                f"source: {package.get('source') or ''}",
                "",
            ]
        )
        candidates = []
        if package.get("license_file"):
            candidates.append(directory / package["license_file"])
        for pattern in ("LICENSE*", "COPYING*", "NOTICE*"):
            candidates.extend(directory.glob(pattern))
        for path in sorted({path for path in candidates if path.is_file()}):
            output.extend([f"file: {path.name}", path.read_text(errors="replace").rstrip(), ""])
    return ("\n".join(output).rstrip() + "\n").encode()


def write_bundle(
    path: Path, source: Path, target: str, output: Path, notices: bytes
) -> None:
    suffix = ".exe" if "windows" in target else ""
    binary = output / f"snolc{suffix}"
    if not binary.is_file():
        raise SystemExit(f"missing binary: {binary}")
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        add_bytes(archive, f"bin/{binary.name}", binary.read_bytes(), 0o755)
        add_bytes(archive, "include/snolc.h", (source / "include/snolc.h").read_bytes(), 0o644)
        add_bytes(archive, "LICENSE", (source / "LICENSE").read_bytes(), 0o644)
        add_bytes(archive, "THIRD_PARTY_NOTICES.txt", notices, 0o644)
    with path.open("wb") as output_file:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=output_file, mtime=0, compresslevel=9
        ) as compressed:
            compressed.write(raw.getvalue())


def add_bytes(archive: tarfile.TarFile, name: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


if __name__ == "__main__":
    main()
