#!/usr/bin/env python3

import hashlib
import sys
import tarfile
import tomllib
from pathlib import Path, PurePosixPath


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: verify-release.py <artifact-directory>")
    root = Path(__file__).resolve().parent.parent
    dist = Path(sys.argv[1]).resolve()
    if not dist.is_dir():
        fail(f"artifact directory does not exist: {dist}")

    assets = set()
    rows = 0
    for manifest_path in sorted((root / "snolpkg").glob("*.toml")):
        manifest = tomllib.loads(manifest_path.read_text())
        for artifact in manifest["artifacts"]:
            name = artifact["url"].rsplit("/", 1)[-1]
            if name in assets:
                fail(f"duplicate artifact name: {name}")
            assets.add(name)
            archive_path = dist / name
            data = archive_path.read_bytes()
            if len(data) != artifact["byte_size"]:
                fail(f"size mismatch: {name}")
            if hashlib.sha256(data).hexdigest() != artifact["sha256"]:
                fail(f"hash mismatch: {name}")
            if len(data) < 10 or int.from_bytes(data[4:8], "little") != 0:
                fail(f"gzip timestamp is not zero: {name}")
            verify_archive(root, archive_path, manifest, artifact["target"])
            rows += 1

    disk_assets = {path.name for path in dist.glob("*.tar.gz")}
    bundle_assets = {name for name in disk_assets if name.startswith("snolc-0.0.1-")}
    if rows != 30 or disk_assets - bundle_assets != assets:
        fail(
            f"expected 30 exact module assets, found {rows} rows and "
            f"{len(disk_assets - bundle_assets)} files"
        )
    for name in sorted(bundle_assets):
        verify_bundle(root, dist / name)
    print(f"verified {rows} module artifacts and {len(bundle_assets)} bundles")


def verify_archive(root: Path, path: Path, manifest: dict, target: str) -> None:
    templates = {
        f"templates/{template['role']}.toml": (root / template["source"]).read_bytes()
        for template in manifest["templates"]
        if target in template["targets"]
    }
    expected = {
        manifest["entry"],
        "LICENSE",
        "THIRD_PARTY_NOTICES.txt",
        *templates,
    }
    seen = set()
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = member.name
            pure = PurePosixPath(name)
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or name in seen
                or name not in expected
                or not member.isfile()
            ):
                fail(f"invalid archive entry {name}: {path.name}")
            seen.add(name)
            mode = 0o755 if name == manifest["entry"] else 0o644
            if member.uid != 0 or member.gid != 0 or member.mtime != 0 or member.mode != mode:
                fail(f"non-deterministic metadata for {name}: {path.name}")
            content = archive.extractfile(member)
            if content is None:
                fail(f"missing archive content for {name}: {path.name}")
            data = content.read()
            if name in templates and data != templates[name]:
                fail(f"template mismatch for {name}: {path.name}")
            if name in {"LICENSE", "THIRD_PARTY_NOTICES.txt"} and not data:
                fail(f"empty notice file {name}: {path.name}")
    if seen != expected:
        fail(f"archive entries differ: {path.name}")


def verify_bundle(root: Path, path: Path) -> None:
    data = path.read_bytes()
    if len(data) < 10 or int.from_bytes(data[4:8], "little") != 0:
        fail(f"gzip timestamp is not zero: {path.name}")
    target = path.name.removeprefix("snolc-0.0.1-").removesuffix(".tar.gz")
    if "windows" in target:
        binary_suffix = ".exe"
        library_prefix = ""
        library_suffix = ".dll"
    elif "apple" in target:
        binary_suffix = ""
        library_prefix = "lib"
        library_suffix = ".dylib"
    else:
        binary_suffix = ""
        library_prefix = "lib"
        library_suffix = ".so"
    modules = {
        f"lib/{library_prefix}snolc_{name}{library_suffix}"
        for name in (
            "adapter_direct",
            "adapter_http_connect",
            "adapter_socks5",
            "adapter_tun",
            "carrier_ssh",
            "carrier_tcp",
            "policy_dummy",
            "policy_local",
            "protection_dummy",
            "protection_noise",
        )
    }
    required = {
        "LICENSE",
        "THIRD_PARTY_NOTICES.txt",
        "include/snolc.h",
        f"bin/snolc{binary_suffix}",
        f"bin/snolpkg{binary_suffix}",
        *modules,
        *(template.relative_to(root).as_posix() for template in (root / "config/templates").rglob("*.toml")),
    }
    seen = set()
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = member.name
            pure = PurePosixPath(name)
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or name in seen
                or not member.isfile()
                or member.uid != 0
                or member.gid != 0
                or member.mtime != 0
            ):
                fail(f"invalid bundle entry {name}: {path.name}")
            mode = 0o755 if name.startswith(("bin/", "lib/")) else 0o644
            if member.mode != mode:
                fail(f"invalid bundle mode for {name}: {path.name}")
            seen.add(name)
    optional = {f"bin/snolcNG{binary_suffix}"}
    if seen - optional != required:
        fail(f"incomplete release bundle: {path.name}")


if __name__ == "__main__":
    main()
