#!/usr/bin/env python3

import argparse
import hashlib
import json
import subprocess
import tomllib
from pathlib import Path


GENERATED = {
    "release-inventory.json",
    "release-inventory.json.sig",
    "SHA256SUMS",
    "SHA256SUMS.sig",
    "release-ed25519.pem",
}

TARGETS = {
    "i586-unknown-linux-gnu": {"minimum_os": "Linux 4.19", "minimum_libc": "glibc 2.28", "minimum_isa": "i586+sse2"},
    "i686-unknown-linux-gnu": {"minimum_os": "Linux 4.19", "minimum_libc": "glibc 2.28", "minimum_isa": "i686"},
    "x86_64-unknown-linux-gnu": {"minimum_os": "Linux 4.19", "minimum_libc": "glibc 2.28", "minimum_isa": "x86-64"},
    "aarch64-unknown-linux-gnu": {"minimum_os": "Linux 4.19", "minimum_libc": "glibc 2.28", "minimum_isa": "armv8-a"},
    "armv7-unknown-linux-gnueabihf": {"minimum_os": "Linux 4.19", "minimum_libc": "glibc 2.28", "minimum_isa": "armv7-a"},
    "riscv64gc-unknown-linux-gnu": {"minimum_os": "Linux 4.19", "minimum_libc": "glibc 2.28", "minimum_isa": "riscv64gc"},
    "aarch64-linux-android": {"minimum_os": "Android API 24", "minimum_isa": "armv8-a"},
    "armv7-linux-androideabi": {"minimum_os": "Android API 24", "minimum_isa": "armv7-a"},
    "x86_64-unknown-freebsd": {"minimum_os": "FreeBSD 14", "minimum_isa": "x86-64"},
    "aarch64-unknown-freebsd": {"minimum_os": "FreeBSD 14", "minimum_isa": "armv8-a"},
    "x86_64-unknown-netbsd": {"minimum_os": "NetBSD 10", "minimum_isa": "x86-64"},
    "x86_64-apple-darwin": {"minimum_os": "macOS 11", "minimum_isa": "x86-64"},
    "aarch64-apple-darwin": {"minimum_os": "macOS 11", "minimum_isa": "armv8-a"},
    "x86_64-pc-windows-msvc": {"minimum_os": "unverified", "minimum_isa": "x86-64"},
}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    return parser.parse_args()


def command(args: list[str], cwd: Path) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    assets = args.assets.resolve()
    if not source.is_dir() or not assets.is_dir() or not args.signing_key.is_file():
        raise SystemExit("source, assets, or signing key is missing")
    if command(["git", "status", "--porcelain"], source):
        raise SystemExit("source checkout is dirty")
    for name in GENERATED:
        path = assets / name
        if path.exists():
            path.unlink()

    public_key = assets / "release-ed25519.pem"
    subprocess.run(
        ["openssl", "pkey", "-in", str(args.signing_key), "-pubout", "-out", str(public_key)],
        check=True,
    )
    verify_public_key(source, public_key)

    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=source
        )
    )
    lock = tomllib.loads((source / "Cargo.lock").read_text())
    licenses = {
        (package["name"], package["version"], package.get("source")): package.get("license")
        for package in metadata["packages"]
    }
    dependencies = []
    for package in sorted(
        lock["package"], key=lambda value: (value["name"], value["version"], value.get("source", ""))
    ):
        source_name = package.get("source")
        dependencies.append(
            {
                "name": package["name"],
                "version": package["version"],
                "source": source_name,
                "checksum": package.get("checksum"),
                "license": licenses.get((package["name"], package["version"], source_name)),
            }
        )

    module_assets, revisions = module_metadata(source)
    build_source_commit = revisions.pop() if len(revisions) == 1 else sorted(revisions)
    files = []
    for path in sorted(value for value in assets.iterdir() if value.is_file()):
        target = module_assets.get(path.name)
        if target is None and path.name.startswith("snolc-0.0.1-") and path.name.endswith(".tar.gz"):
            target_name = path.name.removeprefix("snolc-0.0.1-").removesuffix(".tar.gz")
            target = {"target": target_name, **TARGETS.get(target_name, {})}
        elif target is None and path.suffix == ".apk":
            target = {
                "target": "aarch64-linux-android+armv7-linux-androideabi",
                "minimum_os": "Android API 24",
                "minimum_isa": "armv8-a+armv7-a",
            }
        files.append(
            {
                "name": path.name,
                "byte_size": path.stat().st_size,
                "sha256": sha256(path),
                **(target or {}),
            }
        )

    workspace = tomllib.loads((source / "Cargo.toml").read_text())
    inventory = {
        "package_version": workspace["workspace"]["package"]["version"],
        "wire_version": 1,
        "publication_commit": command(["git", "rev-parse", "HEAD"], source),
        "build_source_commit": build_source_commit,
        "dirty": False,
        "module_source_commit": build_source_commit,
        "rustc": command(["rustc", "+1.98.1", "--version", "--verbose"], source),
        "cargo": command(["cargo", "+1.98.1", "--version", "--verbose"], source),
        "cargo_lock_sha256": sha256(source / "Cargo.lock"),
        "assets": files,
        "dependencies": dependencies,
    }
    inventory_path = assets / "release-inventory.json"
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")

    checksummed = sorted(
        path for path in assets.iterdir() if path.is_file() and path.name not in {"SHA256SUMS", "SHA256SUMS.sig"}
    )
    checksums = assets / "SHA256SUMS"
    checksums.write_text("".join(f"{sha256(path)}  {path.name}\n" for path in checksummed))
    sign(args.signing_key, inventory_path)
    sign(args.signing_key, checksums)
    subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public_key), "-in", str(inventory_path), "-sigfile", f"{inventory_path}.sig"],
        check=True,
    )
    subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public_key), "-in", str(checksums), "-sigfile", f"{checksums}.sig"],
        check=True,
    )
    print(f"inventoried {len(files)} assets and {len(dependencies)} dependencies")


def module_metadata(source: Path) -> tuple[dict[str, dict], set[str]]:
    assets = {}
    revisions = set()
    for path in sorted((source / "snolpkg").glob("*.toml")):
        manifest = tomllib.loads(path.read_text())
        revisions.add(manifest["source"]["revision"])
        for artifact in manifest["artifacts"]:
            target = artifact["target"]
            values = {"target": target, **TARGETS.get(target, {})}
            assets[artifact["url"].rsplit("/", 1)[-1]] = values
    return assets, revisions


def verify_public_key(source: Path, public_key: Path) -> None:
    der = subprocess.check_output(
        ["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"]
    )
    configured = tomllib.loads((source / "config/packages/sources.toml").read_text())[
        "sources"
    ][0]["public_key"]
    if der[-32:].hex() != configured:
        raise SystemExit("release key does not match the configured trust root")


def sign(key: Path, path: Path) -> None:
    subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(path), "-out", f"{path}.sig"],
        check=True,
    )


if __name__ == "__main__":
    main()
