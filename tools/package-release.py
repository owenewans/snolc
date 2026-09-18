#!/usr/bin/env python3

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--signing-key", type=Path)
    parser.add_argument("--output", action="append", default=[], metavar="TARGET=DIR")
    parser.add_argument("--bundle-output", action="append", default=[], metavar="TARGET=DIR")
    parser.add_argument("--notices-output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = arguments()
    root = Path(__file__).resolve().parent.parent
    source = args.source.resolve()
    outputs = parse_outputs(args.output)
    bundle_outputs = parse_outputs(args.bundle_output)
    dist = args.dist.resolve() if args.dist is not None else None
    if not source.is_dir():
        raise SystemExit("source checkout is missing")
    if not outputs and not bundle_outputs and args.notices_output is None:
        raise SystemExit("at least one output is required")
    if (outputs or bundle_outputs) and dist is None:
        raise SystemExit("dist directory is required for archives")
    if outputs and (args.signing_key is None or not args.signing_key.is_file()):
        raise SystemExit("signing key is missing")
    if outputs and tomllib is None:
        raise SystemExit("Python 3.11 or tomllib is required for module publication")
    source_revision = None
    if outputs:
        git = ["git", "-c", f"safe.directory={source}"]
        if subprocess.check_output([*git, "status", "--porcelain"], cwd=source, text=True).strip():
            raise SystemExit("source checkout must be clean")
        source_revision = subprocess.check_output(
            [*git, "rev-parse", "HEAD"], cwd=source, text=True
        ).strip()
    if dist is not None:
        dist.mkdir(parents=True, exist_ok=True)
        if any(dist.iterdir()):
            raise SystemExit("dist directory must be empty")

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

    manifest_paths = sorted((root / "snolpkg").glob("*.toml")) if outputs else []
    for manifest_path in manifest_paths:
        update_source_revision(manifest_path, source_revision)
        manifest = tomllib.loads(manifest_path.read_text())
        notices = dependency_notices([manifest["build"]["package"]], local, packages, nodes)
        updates = {}
        for artifact in manifest["artifacts"]:
            target = artifact["target"]
            if target not in outputs:
                raise SystemExit(f"missing output directory for {target}")
            library = outputs[target] / artifact["build_output"]
            if not library.is_file():
                raise SystemExit(f"missing built library: {library}")
            name = artifact["url"].rsplit("/", 1)[-1]
            archive = dist / name
            templates = {
                template["role"]: source / template["source"]
                for template in manifest["templates"]
                if target in template["targets"]
            }
            write_archive(archive, source, manifest["entry"], library, templates, notices)
            data = archive.read_bytes()
            updates[target] = (len(data), hashlib.sha256(data).hexdigest())
        update_artifacts(manifest_path, updates)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(args.signing_key),
                "-in",
                str(manifest_path),
                "-out",
                f"{manifest_path}.sig",
            ],
            check=True,
        )
    notices = dependency_notices(sorted(local), local, packages, nodes)
    if args.notices_output is not None:
        notices_output = args.notices_output.resolve()
        notices_output.parent.mkdir(parents=True, exist_ok=True)
        notices_output.write_bytes(notices)
    for target, output in sorted(bundle_outputs.items()):
        write_bundle(
            dist / f"snolc-0.0.1-{target}.tar.gz",
            source,
            target,
            output,
            notices,
        )
    artifacts = len(list(dist.glob("*.tar.gz"))) if dist is not None else 0
    print(f"created {artifacts} release artifacts")


def parse_outputs(values: list[str]) -> dict[str, Path]:
    outputs = {}
    for value in values:
        target, separator, directory = value.partition("=")
        if not separator or not target or not directory or target in outputs:
            raise SystemExit(f"invalid --output: {value}")
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
    output = [
        "SNOLC THIRD-PARTY NOTICES",
        "",
        "The archive includes the following Rust dependencies. License texts follow each entry.",
        "",
    ]
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
        unique = sorted({path for path in candidates if path.is_file()})
        for path in unique:
            output.extend(
                [f"file: {path.name}", path.read_text(errors="replace").rstrip(), ""]
            )
    return ("\n".join(output).rstrip() + "\n").encode()


def write_archive(
    path: Path,
    source: Path,
    entry: str,
    library: Path,
    templates: dict[str, Path],
    notices: bytes,
) -> None:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        add_bytes(archive, entry, library.read_bytes(), 0o755)
        add_bytes(archive, "LICENSE", (source / "LICENSE").read_bytes(), 0o644)
        add_bytes(archive, "THIRD_PARTY_NOTICES.txt", notices, 0o644)
        for role, template in sorted(templates.items()):
            add_bytes(archive, f"templates/{role}.toml", template.read_bytes(), 0o644)
    with path.open("wb") as output:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=output, mtime=0, compresslevel=9
        ) as compressed:
            compressed.write(raw.getvalue())


def write_bundle(
    path: Path,
    source: Path,
    target: str,
    output: Path,
    notices: bytes,
) -> None:
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
    files = []
    for name in ("snolc", "snolpkg"):
        artifact = output / f"{name}{binary_suffix}"
        if not artifact.is_file():
            raise SystemExit(f"missing bundle binary: {artifact}")
        files.append((f"bin/{artifact.name}", artifact, 0o755))
    gui = output / f"snolcNG{binary_suffix}"
    if gui.is_file():
        files.append((f"bin/{gui.name}", gui, 0o755))
    modules = (
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
    for module in modules:
        name = f"{library_prefix}snolc_{module}{library_suffix}"
        artifact = output / name
        if not artifact.is_file():
            raise SystemExit(f"missing bundle module: {artifact}")
        files.append((f"lib/{name}", artifact, 0o755))

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, artifact, mode in sorted(files):
            add_bytes(archive, name, artifact.read_bytes(), mode)
        add_bytes(archive, "include/snolc.h", (source / "include/snolc.h").read_bytes(), 0o644)
        add_bytes(archive, "LICENSE", (source / "LICENSE").read_bytes(), 0o644)
        add_bytes(archive, "THIRD_PARTY_NOTICES.txt", notices, 0o644)
        for template in sorted((source / "config/templates").rglob("*.toml")):
            relative = template.relative_to(source)
            add_bytes(archive, relative.as_posix(), template.read_bytes(), 0o644)
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


def update_artifacts(path: Path, updates: dict[str, tuple[int, str]]) -> None:
    output = []
    artifact = False
    target = None
    for line in path.read_text().splitlines():
        if line == "[[artifacts]]":
            artifact = True
            target = None
        elif line.startswith("[["):
            artifact = False
            target = None
        if artifact and line.startswith("target = "):
            target = line.split('"')[1]
        if artifact and target in updates and line.startswith("byte_size = "):
            line = f"byte_size = {updates[target][0]}"
        if artifact and target in updates and line.startswith("sha256 = "):
            line = f'sha256 = "{updates[target][1]}"'
        output.append(line)
    path.write_text("\n".join(output) + "\n")


def update_source_revision(path: Path, revision: str) -> None:
    output = []
    source = False
    updated = False
    for line in path.read_text().splitlines():
        if line == "[source]":
            source = True
        elif line.startswith("["):
            source = False
        if source and line.startswith("revision = "):
            line = f'revision = "{revision}"'
            updated = True
        output.append(line)
    if not updated:
        raise SystemExit(f"source revision is missing: {path}")
    path.write_text("\n".join(output) + "\n")


if __name__ == "__main__":
    main()
