#!/usr/bin/env python3

import argparse
import gzip
import hashlib
import io
import json
import subprocess
import tarfile
import tomllib
from pathlib import Path


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--output", action="append", required=True, metavar="TARGET=DIR")
    return parser.parse_args()


def main() -> None:
    args = arguments()
    root = Path(__file__).resolve().parent.parent
    source = args.source.resolve()
    outputs = parse_outputs(args.output)
    dist = args.dist.resolve()
    if not source.is_dir() or not args.signing_key.is_file():
        raise SystemExit("source checkout or signing key is missing")
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

    for manifest_path in sorted((root / "snolpkg").glob("*.toml")):
        manifest = tomllib.loads(manifest_path.read_text())
        notices = dependency_notices(manifest["build"]["package"], local, packages, nodes)
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
    print(f"created {len(list(dist.glob('*.tar.gz')))} release artifacts")


def parse_outputs(values: list[str]) -> dict[str, Path]:
    outputs = {}
    for value in values:
        target, separator, directory = value.partition("=")
        if not separator or not target or not directory or target in outputs:
            raise SystemExit(f"invalid --output: {value}")
        outputs[target] = Path(directory).resolve()
    return outputs


def dependency_notices(
    crate: str, local: dict, packages: dict, nodes: dict
) -> bytes:
    pending = [local[crate]]
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


if __name__ == "__main__":
    main()
