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
    if rows != 30 or disk_assets != assets:
        fail(f"expected 30 exact assets, found {rows} rows and {len(disk_assets)} files")
    print(f"verified {rows} release artifacts")


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


if __name__ == "__main__":
    main()
