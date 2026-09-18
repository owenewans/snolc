#!/usr/bin/env python3

import sys
import tarfile
from pathlib import Path, PurePosixPath


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: verify-release.py <artifact-directory>")
    dist = Path(sys.argv[1]).resolve()
    if not dist.is_dir():
        fail(f"artifact directory does not exist: {dist}")
    assets = sorted(dist.glob("snolc-0.0.2-*.tar.gz"))
    if not assets:
        fail("no snolc 0.0.2 archives found")
    for path in assets:
        verify_bundle(path)
    print(f"verified {len(assets)} binary archives")


def verify_bundle(path: Path) -> None:
    data = path.read_bytes()
    if len(data) < 10 or int.from_bytes(data[4:8], "little") != 0:
        fail(f"gzip timestamp is not zero: {path.name}")
    target = path.name.removeprefix("snolc-0.0.2-").removesuffix(".tar.gz")
    suffix = ".exe" if "windows" in target else ""
    expected = {
        f"bin/snolc{suffix}",
        "include/snolc.h",
        "LICENSE",
        "THIRD_PARTY_NOTICES.txt",
    }
    seen = set()
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = member.name
            pure = PurePosixPath(name)
            mode = 0o755 if name.startswith("bin/") else 0o644
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or name in seen
                or name not in expected
                or not member.isfile()
                or member.uid != 0
                or member.gid != 0
                or member.mtime != 0
                or member.mode != mode
            ):
                fail(f"invalid archive entry {name}: {path.name}")
            seen.add(name)
    if seen != expected:
        fail(f"incomplete binary archive: {path.name}")


if __name__ == "__main__":
    main()
