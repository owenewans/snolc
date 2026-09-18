#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--maximum", required=True)
    parser.add_argument("path", type=Path)
    return parser.parse_args()


def version(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def main() -> None:
    args = arguments()
    maximum = version(args.maximum)
    paths = [args.path] if args.path.is_file() else sorted(args.path.rglob("*"))
    checked = 0
    required = set()
    for path in paths:
        if not path.is_file():
            continue
        with path.open("rb") as stream:
            magic = stream.read(4)
        if magic != b"\x7fELF":
            continue
        output = subprocess.check_output(
            ["readelf", "--version-info", str(path)], text=True, errors="replace"
        )
        required.update(re.findall(r"GLIBC_([0-9]+(?:\.[0-9]+)+)", output))
        checked += 1
    if checked == 0 or not required:
        raise SystemExit("no ELF files with glibc symbols found")
    highest = max(required, key=version)
    if version(highest) > maximum:
        raise SystemExit(f"requires GLIBC_{highest}, maximum is GLIBC_{args.maximum}")
    print(f"checked {checked} ELF files; maximum GLIBC_{highest}")


if __name__ == "__main__":
    main()
