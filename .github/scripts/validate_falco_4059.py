#!/usr/bin/env python3
"""Offline integration check for Falco issue #4059 using the real apt-ftparchive.

Reads public Falco source; never invokes the publisher, AWS, signing, or networking.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("phase", choices=("before", "after"))
    args = parser.parse_args()

    script = args.source.read_text()
    before = 'APT::FTPArchive::Release::Architectures="$(join_arr , "${architectures[@]}")"'
    after = 'APT::FTPArchive::Release::Architectures="$(join_arr " " "${architectures[@]}")"'
    if before not in script:
        raise AssertionError("Upstream publisher changed; review the patch before reusing test")
    if args.phase == "after":
        script = script.replace(before, after, 1)

    helper = re.search(r"(?ms)^join_arr\(\) \{\n.*?^\}", script)
    if helper is None:
        raise AssertionError("No public join_arr function in upstream")

    sep = '" "' if args.phase == "after" else ","
    for archs in [("amd64",), ("amd64", "arm64"), ("amd64", "arm64", "riscv64")]:
        expected = " ".join(archs) if args.phase == "after" else ",".join(archs)
        shell = helper.group(0) + "\narchitectures=(" + " ".join(archs) + ")\n" + (
            f'join_arr {sep} "${{architectures[@]}}"\n'
        )
        joined = subprocess.check_output(["bash", "-c", shell], text=True).strip()
        assert joined == expected, (archs, joined, expected)
        with tempfile.TemporaryDirectory() as td:
            release_dir = Path(td) / "dists" / "stable"
            packages_dir = release_dir / "main" / "binary-amd64"
            packages_dir.mkdir(parents=True)
            (packages_dir / "Packages").write_text("", encoding="utf-8")
            result = subprocess.run(
                [
                    "apt-ftparchive", "release",
                    "-o", "APT::FTPArchive::Release::Origin=Falco",
                    "-o", f"APT::FTPArchive::Release::Architectures={joined}",
                    str(release_dir),
                ],
                check=True, capture_output=True, text=True,
            )
            line = next(
                (line for line in result.stdout.splitlines()
                 if line.startswith("Architectures:")), None
            )
            assert line == f"Architectures: {expected}", (archs, line, expected)
            if args.phase == "after":
                assert "," not in line, line
            print(f"{args.phase}: {line}")
    print(f"PASS: real apt-ftparchive generated expected {args.phase} metadata")


if __name__ == "__main__":
    main()
