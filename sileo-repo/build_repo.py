"""Build the flat KingVCam APT repository from the verified iOS release.

Run on a Linux host with dpkg-deb and apt-ftparchive. This only writes to the
given output directory; it never touches the API or the source .deb.
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import lzma
from pathlib import Path
import shutil
import subprocess


EXPECTED_SHA256 = "e83357e2e642b7ba55bcb37b3fc1a6c00ac82054696fb5903a0e725ed0c744a4"
EXPECTED_PACKAGE = "com.apple.avservicesd.rootless"
EXPECTED_VERSION = "3.0.44-20"
EXPECTED_ARCH = "iphoneos-arm64"


def command(*args: str, cwd: Path | None = None) -> bytes:
    return subprocess.check_output(args, cwd=cwd)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("deb", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    source = args.deb.resolve()
    root = args.output.resolve()
    actual = hashlib.sha256(source.read_bytes()).hexdigest()
    if actual != EXPECTED_SHA256:
        raise SystemExit(f"Unexpected package hash: {actual}")
    for field, expected in (("Package", EXPECTED_PACKAGE),
                            ("Version", EXPECTED_VERSION),
                            ("Architecture", EXPECTED_ARCH)):
        actual_field = command("dpkg-deb", "-f", str(source), field).decode().strip()
        if actual_field != expected:
            raise SystemExit(f"Unexpected {field}: {actual_field}")

    pool = root / "pool"
    pool.mkdir(parents=True, exist_ok=True)
    target = pool / source.name
    if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise SystemExit(f"Refusing to overwrite a different package: {target}")
    shutil.copy2(source, target)

    packages = command("apt-ftparchive", "packages", "pool", cwd=root)
    if packages.count(b"Package: ") != 1 or b"Filename: pool/" not in packages:
        raise SystemExit("Repository index does not describe exactly one package")
    (root / "Packages").write_bytes(packages)
    with (root / "Packages.gz").open("wb") as output:
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as packed:
            packed.write(packages)
    (root / "Packages.bz2").write_bytes(bz2.compress(packages))
    (root / "Packages.xz").write_bytes(lzma.compress(packages, format=lzma.FORMAT_XZ))

    options = {
        "Origin": "KingVCam",
        "Label": "KingVCam",
        "Suite": "stable",
        "Codename": "kingvcam",
        "Architectures": EXPECTED_ARCH,
        "Components": "main",
        "Description": "KingVCam official rootless iOS packages",
    }
    cmd = ["apt-ftparchive"]
    for key, value in options.items():
        cmd.extend(["-o", f"APT::FTPArchive::Release::{key}={value}"])
    cmd.extend(["release", "."])
    (root / "Release").unlink(missing_ok=True)
    (root / "Release").write_bytes(command(*cmd, cwd=root))
    print(f"Package: {target}")
    print(f"SHA256: {EXPECTED_SHA256}")
    print(f"Index: {root / 'Packages.gz'}")


if __name__ == "__main__":
    main()
