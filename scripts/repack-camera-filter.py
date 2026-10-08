"""Build an unpublished 3.0.44-17 test that targets Camera explicitly.

Only the injection filter and Debian version differ from the owner-confirmed
3.0.44-14 package. Do not publish before an on-device boot and camera test.
"""
from __future__ import annotations

import gzip
import hashlib
import lzma
import plistlib

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "safe_filter", Path(__file__).with_name("repack-safe-filter.py")
)
safe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(safe)
helpers = safe.helpers

VERSION = "3.0.44-17"
OUTPUT = safe.ROOT / f"dist/com.apple.avservicesd.rootless_{VERSION}_kingvcam-camera-test_iphoneos-arm64.deb"
CAMERA_BUNDLE = "com.apple.camera"


def camera_filter(original: bytes) -> bytes:
    payload = plistlib.loads(safe.narrowed_filter(original))
    payload["Filter"]["Bundles"].append(CAMERA_BUNDLE)
    return plistlib.dumps(payload, fmt=plistlib.FMT_BINARY, sort_keys=False)


def versioned_control(original: bytes) -> bytes:
    old = b"Version: 3.0.44-14\n"
    if original.count(old) != 1:
        raise ValueError("Unexpected source package version")
    return original.replace(old, f"Version: {VERSION}\n".encode())


def main() -> None:
    if OUTPUT.exists():
        raise FileExistsError(OUTPUT)
    source = safe.SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != safe.SOURCE_SHA256:
        raise ValueError("Source is not the owner-confirmed 3.0.44-14 build")
    package = helpers.read_ar(source)
    data_files = helpers.contents(package["data.tar.lzma"])
    control_files = helpers.contents(package["control.tar.gz"])
    data = lzma.compress(
        helpers.rewrite_tar(package["data.tar.lzma"], {
            safe.FILTER_PATH: camera_filter(data_files[safe.FILTER_PATH]),
        }),
        format=lzma.FORMAT_ALONE,
        preset=9,
    )
    control = gzip.compress(
        helpers.rewrite_tar(package["control.tar.gz"], {
            "control": versioned_control(control_files["control"]),
        }),
        mtime=0,
    )
    result = (b"!<arch>\n"
              + helpers.helpers.ar_member("debian-binary", package["debian-binary"])
              + helpers.helpers.ar_member("control.tar.gz", control)
              + helpers.helpers.ar_member("data.tar.lzma", data))
    OUTPUT.write_bytes(result)
    print(f"Built unpublished diagnostic package: {OUTPUT}")
    print(f"SHA256 {hashlib.sha256(result).hexdigest()}")


if __name__ == "__main__":
    main()
