"""Build an unpublished Dasher-only injection test from the frozen 3.0.44-19.

Only the MobileSubstrate filter and Debian package version may differ.
"""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import lzma
import plistlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "repack_helpers", Path(__file__).with_name("repack-api-only.py")
)
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)

SOURCE = ROOT / "dist/com.apple.avservicesd.rootless_3.0.44-19_iphoneos-arm64.deb"
SOURCE_SHA256 = "3084934c41742af6bf210894f21348000eda0a07186a42609d6a8abf9043cd55"
VERSION = "3.0.44-20"
OUTPUT = ROOT / f"dist/com.apple.avservicesd.rootless_{VERSION}_kingvcam-dasher-test_iphoneos-arm64.deb"
FILTER_PATH = "var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.plist"
DASHER_BUNDLE = "com.doordash.dasher"


def dasher_filter(original: bytes) -> bytes:
    payload = plistlib.loads(original)
    filters = payload.get("Filter")
    if not isinstance(filters, dict) or set(filters) != {"Bundles", "Executables"}:
        raise ValueError("Unexpected injection filter structure")
    expected_bundles = [
        "com.apple.mediaserverd", "com.apple.springboard", "com.apple.camera",
        "com.apple.mobilesafari", "com.apple.WebKit.WebContent", "com.apple.WebKit.GPU",
    ]
    if filters["Bundles"] != expected_bundles or filters["Executables"] != ["mediaserverd", "assetsd"]:
        raise ValueError("Source filter is not the frozen 3.0.44-19 filter")
    filters["Bundles"].append(DASHER_BUNDLE)
    return plistlib.dumps(payload, fmt=plistlib.FMT_BINARY, sort_keys=False)


def versioned_control(original: bytes) -> bytes:
    old = b"Version: 3.0.44-19\n"
    if original.count(old) != 1:
        raise ValueError("Unexpected source package version")
    return original.replace(old, f"Version: {VERSION}\n".encode())


def main() -> None:
    if OUTPUT.exists():
        raise FileExistsError(OUTPUT)
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("Source is not the frozen 3.0.44-19 package")
    package = helpers.read_ar(source)
    data_files = helpers.contents(package["data.tar.lzma"])
    control_files = helpers.contents(package["control.tar.gz"])
    data = lzma.compress(
        helpers.rewrite_tar(package["data.tar.lzma"], {
            FILTER_PATH: dasher_filter(data_files[FILTER_PATH]),
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
