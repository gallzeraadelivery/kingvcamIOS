"""Build an unpublished diagnostic package with only the injection filter narrowed.

The authenticated 3.0.44-14 runtime, daemon, install scripts, and API data
remain byte-identical. This candidate must be tested on the owner's iPhone
before publication because removing framework-wide injection may affect camera
replacement in third-party apps.
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

SOURCE = ROOT / "dist/com.apple.avservicesd.rootless_3.0.44-14_kingvcam-minimal_iphoneos-arm64.deb"
SOURCE_SHA256 = "5ff308d049f9de3eed34f4f46b6ef2fd29c756db55a77471cdec839ec4640d88"
VERSION = "3.0.44-16"
OUTPUT = ROOT / f"dist/com.apple.avservicesd.rootless_{VERSION}_kingvcam-filter-test_iphoneos-arm64.deb"
FILTER_PATH = "var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.plist"
UNSAFE_BUNDLES = {"com.apple.UIKit", "com.apple.WebKit.GPU"}


def narrowed_filter(original: bytes) -> bytes:
    payload = plistlib.loads(original)
    filters = payload.get("Filter")
    if not isinstance(filters, dict) or set(filters) != {"Bundles", "Executables"}:
        raise ValueError("Unexpected original filter structure")
    bundles = filters["Bundles"]
    executables = filters["Executables"]
    if set(bundles) != {
        "com.apple.mediaserverd", "com.apple.springboard", "com.apple.lskdd",
        *UNSAFE_BUNDLES,
    } or set(executables) != {"mediaserverd", "lskdd", "assetsd"}:
        raise ValueError("Unexpected original injection targets")
    filters["Bundles"] = [name for name in bundles if name not in UNSAFE_BUNDLES]
    return plistlib.dumps(payload, fmt=plistlib.FMT_BINARY, sort_keys=False)


def versioned_control(original: bytes) -> bytes:
    old = b"Version: 3.0.44-14\n"
    if original.count(old) != 1:
        raise ValueError("Unexpected source package version")
    return original.replace(old, f"Version: {VERSION}\n".encode())


def main() -> None:
    if OUTPUT.exists():
        raise FileExistsError(OUTPUT)
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("Source is not the owner-confirmed 3.0.44-14 build")
    package = helpers.read_ar(source)
    data_files = helpers.contents(package["data.tar.lzma"])
    control_files = helpers.contents(package["control.tar.gz"])
    filtered = narrowed_filter(data_files[FILTER_PATH])
    data = lzma.compress(
        helpers.rewrite_tar(package["data.tar.lzma"], {FILTER_PATH: filtered}),
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
