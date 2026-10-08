"""Build an unpublished Safari camera test with explicit process targets only."""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import lzma
import plistlib
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "camera_filter", Path(__file__).with_name("repack-camera-filter.py")
)
camera = importlib.util.module_from_spec(spec)
spec.loader.exec_module(camera)
safe = camera.safe
helpers = camera.helpers

VERSION = "3.0.44-18"
OUTPUT = safe.ROOT / f"dist/com.apple.avservicesd.rootless_{VERSION}_kingvcam-safari-test_iphoneos-arm64.deb"
BROWSER_BUNDLES = ("com.apple.mobilesafari", "com.apple.WebKit.WebContent")


def browser_filter(original: bytes) -> bytes:
    payload = plistlib.loads(camera.camera_filter(original))
    payload["Filter"]["Bundles"].extend(BROWSER_BUNDLES)
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
            safe.FILTER_PATH: browser_filter(data_files[safe.FILTER_PATH]),
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
