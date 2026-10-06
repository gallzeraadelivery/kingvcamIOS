"""Repackage the working 3.0.44 runtime with only its API base redirected.

No executable instruction, UI string, media hook, filter plist or signature
marker is changed. This is a test artifact, not an on-device validation.
"""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import lzma
import plistlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('repack_helpers', Path(__file__).with_name('repack-api-only.py'))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)

VERSION = '3.0.44-14'
OUTPUT = ROOT / f'dist/com.apple.avservicesd.rootless_{VERSION}_kingvcam-minimal_iphoneos-arm64.deb'


def control_file(original: bytes) -> bytes:
    replacements = {
        'Name': 'KingVCam (Rootless)',
        'Version': VERSION,
        'Description': 'KingVCam media services runtime',
        'Author': 'KingVCam',
        'Maintainer': 'KingVCam',
    }
    lines = []
    for line in original.decode().splitlines():
        key = line.partition(':')[0]
        if key in replacements:
            line = f'{key}: {replacements[key]}'
        elif key == 'Depends':
            line = line.replace('Depends: ', 'Depends: ldid, ', 1)
        lines.append(line)
    return ('\n'.join(lines) + '\n').encode()


def patch_site(blob: bytes, expected_count: int) -> bytes:
    key = helpers.KEY
    def encode(value: str) -> bytes:
        return bytes(char ^ key[index % len(key)] for index, char in enumerate(value.encode()))
    old = encode('https://www.lordvcam.com')
    new = encode('https://www.kingvcam.com')
    if len(old) != len(new) or blob.count(old) != expected_count:
        raise ValueError('Unexpected original site URL layout')
    return blob.replace(old, new)


def main() -> None:
    if OUTPUT.exists():
        raise FileExistsError(OUTPUT)
    source = helpers.SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != helpers.SOURCE_SHA256:
        raise ValueError('Source differs from the owner-verified working package')
    package = helpers.read_ar(source)
    original_data = helpers.contents(package['data.tar.lzma'])
    original_control = helpers.contents(package['control.tar.gz'])
    changed = {}
    for path in (helpers.DYLIB, helpers.DAEMON):
        before = original_data[path]
        after = patch_site(helpers.patch_api(before), 6 if path == helpers.DYLIB else 2)
        if helpers.executable_sections(before) != helpers.executable_sections(after):
            raise ValueError(f'Executable code changed in {path}')
        changed[path] = after
    entitlements = plistlib.dumps(
        helpers.helpers.original_daemon_entitlements(original_data[helpers.DAEMON]),
        sort_keys=False,
    )
    data = lzma.compress(
        helpers.rewrite_tar(package['data.tar.lzma'], changed, {helpers.ENTITLEMENTS: entitlements}),
        format=lzma.FORMAT_ALONE,
        preset=9,
    )
    postinst = original_control['postinst']
    if not postinst.startswith(b'#!/bin/bash\n'):
        raise ValueError('Unexpected original postinst')
    control = gzip.compress(
        helpers.rewrite_tar(package['control.tar.gz'], {
            'control': control_file(original_control['control']),
            'postinst': helpers.signing_prefix() + postinst.split(b'\n', 1)[1],
        }),
        mtime=0,
    )
    result = (b'!<arch>\n'
              + helpers.helpers.ar_member('debian-binary', package['debian-binary'])
              + helpers.helpers.ar_member('control.tar.gz', control)
              + helpers.helpers.ar_member('data.tar.lzma', data))
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_bytes(result)
    print(f'Built {OUTPUT}')
    print(f'SHA256 {hashlib.sha256(result).hexdigest()}')
    print('Code and engine unchanged; physical iPhone behavior not verified')


if __name__ == '__main__':
    main()
