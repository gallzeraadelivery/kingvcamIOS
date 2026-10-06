"""Repack the verified original with API/branding data only; preserve its code."""
from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import io
import lzma
import plistlib
import re
import struct
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'incoming/com.apple.avservicesd.rootless_3.0.44_iphoneos-arm64.deb'
SOURCE_SHA256 = '7ffab80997c84e168e9a3448f559c6bd6b6805c837d14242de72b7e070c22af7'
VERSION = '3.0.44-12'
OUTPUT = ROOT / f'dist/com.apple.avservicesd.rootless_{VERSION}_kingvcam_iphoneos-arm64.deb'
DYLIB = 'var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.dylib'
DAEMON = 'var/jb/usr/libexec/avfsupportd'
ENTITLEMENTS = 'var/jb/usr/share/kingvcam/avfsupportd.entitlements'
KEY = b'LordVCAM_2026_k3'
OLD_API = b'https://www.lordvcam.com/v1'
NEW_API = b'https://www.kingvcam.com/v1'

spec = importlib.util.spec_from_file_location('authenticated_repacker', Path(__file__).with_name('repack-authenticated-v3.py'))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


def read_ar(data: bytes) -> dict[str, bytes]:
    if not data.startswith(b'!<arch>\n'):
        raise ValueError('Invalid Debian archive')
    result = {}
    offset = 8
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[-2:] != b'`\n':
            raise ValueError('Invalid ar header')
        size = int(header[48:58])
        name = header[:16].decode('ascii').strip().rstrip('/')
        result[name] = data[offset + 60:offset + 60 + size]
        offset += 60 + size + size % 2
    return result


def contents(payload: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:*') as archive:
        return {m.name.removeprefix('./'): archive.extractfile(m).read()
                for m in archive if m.isfile()}


def rewrite_tar(payload: bytes, changes: dict[str, bytes], additions: dict[str, bytes] | None = None) -> bytes:
    """Keep original modes, owner/group, links, names and every unedited payload."""
    buffer = io.BytesIO()
    seen = set()
    existing = set()
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:*') as original, tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as output:
        for member in original:
            normalized = member.name.removeprefix('./')
            existing.add(normalized.rstrip('/'))
            info = copy.copy(member)
            if member.isfile():
                data = original.extractfile(member).read()
                if normalized in changes:
                    data = changes[normalized]
                    seen.add(normalized)
                info.size = len(data)
                output.addfile(info, io.BytesIO(data))
            else:
                output.addfile(info)
        if seen != changes.keys():
            raise ValueError(f'Missing original members: {changes.keys() - seen}')
        for name, data in (additions or {}).items():
            # dpkg requires explicit directory entries before new child files.
            # Merely appending an entitlements file failed on the device at
            # /var/jb/usr/share/kingvcam because that directory did not exist.
            for parent in reversed(PurePosixPath(name).parents):
                directory = parent.as_posix()
                if directory == '.' or directory in existing:
                    continue
                info = tarfile.TarInfo(directory)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.uname = info.gname = 'root'
                output.addfile(info)
                existing.add(directory)
            info = tarfile.TarInfo(name)
            info.mode = 0o644
            info.uname = info.gname = 'root'
            info.size = len(data)
            output.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def patch_api(blob: bytes) -> bytes:
    encode = lambda value: bytes(x ^ KEY[i % len(KEY)] for i, x in enumerate(value))
    old, new = encode(OLD_API), encode(NEW_API)
    if len(old) != len(new) or blob.count(old) != 4:
        raise ValueError('Expected exactly four original API bases in each universal binary')
    patched = blob.replace(old, new)
    if len(patched) != len(blob) or old in patched or patched.count(new) != 4:
        raise ValueError('API replacement failed')
    return patched


def executable_sections(blob: bytes) -> dict[tuple[int, str, str], bytes]:
    """Read executable sections directly, without rewriting Mach-O metadata."""
    sections = {}
    count = struct.unpack_from('>I', blob, 4)[0]
    for index in range(count):
        _, _, offset, size, _ = struct.unpack_from('>IIIII', blob, 8 + index * 20)
        thin = blob[offset:offset + size]
        cursor = 32
        for _ in range(struct.unpack_from('<I', thin, 16)[0]):
            command, length = struct.unpack_from('<II', thin, cursor)
            if command == 0x19:  # LC_SEGMENT_64
                nsects = struct.unpack_from('<I', thin, cursor + 64)[0]
                for sec in range(nsects):
                    entry = cursor + 72 + sec * 80
                    name = thin[entry:entry + 16].split(b'\0')[0].decode()
                    segment = thin[entry + 16:entry + 32].split(b'\0')[0].decode()
                    size = struct.unpack_from('<Q', thin, entry + 40)[0]
                    start = struct.unpack_from('<I', thin, entry + 48)[0]
                    flags = struct.unpack_from('<I', thin, entry + 64)[0]
                    if flags & (0x80000000 | 0x400):  # instructions
                        sections[index, segment, name] = thin[start:start + size]
            cursor += length
    if not sections:
        raise ValueError('No executable Mach-O sections found')
    return sections


def patch_runtime(blob: bytes, *, is_tweak: bool = False) -> bytes:
    patched = patch_api(blob)
    # The old service's integrity_mismatch response disables the entire tweak
    # after an otherwise successful login. The KingVCam server owns license
    # validation now; skip only that legacy response field. The valid-login
    # path, frame verifier, media hooks and volume shortcut remain untouched.
    legacy_checks = (
        (bytes.fromhex('c8024039680200375a0200b4'), bytes.fromhex('14000014')),  # arm64: 0x104850 -> 0x1048a0
        (bytes.fromhex('c802403908030037fa0200b4'), bytes.fromhex('19000014')),  # arm64e: 0x10a4e8 -> 0x10a54c
    )
    matches = 0
    for legacy_check, branch in legacy_checks:
        count = patched.count(legacy_check)
        if count > 1:
            raise ValueError('Unexpected duplicate integrity check')
        if count == 1:
            patched = patched.replace(legacy_check, branch + legacy_check[4:])
            matches += 1
    if matches != (2 if is_tweak else 1):
        raise ValueError('Unexpected integrity-check locations')
    # Same-length text edits. Leave protocol/decoder keys unchanged and keep
    # original selectors/colors. No systemBlueColor -> systemMintColor patch.
    for encoding in ('ascii', 'utf-16le'):
        for old, new in (('LordVCAM', 'KingVCam'), ('LordVCam', 'KingVCam'),
                         ('lordvcam', 'kingvcam'), ('LORDVCAM', 'KINGVCAM')):
            a, b = old.encode(encoding), new.encode(encoding)
            if len(a) != len(b):
                raise ValueError('Branding changes must preserve binary size')
            patched = patched.replace(a, b)
    # The original update dialog still instructed users to add its Sileo repo.
    # Replace all three visible translations in-place, keeping Mach-O offsets.
    update_messages = (
        ('To update:\n\n1. Open Sileo or Zebra\n2. Go to Packages tab\n3. Tap "Upgrade All" then "Confirm"\n\nIf you don\'t have the repo yet,\nadd this source:',
         'To update:\n\n1. Visit kingvcam.com\n2. Download the current package\n3. Install it with Sileo or Filza\n\nKingVCam downloads are at\nkingvcam.com', 'ascii'),
        ('Para atualizar:\n\n1. Abra o Sileo ou Zebra\n2. Vá na aba Pacotes\n3. Toque em "Atualizar Tudo" e "Confirmar"\n\nSe ainda não tem o repo,\nadicione esta fonte:',
         'Para atualizar:\n\n1. Acesse kingvcam.com\n2. Baixe o pacote atual\n3. Instale pelo Sileo ou Filza\n\nBaixe sempre pelo site\nkingvcam.com', 'utf-16le'),
        ('Para actualizar:\n\n1. Abre Sileo o Zebra\n2. Ve a la pestaña Paquetes\n3. Toca "Actualizar Todo" y "Confirmar"\n\nSi aún no tienes el repo,\nagrega esta fuente:',
         'Para actualizar:\n\n1. Visita kingvcam.com\n2. Descarga el paquete actual\n3. Instálalo con Sileo o Filza\n\nDescargas de KingVCam en\nkingvcam.com', 'utf-16le'),
        ('Copy Repo URL', 'Copy Site URL', 'ascii'),
        ('Copiar URL do Repo', 'Copiar URL do Site', 'ascii'),
        ('Copiar URL del Repo', 'Copiar sitio web', 'ascii'),
    )
    for old, new, encoding in update_messages:
        needle, replacement = old.encode(encoding), new.encode(encoding)
        if len(replacement) > len(needle):
            raise ValueError(f'Update text exceeds its original Mach-O slot: {old[:24]!r} {len(replacement)} > {len(needle)}')
        if needle in patched:
            padding = b' ' if encoding == 'ascii' else ' '.encode('utf-16le')
            replacement += padding * ((len(needle) - len(replacement)) // len(padding))
            patched = patched.replace(needle, replacement)
    # Replace old embedded support links in both plain and encoded data.
    for match in list(re.finditer(rb'https://t\.me/lordvcam(?:_bot|777)?', patched, re.IGNORECASE)):
        new = b'https://kingvcam.com'.ljust(len(match.group()), b'/')
        if len(new) != len(match.group()):
            raise ValueError('Support URL replacement has a different size')
        patched = patched[:match.start()] + new + patched[match.end():]
    # The plain branding pass already changes plain Telegram usernames.
    for match in list(re.finditer(rb'https://t\.me/kingvcam(?:_bot|777)?', patched, re.IGNORECASE)):
        new = b'https://kingvcam.com'.ljust(len(match.group()), b'/')
        if len(new) != len(match.group()):
            raise ValueError('Support URL replacement has a different size')
        patched = patched[:match.start()] + new + patched[match.end():]
    patched, _ = helpers.patch_encoded_references(patched)
    if len(patched) != len(blob):
        raise ValueError('Runtime edits changed binary size; refusing this build')
    return patched


def patch_control(payload: bytes) -> bytes:
    fields = {'Name': 'KingVCam (Rootless)', 'Version': VERSION,
              'Description': 'KingVCam authenticated media services runtime',
              'Maintainer': 'KingVCam', 'Author': 'KingVCam'}
    lines = []
    for line in payload.decode().splitlines():
        name = line.partition(':')[0]
        if name in fields:
            line = f'{name}: {fields[name]}'
        elif name == 'Depends':
            line = line.replace('Depends: ', 'Depends: ldid, ', 1)
        lines.append(line)
    return ('\n'.join(lines) + '\n').encode()


def signing_prefix() -> bytes:
    return b'''#!/bin/bash
# URL replacement invalidates the original signature. Preserve the original
# daemon entitlements; all original installation actions follow this prefix.
set -e
KC_JB="${JBROOT:-}"
[ -z "$KC_JB" ] && command -v jbroot >/dev/null 2>&1 && KC_JB="$(jbroot 2>/dev/null)"
[ -z "$KC_JB" ] && [ -d /var/jb ] && KC_JB="/var/jb"
KC_LDID="$(command -v ldid 2>/dev/null || true)"
[ -n "$KC_LDID" ] || { echo "KingVCam: ldid is required" >&2; exit 1; }
KC_ENT="$KC_JB/usr/share/kingvcam/avfsupportd.entitlements"
[ -s "$KC_ENT" ] || { echo "KingVCam: original daemon entitlements missing" >&2; exit 1; }
"$KC_LDID" -S "$KC_JB/Library/MobileSubstrate/DynamicLibraries/AVServicesd.dylib"
"$KC_LDID" -S"$KC_ENT" "$KC_JB/usr/libexec/avfsupportd"
set +e
'''


def main() -> None:
    if OUTPUT.exists():
        raise FileExistsError(f'Preserve the existing build before rebuilding: {OUTPUT}')
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError('Source is not the original package confirmed by the user')
    members = read_ar(source)
    original_data = contents(members['data.tar.lzma'])
    original_control = contents(members['control.tar.gz'])
    patched_binaries = {path: patch_runtime(original_data[path], is_tweak=(path == DYLIB)) for path in (DYLIB, DAEMON)}
    entitlements = plistlib.dumps(helpers.original_daemon_entitlements(original_data[DAEMON]), sort_keys=False)
    data = lzma.compress(rewrite_tar(members['data.tar.lzma'], patched_binaries, {ENTITLEMENTS: entitlements}), format=lzma.FORMAT_ALONE, preset=9)
    if b'Version: 3.0.44\n' not in original_control['control']:
        raise ValueError('Unexpected original version')
    control = patch_control(original_control['control'])
    original_script = original_control['postinst']
    if not original_script.startswith(b'#!/bin/bash\n'):
        raise ValueError('Unexpected original installation script')
    postinst = signing_prefix() + original_script.split(b'\n', 1)[1]
    packed_control = gzip.compress(rewrite_tar(members['control.tar.gz'], {'control': control, 'postinst': postinst}), mtime=0)
    package = b'!<arch>\n' + helpers.ar_member('debian-binary', members['debian-binary']) + helpers.ar_member('control.tar.gz', packed_control) + helpers.ar_member('data.tar.lzma', data)
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_bytes(package)
    print(f'Built: {OUTPUT}')
    print('TEST BUILD: old-service integrity mismatch check bypassed; camera behavior still requires on-device verification')
    print(f'SHA256: {hashlib.sha256(package).hexdigest()}')


if __name__ == '__main__':
    main()
