#!/usr/bin/env python3
"""Rebrand and repack the authenticated 3.x runtime without auth bypasses."""

from __future__ import annotations

import gzip
import io
import lzma
import plistlib
import shutil
import struct
import tarfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXTRACTED = ROOT / "extracted"
DIST = ROOT / "dist"
VERSION = "3.0.44-6"
REPACK = ROOT / f"repack-authenticated-v3-{VERSION}"
OUTPUT = DIST / f"com.apple.avservicesd.rootless_{VERSION}_kingvcam-auth_iphoneos-arm64.deb"
DYLIB = Path("data/var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.dylib")
ICON = Path("data/var/jb/Library/KingVCam/icon.png")
DAEMON_ENTITLEMENTS = Path("data/var/jb/Library/KingVCam/avfsupportd.entitlements")
URL_XOR_KEY = b"LordVCAM_2026_k3"
ORIGINAL_API_BASE = b"https://www.lordvcam.com/v1"
KINGVCAM_API_BASE = b"https://www.kingvcam.com/v1"


def xor_url(value: bytes) -> bytes:
    return bytes(byte ^ URL_XOR_KEY[index % len(URL_XOR_KEY)] for index, byte in enumerate(value))


def patch_api_base(blob: bytes) -> tuple[bytes, int]:
    """Replace the obfuscated runtime API base, not just visible UI text."""
    if len(ORIGINAL_API_BASE) != len(KINGVCAM_API_BASE):
        raise ValueError("API base URLs must have the same encoded length")
    original = xor_url(ORIGINAL_API_BASE)
    replacement = xor_url(KINGVCAM_API_BASE)
    count = blob.count(original)
    if count != 4:
        raise RuntimeError(f"expected 4 encoded API base URLs, found {count}")
    return blob.replace(original, replacement), count


def patch_branding(blob: bytes) -> tuple[bytes, list[str]]:
    replacements = (
        (b"LordVCAM", b"KingVCam"),
        (b"lordvcam", b"kingvcam"),
        (b"LORDVCAM", b"KINGVCAM"),
        ("LordVCAM".encode("utf-16le"), "KingVCam".encode("utf-16le")),
        ("lordvcam".encode("utf-16le"), "kingvcam".encode("utf-16le")),
        (b"systemBlueColor", b"systemMintColor"),
    )
    output = blob
    log: list[str] = []
    for old, new in replacements:
        count = output.count(old)
        output = output.replace(old, new)
        log.append(f"{old!r} -> {new!r} ({count}x)")
    log.append("AUTH_BYPASS=False (login/plano originais)")
    return output, log


def patch_encoded_references(blob: bytes) -> tuple[bytes, list[str]]:
    """Update embedded hostnames and support URLs without changing string lengths.

    Keep the decoder key unchanged: it is also used for protocol field names.
    """
    import re
    output = bytearray(blob)
    log = []
    for phase in range(len(URL_XOR_KEY)):
        decoded = bytes(b ^ URL_XOR_KEY[(i + phase) % len(URL_XOR_KEY)] for i, b in enumerate(output))
        edits = []
        for match in re.finditer(rb"lordvcam\.com", decoded, re.IGNORECASE):
            edits.append((match.start(), b"kingvcam.com"))
        for match in re.finditer(rb"https://t\.me/[Ll][Oo][Rr][Dd][Vv][Cc][Aa][Mm](?:_bot|777)?", decoded):
            old = match.group()
            new = b"https://kingvcam.com"
            if len(new) > len(old):
                raise RuntimeError("support URL replacement too long")
            edits.append((match.start(), new.ljust(len(old), b"/")))
        for offset, replacement in edits:
            for i, b in enumerate(replacement):
                output[offset + i] = b ^ URL_XOR_KEY[(offset + i + phase) % len(URL_XOR_KEY)]
        if edits:
            log.append(f"encoded references phase {phase}: {len(edits)} replacements")
    return bytes(output), log


def rewrite_control(path: Path) -> None:
    replacements = {
        "Name": "KingVCam (Rootless)",
        "Version": VERSION,
        "Description": "KingVCam authenticated media services runtime",
        "Maintainer": "KingVCam",
        "Author": "KingVCam",
    }
    result: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        key = line.partition(":")[0]
        if key in replacements:
            result.append(f"{key}: {replacements[key]}")
            seen.add(key)
        else:
            result.append(line)
    for key, value in replacements.items():
        if key not in seen:
            result.append(f"{key}: {value}")
    result.append("Icon: file:///var/jb/Library/KingVCam/icon.png")
    path.write_text("\n".join(result) + "\n", encoding="utf-8", newline="\n")


def restrict_injection_filter(path: Path) -> None:
    """Limit this diagnostic build to SpringBoard and the native camera path.

    UIKit is a framework match, not an application-only match. The device logs
    show our initializer creating a CIContext in amfid and donotdisturbd and
    crashing both. Never match a ubiquitous framework here. Keep SpringBoard
    explicitly for the menu/volume hooks. Third-party apps are not enabled in
    this build and must be added by their exact bundle identifier after testing.
    """
    payload = {"Filter": {
        "Bundles": ["com.apple.springboard", "com.apple.camera"],
        "Executables": ["SpringBoard", "Camera", "mediaserverd"],
    }}
    path.write_bytes(plistlib.dumps(payload, fmt=plistlib.FMT_BINARY, sort_keys=False))


def original_daemon_entitlements(blob: bytes) -> dict:
    """Preserve the original executable's signed permissions in every slice."""
    if blob[:4] != bytes.fromhex("cafebabe"):
        raise ValueError("Expected the original universal Mach-O daemon")
    count = struct.unpack_from(">I", blob, 4)[0]
    entitlements = []
    for index in range(count):
        _, _, offset, size, _ = struct.unpack_from(">IIIII", blob, 8 + index * 20)
        thin = blob[offset:offset + size]
        if thin[:4] != bytes.fromhex("cffaedfe"):
            raise ValueError("Expected a little-endian 64-bit Mach-O slice")
        commands = struct.unpack_from("<I", thin, 16)[0]
        cursor = 32
        signature = None
        for _ in range(commands):
            command, length = struct.unpack_from("<II", thin, cursor)
            if command == 0x1d:  # LC_CODE_SIGNATURE
                start, length = struct.unpack_from("<II", thin, cursor + 8)
                signature = thin[start:start + length]
                break
            cursor += length
        if signature is None:
            raise ValueError("Daemon slice has no code signature")
        magic, _, slots = struct.unpack_from(">III", signature)
        if magic != 0xfade0cc0:
            raise ValueError("Invalid signature superblob")
        found = None
        for slot in range(slots):
            kind, start = struct.unpack_from(">II", signature, 12 + slot * 8)
            if kind == 5:  # CSSLOT_ENTITLEMENTS
                magic, length = struct.unpack_from(">II", signature, start)
                if magic != 0xfade7171:
                    raise ValueError("Invalid XML entitlement blob")
                found = plistlib.loads(signature[start + 8:start + length])
        if not found:
            raise ValueError("Original daemon entitlements missing")
        entitlements.append(found)
    if not entitlements or any(item != entitlements[0] for item in entitlements):
        raise ValueError("Daemon slices have different entitlements")
    return entitlements[0]


def write_safe_postinst(path: Path) -> None:
    script = """#!/bin/bash
set -e
JB="${JBROOT:-}"
[ -z "$JB" ] && command -v jbroot >/dev/null 2>&1 && JB="$(jbroot 2>/dev/null)"
[ -z "$JB" ] && [ -d /var/jb ] && JB="/var/jb"

DYLIB="$JB/Library/MobileSubstrate/DynamicLibraries/AVServicesd.dylib"
BIN="$JB/usr/libexec/avfsupportd"
PLIST="$JB/Library/LaunchDaemons/com.apple.avfsupportd.plist"
ENTITLEMENTS="$JB/Library/KingVCam/avfsupportd.entitlements"

# Binary patching invalidates the original ad-hoc signature. Sign before any
# target process is restarted; fail installation safely if ldid is unavailable.
LDID="$(command -v ldid 2>/dev/null || true)"
[ -n "$LDID" ] || { echo "KingVCam: ldid is required" >&2; exit 1; }
"$LDID" -S "$DYLIB"
[ -s "$ENTITLEMENTS" ] || { echo "KingVCam: daemon entitlements missing" >&2; exit 1; }
"$LDID" -S"$ENTITLEMENTS" "$BIN"

mkdir -p /var/tmp/com.apple.avfcache
chmod 777 /var/tmp/com.apple.avfcache
if [ -x "$BIN" ]; then
    mkdir -p "$JB/Library/LaunchDaemons"
    cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.apple.avfsupportd</string>
<key>Program</key><string>$BIN</string>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>10</integer>
<key>ProcessType</key><string>Interactive</string>
<key>LegacyTimers</key><true/>
</dict></plist>
PL
    launchctl bootout system "$PLIST" 2>/dev/null || true
    launchctl enable system/com.apple.avfsupportd 2>/dev/null || true
    if ! launchctl bootstrap system "$PLIST" && ! launchctl load -w "$PLIST"; then
        echo "KingVCam: could not load video producer" >&2
        launchctl print system/com.apple.avfsupportd >&2 || true
        exit 1
    fi
    if ! launchctl kickstart -k system/com.apple.avfsupportd; then
        echo "KingVCam: could not start video producer" >&2
        launchctl print system/com.apple.avfsupportd >&2 || true
        exit 1
    fi
    # Record the producer's launch state for diagnostics without user credentials.
    launchctl print system/com.apple.avfsupportd > /var/tmp/com.apple.avfcache/kingvcam-launch.txt 2>&1 || true
fi

# Restart only the process selected by the injection filter. Never terminate
# SpringBoard or backboardd from a package script.
killall -9 mediaserverd 2>/dev/null || true
exit 0
"""
    path.write_text(script, encoding="utf-8", newline="\n")


def write_diagnostics(path: Path) -> None:
    """Collect launch/IPC state locally without reading credentials or sessions."""
    script = f'''#!/bin/bash
set -u
OUT="/var/mobile/kingvcam-diagnostics.txt"
CACHE="/var/tmp/com.apple.avfcache"
umask 077
{{
    echo "KingVCam package {VERSION} diagnostic report"
    date -u
    echo "Installed package:"
    dpkg-query -W -f='${{Version}}\\n' com.apple.avservicesd.rootless 2>&1
    echo "Video producer launch state:"
    launchctl print system/com.apple.avfsupportd 2>&1
    echo "Relevant processes:"
    for NAME in avfsupportd SpringBoard Camera mediaserverd cameracaptured; do
        pgrep -x -l "$NAME" || true
    done
    echo "Video IPC files (metadata only):"
    for NAME in vcam_decoded.bin vcam_audio.bin playhead.txt prefs.lock session.dat kingvcam-launch.txt; do
        ls -l "$CACHE/$NAME" 2>&1
    done
    echo "Native diagnostic log locations (metadata only):"
    for LOG in "$CACHE/crash.txt" "$CACHE/vcam_debug.log" /var/mobile/vcam_lock.log /var/tmp/vcam_debug.log; do
        ls -l "$LOG" 2>&1
    done
}} > "$OUT" 2>&1
chown mobile:mobile "$OUT" 2>/dev/null || true
echo "Saved: $OUT"
'''
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(script, encoding="utf-8", newline="\n")


def tar_info(name: str, size: int, mode: int, directory: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = 0 if directory else size
    info.mode = mode
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = int(time.time())
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    return info


def archive_tree(root: Path, compression: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        archive.addfile(tar_info(".", 0, 0o755, True))
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if path.is_dir():
                archive.addfile(tar_info(relative, 0, 0o755, True))
                continue
            executable = (
                relative in {"postinst", "postrm"}
                or path.suffix == ".dylib"
                or "/usr/libexec/" in f"/{relative}"
                or relative == "var/jb/usr/bin/kingvcam-diagnostics"
            )
            data = path.read_bytes().replace(b"\r\n", b"\n") if root.name == "control" else path.read_bytes()
            info = tar_info(relative if root.name != "control" else f"./{relative}", len(data), 0o755 if executable else 0o644)
            archive.addfile(info, io.BytesIO(data))
    raw = buffer.getvalue()
    return gzip.compress(raw, mtime=0) if compression == "gzip" else lzma.compress(raw, format=lzma.FORMAT_ALONE, preset=9)


def ar_member(name: str, payload: bytes) -> bytes:
    header = (
        name.encode("ascii").ljust(16)
        + b"0".ljust(12)
        + b"0".ljust(6)
        + b"0".ljust(6)
        + b"100644".ljust(8)
        + str(len(payload)).encode("ascii").ljust(10)
        + b"`\n"
    )
    return header + payload + (b"\n" if len(payload) % 2 else b"")


def main() -> int:
    if not (EXTRACTED / "control" / "control").is_file():
        raise FileNotFoundError("Extract the 3.0.44 package with scripts/extract-deb.py first")
    if REPACK.exists():
        raise FileExistsError(f"Build directory already exists; preserve or move it before rebuilding: {REPACK}")
    shutil.copytree(EXTRACTED / "control", REPACK / "control")
    shutil.copytree(EXTRACTED / "data", REPACK / "data")

    permissions = original_daemon_entitlements(
        (EXTRACTED / "data/var/jb/usr/libexec/avfsupportd").read_bytes())
    entitlement_path = REPACK / DAEMON_ENTITLEMENTS
    entitlement_path.parent.mkdir(parents=True, exist_ok=True)
    entitlement_path.write_bytes(plistlib.dumps(permissions, sort_keys=False))

    log = []
    for binary in (REPACK / DYLIB, REPACK / "data/var/jb/usr/libexec/avfsupportd"):
        original = binary.read_bytes()
        patched, brand_log = patch_branding(original)
        patched, url_log = patch_encoded_references(patched)
        if len(original) != len(patched):
            raise RuntimeError("binary size changed")
        if xor_url(ORIGINAL_API_BASE) in patched:
            raise RuntimeError("old API base still present")
        binary.write_bytes(patched)
        log.append(str(binary.relative_to(REPACK)))
        log.extend(brand_log + url_log)
    rewrite_control(REPACK / "control" / "control")
    control_path = REPACK / "control" / "control"
    control_text = control_path.read_text(encoding="utf-8")
    control_text = control_text.replace(
        "Depends: mobilesubstrate | ellekit | libhooker | substitute",
        "Depends: ldid, mobilesubstrate | ellekit | libhooker | substitute",
    )
    control_path.write_text(control_text, encoding="utf-8", newline="\n")
    restrict_injection_filter(
        REPACK / "data/var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.plist"
    )
    write_safe_postinst(REPACK / "control" / "postinst")
    write_diagnostics(REPACK / "data/var/jb/usr/bin/kingvcam-diagnostics")

    icon_target = REPACK / ICON
    icon_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "assets" / "kingvcam-icon.png", icon_target)
    (REPACK / "PATCHLOG.txt").write_text("\n".join(log) + "\n", encoding="utf-8")

    control = archive_tree(REPACK / "control", "gzip")
    data = archive_tree(REPACK / "data", "lzma")
    package = b"!<arch>\n" + ar_member("debian-binary", b"2.0\n") + ar_member("control.tar.gz", control) + ar_member("data.tar.lzma", data)
    DIST.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(package)
    print(f"OK: {OUTPUT} ({OUTPUT.stat().st_size} bytes)")
    print((REPACK / "PATCHLOG.txt").read_text(encoding="utf-8").rstrip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
