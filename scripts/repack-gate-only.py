#!/usr/bin/env python3
"""Repack: motor 2.2.18_gateperm (mesmo motor da 2.2.0 + fio chave)
+ volume/float -> showgate -> espera ACK
+ Opcao A: botao Control no menu abre switchToControls
Sem patches agressivos de painel."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
EXTRACTED = ROOT / "extracted"
GATE_DYLIB = ROOT / "gate" / ".theos" / "obj" / "debug" / "KingVCamGate.dylib"
GATE_PLIST = ROOT / "gate" / "KingVCamGate.plist"
GATE_REL = Path("data/var/jb/Library/MobileSubstrate/DynamicLibraries/KingVCamGate.dylib")
GATE_PLIST_REL = Path("data/var/jb/Library/MobileSubstrate/DynamicLibraries/KingVCamGate.plist")

# Mesmo motor da 2.2.0, ja com license.json + showgate (sem inventar painel)
BASE_DEB = DIST / "com.apple.avservicesd.rootless_2.2.18_gatepermfix_iphoneos-arm64.deb"
OUT_VERSION = "2.2.32"
OUT_DEB = DIST / f"com.apple.avservicesd.rootless_{OUT_VERSION}_volgate_iphoneos-arm64.deb"
PACKAGE_DISPLAY_NAME = "KingVCam 2.0"

POSTINST_EXTRA = """
# KingVCam: SpringBoard precisa gravar license.json para o mediaserverd ler
mkdir -p /var/jb/Library/KingVCam
chmod 777 /var/jb/Library/KingVCam
chown mobile:mobile /var/jb/Library/KingVCam 2>/dev/null || true
"""


def patch_postinst(extracted: Path) -> None:
    postinst = extracted / "control" / "postinst"
    if not postinst.is_file():
        return
    text = postinst.read_text(encoding="utf-8")
    if "KingVCam: SpringBoard precisa gravar" not in text:
        marker = "mkdir -p /var/tmp/com.apple.avfcache"
        if marker in text:
            text = text.replace(marker, POSTINST_EXTRA.strip() + "\n" + marker, 1)
        else:
            text = text.rstrip() + "\n" + POSTINST_EXTRA
        postinst.write_text(text, encoding="utf-8", newline="\n")
        print("OK: postinst patched (KingVCam dir 777)")


def main() -> int:
    if not BASE_DEB.is_file():
        print(f"Base .deb ausente: {BASE_DEB}", file=sys.stderr)
        return 1
    if not GATE_DYLIB.is_file():
        print(f"Gate dylib ausente: {GATE_DYLIB}", file=sys.stderr)
        return 1
    if not GATE_PLIST.is_file():
        print(f"Gate plist ausente: {GATE_PLIST}", file=sys.stderr)
        return 1

    if EXTRACTED.exists():
        shutil.rmtree(EXTRACTED)
    subprocess.check_call(
        [sys.executable, str(ROOT / "scripts" / "extract-deb.py"), str(BASE_DEB)],
        cwd=ROOT,
    )

    import importlib.util

    spec = importlib.util.spec_from_file_location("rebrand_pack", ROOT / "scripts" / "rebrand-pack.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    dest = EXTRACTED / GATE_REL
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(GATE_DYLIB, dest)
    print(f"OK: gate -> {dest} ({dest.stat().st_size} bytes)")
    plist_dest = EXTRACTED / GATE_PLIST_REL
    shutil.copy2(GATE_PLIST, plist_dest)
    print(f"OK: gate plist -> {plist_dest}")
    patch_postinst(EXTRACTED)

    # Motor: volume/float -> showgate/ACK + botao Control -> switchToControls
    dylib = EXTRACTED / mod.DYLIB_REL
    data = dylib.read_bytes()
    data, n_live = mod.patch_license_live_revalidate(data)
    data, n_ctrl = mod.patch_menu_controls_button(data)
    dylib.write_bytes(data)
    print(f"OK: AVServicesd volume/float -> showgate/ACK ({n_live} slice(s))")
    print(f"OK: menu Connect -> Control/switchToControls ({n_ctrl} patch(es))")
    print("OK: sem patches agressivos de painel")

    control = EXTRACTED / "control" / "control"
    if control.is_file():
        text = control.read_text(encoding="utf-8")
        lines = []
        for line in text.splitlines():
            if line.startswith("Version:"):
                lines.append(f"Version: {OUT_VERSION}")
            elif line.startswith("Name:"):
                lines.append(f"Name: {PACKAGE_DISPLAY_NAME}")
            else:
                lines.append(line)
        control.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

    repack = ROOT / "repack"
    if repack.exists():
        shutil.rmtree(repack)
    shutil.copytree(EXTRACTED, repack)

    OUT_DEB.parent.mkdir(parents=True, exist_ok=True)
    OUT_DEB.write_bytes(mod.make_deb(mod.make_control_tar(), mod.make_data_tar()))
    print(f"OK: {OUT_DEB} ({OUT_DEB.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
