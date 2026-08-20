#!/usr/bin/env python3
"""Clona o .deb extraido, troca LordVCAM -> KingVCam e gera dist/*.deb."""

from __future__ import annotations

import gzip
import io
import lzma
import shutil
import struct
import tarfile
import time
from pathlib import Path

import capstone
import lief

ROOT = Path(__file__).resolve().parents[1]
EXTRACTED = ROOT / "extracted"
REPACK = ROOT / "repack"
DIST = ROOT / "dist"
ASSETS = ROOT / "assets"
DYLIB_REL = Path("data/var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.dylib")
ICON_SRC = ASSETS / "kingvcam-icon.png"
ICON_REL = Path("data/var/jb/Library/KingVCam/icon.png")

OLD_NAME = "LordVCAM"
NEW_NAME = "KingVCam"
OLD_SLUG = "lordvcam"
NEW_SLUG = "kingvcam"
NEW_VERSION = "2.2.18"
PACKAGE_DISPLAY_NAME = "KingVCam 2.0"
GATE_DYLIB = ROOT / "gate" / ".theos" / "obj" / "debug" / "KingVCamGate.dylib"
GATE_PLIST = ROOT / "gate" / "KingVCamGate.plist"
GATE_REL = Path("data/var/jb/Library/MobileSubstrate/DynamicLibraries")
AUTH_BYPASS = True  # overlay 2.2.0; motor so depois da chave
AUTH_UI_SELECTORS = (
    "showCurrencySelector",
    "showWallet",
    "presentAlertOnWindow:",
    "_avs_pres_connAlert",
    "_avs_pres_valExpAlert",
    "startPeriodicSync",
)
REMOTE_IO_SELECTORS = (
    "uploadTaskWithRequest:fromFile:completionHandler:",
    "webSocketTaskWithURL:",
)
TELEGRAM_STR_CAVE = 0x80


def patch_bytes(blob: bytes) -> tuple[bytes, list[str]]:
    replacements = [
        (OLD_NAME.encode("ascii"), NEW_NAME.encode("ascii")),
        (OLD_SLUG.encode("ascii"), NEW_SLUG.encode("ascii")),
        (OLD_NAME.encode("utf-16le"), NEW_NAME.encode("utf-16le")),
        (OLD_SLUG.encode("utf-16le"), NEW_SLUG.encode("utf-16le")),
        (b"systemBlueColor", b"systemMintColor"),
    ]
    log: list[str] = []
    out = blob
    for old, new in replacements:
        if len(old) != len(new):
            raise ValueError(f"tamanho diferente: {old!r} -> {new!r}")
        count = out.count(old)
        out = out.replace(old, new)
        log.append(f"{old!r} -> {new!r} ({count}x)")
    leftovers = []
    for needle in (OLD_NAME, OLD_SLUG, "systemBlueColor"):
        if needle.encode("ascii") in out or needle.encode("utf-16le") in out:
            leftovers.append(needle)
    if leftovers:
        raise RuntimeError(f"ainda restou marca antiga no dylib: {leftovers}")
    if AUTH_BYPASS:
        forced, n_state = patch_force_licensed_state(out)
        out = forced
        log.append(f"ui-state mov x8,#1 ({n_state}x)")
        noped, n_login = patch_nop_auth_ui(out)
        out = noped
        log.append(f"auth-ui nop ({n_login}x)")
        opened, n_cbz = patch_open_tools_panel(out)
        out = opened
        log.append(f"currency-cbz nop ({n_cbz}x)")
        forced_st, n_st = patch_force_bool_getters(out)
        out = forced_st
        log.append(f"cfg getters=1 ({n_st}x)")
        forced_lic, n_lic = patch_force_license_ok(out)
        out = forced_lic
        log.append(f"chk-actLic always-ok ({n_lic}x)")
        opened_tap, n_tap = patch_float_tap_show_panel(out)
        out = opened_tap
        log.append(f"float-tap skip-auth ({n_tap}x)")
        noped_io, n_io = patch_kill_remote_io(out)
        out = noped_io
        log.append(f"remote-io mov x0,#0 ({n_io}x)")
        sync_off, n_sync = patch_disable_periodic_sync(out)
        out = sync_off
        log.append(f"startPeriodicSync ret ({n_sync}x)")
        vol, n_vol = patch_volume_shortcut(out)
        out = vol
        log.append(f"volume-shortcut ({n_vol}x)")
        shown, n_show = patch_ctor_show_overlay(out)
        out = shown
        log.append(f"ctor overlay+flags ({n_show}x)")
        gf, n_gf = patch_getframe_skip_proof(out)
        out = gf
        log.append(f"getFrame skip-proof ({n_gf}x)")
        lic, n_lic2 = patch_license_file_gate(out)
        out = lic
        log.append(f"license-file-gate ({n_lic2}x)")
    else:
        log.append("AUTH_BYPASS=False (login/plano originais)")
    return out, log


MOV_X8_1 = struct.pack("<I", 0xD2800028)
MOV_X0_1 = struct.pack("<I", 0xD2800020)
MOV_X0_0 = struct.pack("<I", 0xD2800000)
MOV_W9_1 = struct.pack("<I", 0x52800029)
RET = struct.pack("<I", 0xD65F03C0)
RETAB = struct.pack("<I", 0xD65F0FFF)
NOP = struct.pack("<I", 0xD503201F)


def encode_arm64_b(pc: int, target: int) -> bytes:
    offset = (target - pc) >> 2
    if offset < -(1 << 25) or offset >= (1 << 25):
        raise ValueError(f"branch fora de alcance: {pc:#x} -> {target:#x}")
    return struct.pack("<I", 0x14000000 | (offset & 0x03FFFFFF))


def encode_arm64_bl(pc: int, target: int) -> bytes:
    offset = (target - pc) >> 2
    if offset < -(1 << 25) or offset >= (1 << 25):
        raise ValueError(f"bl fora de alcance: {pc:#x} -> {target:#x}")
    return struct.pack("<I", 0x94000000 | (offset & 0x03FFFFFF))


def encode_arm64_adrp(pc: int, rd: int, page: int) -> bytes:
    imm = (page - (pc & ~0xFFF)) >> 12
    if imm < -(1 << 20) or imm >= (1 << 20):
        raise ValueError(f"adrp fora de alcance: {pc:#x} -> {page:#x}")
    immlo = imm & 3
    immhi = (imm >> 2) & 0x7FFFF
    return struct.pack("<I", 0x90000000 | (immlo << 29) | (immhi << 5) | rd)


def encode_arm64_strb(rt: int, rn: int, imm: int) -> bytes:
    if imm < 0 or imm > 0xFFF:
        raise ValueError(f"strb imm invalido: {imm:#x}")
    return struct.pack("<I", 0x39000000 | (imm << 10) | (rn << 5) | rt)


def encode_arm64_ldr64(rt: int, rn: int, disp: int) -> bytes:
    if disp < 0 or disp % 8:
        raise ValueError(f"ldr disp invalido: {disp:#x}")
    imm12 = disp // 8
    if imm12 > 0xFFF:
        raise ValueError(f"ldr imm12: {imm12:#x}")
    return struct.pack("<I", 0xF9400000 | (imm12 << 10) | (rn << 5) | rt)


def encode_arm64_add_imm(rd: int, rn: int, imm: int) -> bytes:
    if imm < 0 or imm > 0xFFF:
        raise ValueError(f"add imm invalido: {imm:#x}")
    return struct.pack("<I", 0x91000000 | (imm << 10) | (rn << 5) | rd)


def encode_arm64_ldrb(rt: int, rn: int, disp: int) -> bytes:
    if disp < 0 or disp > 0xFFF:
        raise ValueError(f"ldrb disp invalido: {disp:#x}")
    return struct.pack("<I", 0x39400000 | (disp << 10) | (rn << 5) | rt)


def encode_arm64_cbz(pc: int, rt: int, target: int, is64: bool = False, cbnz: bool = False) -> bytes:
    offset = (target - pc) >> 2
    if offset < -(1 << 18) or offset >= (1 << 18):
        raise ValueError(f"cbz fora de alcance: {pc:#x} -> {target:#x}")
    base = 0x34000000
    if is64:
        base |= 0x80000000
    if cbnz:
        base |= 0x01000000
    return struct.pack("<I", base | ((offset & 0x7FFFF) << 5) | rt)


MOV_X29_X29 = bytes.fromhex("fd031daa")
MOV_X21_X0 = bytes.fromhex("f50300aa")
MOV_X0_X21 = bytes.fromhex("e00315aa")


def fat_slices(blob: bytes) -> list[tuple[int, bytes]]:
    magic = struct.unpack(">I", blob[:4])[0]
    if magic != 0xCAFEBABE:
        return [(0, blob)]
    nfat = struct.unpack(">I", blob[4:8])[0]
    slices: list[tuple[int, bytes]] = []
    off = 8
    for _ in range(nfat):
        _cpu, _sub, offset, size, _align = struct.unpack(">IIIII", blob[off : off + 20])
        slices.append((offset, blob[offset : offset + size]))
        off += 20
    return slices


def _gpr(name: str | None) -> str:
    if not name:
        return ""
    if name[0] in "wx" and name[1:].isdigit():
        return name[1:]
    return name


def _patch_flag_branch(out: bytearray, slice_off: int, text_file: int, text_va: int, insn) -> bool:
    """Converte branch de flag de licenca para o caminho autorizado. True se patchou."""
    file_off = slice_off + text_file + (insn.address - text_va)
    if insn.mnemonic == "tbnz":
        if insn.operands[1].imm != 0:
            return False
        out[file_off : file_off + 4] = encode_arm64_b(insn.address, int(insn.operands[2].imm))
        return True
    if insn.mnemonic == "tbz":
        if insn.operands[1].imm != 0:
            return False
        out[file_off : file_off + 4] = NOP
        return True
    if insn.mnemonic == "cbnz":
        out[file_off : file_off + 4] = encode_arm64_b(insn.address, int(insn.operands[-1].imm))
        return True
    if insn.mnemonic == "cbz":
        out[file_off : file_off + 4] = NOP
        return True
    if insn.mnemonic == "b.ne":
        out[file_off : file_off + 4] = NOP
        return True
    if insn.mnemonic == "b.eq":
        out[file_off : file_off + 4] = encode_arm64_b(insn.address, int(insn.operands[0].imm))
        return True
    return False


def patch_license_gate(blob: bytes) -> tuple[bytes, int]:
    """Forca flags 0x5f0/0x5f1 (e fallback) a sempre seguir o caminho autorizado."""
    out = bytearray(blob)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    patched = 0
    seen: set[int] = set()
    flag_imms = {0x5F0, 0x5F1}

    def apply(slice_off: int, text_file: int, text_va: int, insn) -> None:
        nonlocal patched
        key = slice_off + insn.address
        if key in seen:
            return
        if _patch_flag_branch(out, slice_off, text_file, text_va, insn):
            seen.add(key)
            patched += 1

    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        text = binary.get_section("__text")
        text_va = int(text.virtual_address)
        text_file = int(text.offset)
        insns = list(md.disasm(bytes(text.content), text_va))
        n = len(insns)
        ptr_regs: dict[str, int] = {}
        val_regs: dict[str, int] = {}
        for idx, insn in enumerate(insns):
            expire_before = insn.address
            ptr_regs = {r: exp for r, exp in ptr_regs.items() if exp > expire_before}
            val_regs = {r: exp for r, exp in val_regs.items() if exp > expire_before}

            if insn.mnemonic == "ldrb" and insn.operands[1].type == capstone.arm64.ARM64_OP_MEM:
                disp = insn.operands[1].mem.disp
                dest = _gpr(insn.reg_name(insn.operands[0].reg))
                base = _gpr(insn.reg_name(insn.operands[1].mem.base))
                if disp in flag_imms:
                    val_regs[dest] = insn.address + 64
                elif base in ptr_regs and disp == 0:
                    val_regs[dest] = insn.address + 64

            if insn.mnemonic == "add" and len(insn.operands) >= 3:
                if insn.operands[2].type == capstone.arm64.ARM64_OP_IMM and insn.operands[2].imm in flag_imms:
                    ptr_regs[_gpr(insn.reg_name(insn.operands[0].reg))] = insn.address + 0xC0

            if insn.mnemonic in ("tbnz", "tbz"):
                src = _gpr(insn.reg_name(insn.operands[0].reg))
                if src in val_regs:
                    apply(slice_off, text_file, text_va, insn)
                    continue
            if insn.mnemonic in ("cbz", "cbnz"):
                src = _gpr(insn.reg_name(insn.operands[0].reg))
                if src in val_regs:
                    apply(slice_off, text_file, text_va, insn)
                    continue
            if insn.mnemonic == "cmp" and len(insn.operands) >= 2:
                if insn.operands[1].type == capstone.arm64.ARM64_OP_IMM and insn.operands[1].imm == 1:
                    src = _gpr(insn.reg_name(insn.operands[0].reg))
                    if src in val_regs and idx + 1 < n:
                        nxt = insns[idx + 1]
                        if nxt.mnemonic in ("b.ne", "b.eq"):
                            apply(slice_off, text_file, text_va, nxt)
    if patched < 50:
        raise RuntimeError(f"poucos patches de license-gate ({patched}); abortando")
    return bytes(out), patched


# ldr x8, [x19, #0x28]; cmp x8, #4
STATE_SWITCH = bytes.fromhex("681640f91f1100f1")


def patch_force_licensed_state(blob: bytes) -> tuple[bytes, int]:
    """Forca o dispatcher da UI a tratar estado=1 (plano ativo), sem login/planos."""
    out = bytearray(blob)
    patched = 0
    for slice_off, sdata in fat_slices(blob):
        idx = 0
        while True:
            hit = sdata.find(STATE_SWITCH, idx)
            if hit < 0:
                break
            file_off = slice_off + hit
            out[file_off : file_off + 4] = MOV_X8_1
            patched += 1
            idx = hit + 1
    if patched != 2:
        raise RuntimeError(f"esperado 2 patches de ui-state, veio {patched}")
    return bytes(out), patched


# cbz x20, currency-ui  /  cbz x21, currency-ui  (caminho estado=1)
CURRENCY_CBZ = (
    bytes.fromhex("f41e00b4"),
    bytes.fromhex("d52100b4"),
)


def patch_open_tools_panel(blob: bytes) -> tuple[bytes, int]:
    """Nao desvia para seletor de moeda; segue e monta o painel de ferramentas."""
    out = bytearray(blob)
    patched = 0
    for slice_off, sdata in fat_slices(blob):
        for needle in CURRENCY_CBZ:
            hit = sdata.find(needle)
            if hit < 0 or sdata.find(needle, hit + 1) >= 0:
                raise RuntimeError(f"cbz currency nao unico: {needle.hex()}")
            file_off = slice_off + hit
            out[file_off : file_off + 4] = NOP
            patched += 1
    if patched != 4:
        raise RuntimeError(f"esperado 4 nops de currency-cbz, veio {patched}")
    return bytes(out), patched


def _selref_map(binary) -> dict[int, int]:
    """methname VA -> selref VA."""
    out: dict[int, int] = {}
    for rel in binary.relocations:
        target = getattr(rel, "target", None)
        if target is None:
            continue
        out[int(target)] = int(rel.address)
    return out


def _methname_va(binary, name: str) -> int | None:
    meth = binary.get_section("__objc_methname")
    if meth is None:
        return None
    raw = bytes(meth.content)
    name_off = raw.find(name.encode() + b"\x00")
    if name_off < 0:
        return None
    return int(meth.virtual_address) + name_off


def _stub_va_for_selref(binary, selref_va: int) -> int | None:
    stubs = binary.get_section("__objc_stubs")
    if stubs is None:
        return None
    sb = bytes(stubs.content)
    sva = int(stubs.virtual_address)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    pending: dict[int, tuple[int, int]] = {}
    for insn in md.disasm(sb, sva):
        if insn.mnemonic == "adrp":
            pending[insn.operands[0].reg] = (insn.address, insn.operands[1].imm)
        elif insn.mnemonic == "ldr" and insn.operands[1].type == capstone.arm64.ARM64_OP_MEM:
            base = insn.operands[1].mem.base
            if base in pending:
                dest = pending[base][1] + insn.operands[1].mem.disp
                if dest == selref_va:
                    return pending[base][0]
    return None


def patch_nop_auth_ui(blob: bytes) -> tuple[bytes, int]:
    """NOP nas telas de login/plano/carteira/alerta de auth."""
    out = bytearray(blob)
    patched = 0
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        selmap = _selref_map(binary)
        stubs: list[int] = []
        missing: list[str] = []
        for name in AUTH_UI_SELECTORS:
            mva = _methname_va(binary, name)
            if mva is None or mva not in selmap:
                missing.append(name)
                continue
            stub = _stub_va_for_selref(binary, selmap[mva])
            if stub is None:
                missing.append(name)
                continue
            stubs.append(stub)
        stub_set = set(stubs)
        text = binary.get_section("__text")
        text_va = int(text.virtual_address)
        text_file = int(text.offset)
        for insn in md.disasm(bytes(text.content), text_va):
            if insn.mnemonic != "bl":
                continue
            if insn.operands[0].imm not in stub_set:
                continue
            file_off = slice_off + text_file + (insn.address - text_va)
            out[file_off : file_off + 4] = NOP
            patched += 1
        if missing:
            raise RuntimeError(f"selectors sem stub: {missing}")
    if patched < 10:
        raise RuntimeError(f"poucos NOP auth-ui ({patched})")
    return bytes(out), patched


def _exact_methname_va(binary, name: str) -> int | None:
    meth = binary.get_section("__objc_methname")
    if meth is None:
        return None
    raw = bytes(meth.content)
    needle = b"\x00" + name.encode() + b"\x00"
    hit = raw.find(needle)
    if hit >= 0:
        return int(meth.virtual_address) + hit + 1
    if raw.startswith(name.encode() + b"\x00"):
        return int(meth.virtual_address)
    return None


def _selref_for_name(binary, name: str) -> int | None:
    mva = _exact_methname_va(binary, name)
    if mva is None:
        return None
    sel = binary.get_section("__objc_selrefs")
    if sel is None:
        return None
    sel_lo = int(sel.virtual_address)
    sel_hi = sel_lo + int(sel.size)
    for rel in binary.relocations:
        target = getattr(rel, "target", None)
        if target is None:
            continue
        addr = int(rel.address)
        if int(target) == mva and sel_lo <= addr < sel_hi:
            return addr
    return None


def _imp_for_selref(binary, selref_va: int) -> int | None:
    ml = binary.get_section("__objc_methlist")
    if ml is None:
        return None
    raw = bytes(ml.content)
    mva = int(ml.virtual_address)
    i = 0
    while i + 8 <= len(raw):
        entsize_flags, count = struct.unpack_from("<II", raw, i)
        entsize = entsize_flags & 0xFFFF
        if entsize != 12 or count == 0 or count > 500:
            i += 4
            continue
        payload = count * entsize
        base = i + 8
        if base + payload > len(raw):
            i += 4
            continue
        for k in range(count):
            e = base + k * 12
            nrel, _trel, irel = struct.unpack_from("<iii", raw, e)
            name_ptr = (mva + e) + nrel
            if name_ptr == selref_va:
                return (mva + e + 8) + irel
        i = base + payload
    return None


def _text_file_off(slice_off: int, binary, va: int) -> int:
    text = binary.get_section("__text")
    return slice_off + int(text.offset) + (va - int(text.virtual_address))


def _imported_stub(binary, name: str) -> int:
    got = None
    for bind in binary.bindings:
        sym = getattr(bind, "symbol", None)
        n = getattr(sym, "name", None) if sym is not None else None
        if n == name:
            got = int(bind.address)
            break
    if got is None:
        raise RuntimeError(f"bind {name} ausente")
    stubs = binary.get_section("__stubs")
    if stubs is None:
        raise RuntimeError("__stubs ausente")
    sb = bytes(stubs.content)
    sva = int(stubs.virtual_address)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    pending: dict[int, tuple[int, int]] = {}
    for insn in md.disasm(sb, sva):
        if insn.mnemonic == "adrp":
            pending[insn.operands[0].reg] = (insn.address, int(insn.operands[1].imm))
        elif insn.mnemonic == "ldr" and insn.operands[1].type == capstone.arm64.ARM64_OP_MEM:
            base = insn.operands[1].mem.base
            if base in pending:
                dest = pending[base][1] + insn.operands[1].mem.disp
                if dest == got:
                    return pending[base][0]
    raise RuntimeError(f"stub {name} ausente")


def _bss_page(binary, md) -> int:
    text = binary.get_section("__text")
    tb = bytes(text.content)
    tva = int(text.virtual_address)
    last_adrp = None
    for insn in md.disasm(tb, tva):
        if insn.mnemonic == "adrp":
            last_adrp = int(insn.operands[1].imm)
        if (
            insn.mnemonic == "add"
            and len(insn.operands) >= 3
            and insn.operands[2].type == capstone.arm64.ARM64_OP_IMM
            and insn.operands[2].imm == 0x5F0
            and last_adrp is not None
        ):
            return last_adrp
    raise RuntimeError("bss ausente")


def _sps_http_cave(binary, md) -> tuple[int, int]:
    sel = _selref_for_name(binary, "startPeriodicSync")
    imp = _imp_for_selref(binary, sel) if sel else None
    if imp is None:
        raise RuntimeError("startPeriodicSync sem IMP na cave HTTP")
    text = binary.get_section("__text")
    text_va = int(text.virtual_address)
    tb = bytes(text.content)
    first = next(md.disasm(tb[imp - text_va : imp - text_va + 4], imp))
    cave = imp + (12 if first.mnemonic == "pacibsp" else 8)
    insns = list(md.disasm(tb[imp - text_va : imp - text_va + 0x800], imp))
    limit = None
    for insn in insns:
        if insn.address <= imp + 16:
            continue
        if insn.mnemonic in ("ret", "retab"):
            limit = insn.address
            break
    if limit is None:
        raise RuntimeError("startPeriodicSync sem limite de cave")
    return cave, limit


def _volume_handler_entry(binary, md) -> int:
    text = binary.get_section("__text")
    insns = list(md.disasm(bytes(text.content), int(text.virtual_address)))
    for i, insn in enumerate(insns[:-3]):
        if insn.mnemonic != "adrp" or insn.reg_name(insn.operands[0].reg) != "x21":
            continue
        add_i = insns[i + 1]
        ldr_i = insns[i + 2]
        if add_i.mnemonic != "add" or ldr_i.mnemonic != "ldrb":
            continue
        if len(add_i.operands) < 3 or add_i.operands[2].type != capstone.arm64.ARM64_OP_IMM:
            continue
        if add_i.operands[2].imm != 0x5F0:
            continue
        if ldr_i.operands[1].type != capstone.arm64.ARM64_OP_MEM or ldr_i.operands[1].mem.disp != 0:
            continue
        return add_i.address
    raise RuntimeError("volume handler ausente")


def patch_force_bool_getters(blob: bytes) -> tuple[bytes, int]:
    """Plano ativo e replace ligado: o motor original le esses getters."""
    out = bytearray(blob)
    patched = 0
    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        for name in ("_avs_cfg_st", "_avs_cfg_replOn"):
            selref = _selref_for_name(binary, name)
            if selref is None:
                raise RuntimeError(f"{name} sem selref")
            imp = _imp_for_selref(binary, selref)
            if imp is None:
                raise RuntimeError(f"{name} sem IMP")
            file_off = _text_file_off(slice_off, binary, imp)
            text = binary.get_section("__text")
            rel = imp - int(text.virtual_address)
            first = next(
                capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM).disasm(
                    bytes(text.content)[rel : rel + 4], imp
                )
            )
            if first.mnemonic == "pacibsp":
                out[file_off + 4 : file_off + 12] = MOV_X0_1 + RETAB
            else:
                out[file_off : file_off + 8] = MOV_X0_1 + RET
            patched += 1
    if patched != 4:
        raise RuntimeError(f"esperado 4 patches de getter bool, veio {patched}")
    return bytes(out), patched


def patch_getframe_skip_proof(blob: bytes) -> tuple[bytes, int]:
    """getFrame nao revalida arquivo de licenca a cada 512 frames (isso zera o ready)."""
    out = bytearray(blob)
    patched = 0
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        selref = _selref_for_name(binary, "getFrame")
        if selref is None:
            raise RuntimeError("getFrame sem selref")
        imp = _imp_for_selref(binary, selref)
        if imp is None:
            raise RuntimeError("getFrame sem IMP")
        text = binary.get_section("__text")
        text_va = int(text.virtual_address)
        tb = bytes(text.content)
        rel = imp - text_va
        insns = list(md.disasm(tb[rel : rel + 0x80], imp))
        found = False
        for idx, insn in enumerate(insns[:-1]):
            if insn.mnemonic != "cmp" or len(insn.operands) < 2:
                continue
            if insn.operands[1].type != capstone.arm64.ARM64_OP_IMM:
                continue
            if insn.operands[1].imm != 0x200:
                continue
            nxt = insns[idx + 1]
            if nxt.mnemonic != "b.lt":
                continue
            file_off = _text_file_off(slice_off, binary, nxt.address)
            out[file_off : file_off + 4] = encode_arm64_b(nxt.address, int(nxt.operands[0].imm))
            patched += 1
            found = True
            break
        if not found:
            raise RuntimeError("getFrame sem cmp #0x200 / b.lt do proof")
    if patched != 2:
        raise RuntimeError(f"esperado 2 patches de getFrame skip-proof, veio {patched}")
    return bytes(out), patched


def patch_force_license_ok(blob: bytes) -> tuple[bytes, int]:
    """_avs_chk_actLic nao mostra alerta; sempre retorna autorizado."""
    out = bytearray(blob)
    patched = 0
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        selref = _selref_for_name(binary, "_avs_chk_actLic")
        if selref is None:
            raise RuntimeError("_avs_chk_actLic sem selref")
        imp = _imp_for_selref(binary, selref)
        if imp is None:
            raise RuntimeError("_avs_chk_actLic sem IMP")
        text = binary.get_section("__text")
        rel = imp - int(text.virtual_address)
        first = next(md.disasm(bytes(text.content)[rel : rel + 4], imp))
        file_off = _text_file_off(slice_off, binary, imp)
        if first.mnemonic == "pacibsp":
            out[file_off + 4 : file_off + 12] = MOV_X0_1 + RETAB
        else:
            out[file_off : file_off + 8] = MOV_X0_1 + RET
        patched += 1
    if patched != 2:
        raise RuntimeError(f"esperado 2 patches de chk-actLic, veio {patched}")
    return bytes(out), patched


def patch_kill_remote_io(blob: bytes) -> tuple[bytes, int]:
    """Nao dispara HTTP/WebSocket para o servidor antigo; BL vira mov x0,#0 (nil)."""
    out = bytearray(blob)
    patched = 0
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        stubs: list[int] = []
        missing: list[str] = []
        for name in REMOTE_IO_SELECTORS:
            mva = _exact_methname_va(binary, name)
            selmap = _selref_map(binary)
            if mva is None or mva not in selmap:
                missing.append(name)
                continue
            stub = _stub_va_for_selref(binary, selmap[mva])
            if stub is None:
                missing.append(name)
                continue
            stubs.append(stub)
        if missing:
            raise RuntimeError(f"remote-io sem stub: {missing}")
        stub_set = set(stubs)
        text = binary.get_section("__text")
        text_va = int(text.virtual_address)
        text_file = int(text.offset)
        for insn in md.disasm(bytes(text.content), text_va):
            if insn.mnemonic != "bl":
                continue
            if insn.operands[0].imm not in stub_set:
                continue
            file_off = slice_off + text_file + (insn.address - text_va)
            out[file_off : file_off + 4] = MOV_X0_0
            patched += 1
    if patched < 4:
        raise RuntimeError(f"poucos patches de remote-io ({patched})")
    return bytes(out), patched


def patch_disable_periodic_sync(blob: bytes) -> tuple[bytes, int]:
    """startPeriodicSync nao agenda timer nem HTTP de licenca."""
    out = bytearray(blob)
    patched = 0
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        selref = _selref_for_name(binary, "startPeriodicSync")
        if selref is None:
            raise RuntimeError("startPeriodicSync sem selref")
        imp = _imp_for_selref(binary, selref)
        if imp is None:
            raise RuntimeError("startPeriodicSync sem IMP")
        text = binary.get_section("__text")
        rel = imp - int(text.virtual_address)
        first = next(md.disasm(bytes(text.content)[rel : rel + 4], imp))
        file_off = _text_file_off(slice_off, binary, imp)
        if first.mnemonic == "pacibsp":
            out[file_off + 4 : file_off + 12] = MOV_X0_0 + RETAB
        else:
            out[file_off : file_off + 8] = MOV_X0_0 + RET
        patched += 1
    if patched != 2:
        raise RuntimeError(f"esperado 2 patches de startPeriodicSync, veio {patched}")
    return bytes(out), patched


def _stub_imp_return_1(out: bytearray, slice_off: int, binary, imp: int, md) -> None:
    text = binary.get_section("__text")
    rel = imp - int(text.virtual_address)
    first = next(md.disasm(bytes(text.content)[rel : rel + 4], imp))
    file_off = _text_file_off(slice_off, binary, imp)
    if first.mnemonic == "pacibsp":
        out[file_off + 4 : file_off + 12] = MOV_X0_1 + RETAB
    else:
        out[file_off : file_off + 8] = MOV_X0_1 + RET


def patch_volume_shortcut(blob: bytes) -> tuple[bytes, int]:
    """Atalho volume cima+baixo nao depende mais da prova 0x4204/license.plist."""
    out = bytearray(blob)
    patched = 0
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        selref = _selref_for_name(binary, "_avs_cfg_st")
        if selref is None:
            raise RuntimeError("_avs_cfg_st sem selref no volume-shortcut")
        cfg_stub = _stub_va_for_selref(binary, selref)
        if cfg_stub is None:
            raise RuntimeError("_avs_cfg_st sem stub no volume-shortcut")
        text = binary.get_section("__text")
        text_va = int(text.virtual_address)
        text_file = int(text.offset)
        insns = list(md.disasm(bytes(text.content), text_va))
        found = False
        for idx, insn in enumerate(insns[:-8]):
            if insn.mnemonic != "bl" or insn.operands[0].imm != cfg_stub:
                continue
            cmp_i = None
            for j in range(1, 6):
                cand = insns[idx + j]
                if cand.mnemonic != "cmp" or len(cand.operands) < 2:
                    continue
                if cand.operands[1].type != capstone.arm64.ARM64_OP_IMM:
                    continue
                if cand.operands[1].imm != 4:
                    continue
                cmp_i = idx + j
                break
            if cmp_i is None:
                continue
            beq = insns[cmp_i + 1]
            proof_bl = insns[cmp_i + 2]
            tbz = insns[cmp_i + 3]
            if beq.mnemonic != "b.eq" or proof_bl.mnemonic != "bl" or tbz.mnemonic != "tbz":
                continue
            if tbz.operands[1].imm != 0:
                continue
            file_off = slice_off + text_file + (tbz.address - text_va)
            out[file_off : file_off + 4] = NOP
            patched += 1
            _stub_imp_return_1(out, slice_off, binary, int(proof_bl.operands[0].imm), md)
            patched += 1
            found = True
            break
        if not found:
            raise RuntimeError("nao achei gate do atalho de volume")
    if patched != 4:
        raise RuntimeError(f"esperado 4 patches de volume-shortcut, veio {patched}")
    return bytes(out), patched


def patch_ctor_show_overlay(blob: bytes) -> tuple[bytes, int]:
    """Pula substringToIndex:sysId e grava as flags BSS que o servidor gravaria."""
    out = bytearray(blob)
    patched = 0
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        sys_sel = _selref_for_name(binary, "_avs_cfg_sysId")
        sub_sel = _selref_for_name(binary, "substringToIndex:")
        if sys_sel is None or sub_sel is None:
            raise RuntimeError("selref ausente no ctor-skip")
        sys_stub = _stub_va_for_selref(binary, sys_sel)
        sub_stub = _stub_va_for_selref(binary, sub_sel)
        if sys_stub is None or sub_stub is None:
            raise RuntimeError("stub ausente no ctor-skip")
        text = binary.get_section("__text")
        text_va = int(text.virtual_address)
        insns = list(md.disasm(bytes(text.content), text_va))
        cave_va = None
        cont_va = None
        bss_page = None
        last_adrp_page = None
        for idx, insn in enumerate(insns[:-12]):
            if insn.mnemonic == "adrp":
                last_adrp_page = int(insn.operands[1].imm)
            if (
                insn.mnemonic == "add"
                and len(insn.operands) >= 3
                and insn.operands[2].type == capstone.arm64.ARM64_OP_IMM
                and insn.operands[2].imm == 0x5F0
                and last_adrp_page is not None
                and bss_page is None
            ):
                bss_page = last_adrp_page
            if insn.mnemonic != "bl" or insn.operands[0].imm != sys_stub:
                continue
            mov8 = None
            sub_i = None
            for j in range(1, 8):
                cand = insns[idx + j]
                if (
                    cand.mnemonic == "mov"
                    and len(cand.operands) >= 2
                    and cand.operands[1].type == capstone.arm64.ARM64_OP_IMM
                    and cand.operands[1].imm == 8
                ):
                    mov8 = cand
                if cand.mnemonic == "bl" and cand.operands[0].imm == sub_stub:
                    sub_i = idx + j
                    break
            if mov8 is None or sub_i is None:
                continue
            start_i = idx - 3
            if start_i < 0:
                continue
            if insns[start_i].mnemonic != "adrp" or insns[start_i + 1].mnemonic != "ldr":
                continue
            cave_va = insns[start_i].address
            for k in range(sub_i, min(len(insns) - 1, sub_i + 50)):
                cand = insns[k]
                if cand.mnemonic == "b" and int(cand.operands[0].imm) < cave_va:
                    cont_va = int(cand.operands[0].imm)
                    break
            break
        if cave_va is None or cont_va is None or bss_page is None:
            raise RuntimeError("nao achei cave sysId/substring/bss no ctor")
        seq = [
            encode_arm64_adrp(cave_va, 8, bss_page),
            MOV_W9_1,
            encode_arm64_strb(9, 8, 0x5F0),
            encode_arm64_strb(9, 8, 0xA41),
            encode_arm64_strb(9, 8, 0xB8),
            encode_arm64_strb(9, 8, 0x604),
            encode_arm64_b(cave_va + 24, cont_va),
        ]
        payload = b"".join(seq)
        file_off = _text_file_off(slice_off, binary, cave_va)
        out[file_off : file_off + len(payload)] = payload
        entered = False
        for insn in insns:
            if insn.address >= cave_va:
                break
            if insn.mnemonic != "tbnz":
                continue
            if int(insn.operands[2].imm) != cave_va:
                continue
            if insn.operands[1].imm != 0:
                continue
            gate_off = _text_file_off(slice_off, binary, insn.address)
            out[gate_off : gate_off + 4] = encode_arm64_b(insn.address, cave_va)
            entered = True
            break
        if not entered:
            raise RuntimeError("nao achei tbnz de entrada da cave sysId")
        patched += 1
    if patched != 2:
        raise RuntimeError(f"esperado 2 patches de ctor-skip, veio {patched}")
    return bytes(out), patched


def patch_float_tap_show_panel(blob: bytes) -> tuple[bytes, int]:
    """Tap faz cleanup normal; ignora flag 0x604 e alerta de validade."""
    out = bytearray(blob)
    patched = 0
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        tap_sel = _selref_for_name(binary, "handleButtonTap:")
        if tap_sel is None:
            raise RuntimeError("selref ausente no float-tap")
        tap_imp = _imp_for_selref(binary, tap_sel)
        if tap_imp is None:
            raise RuntimeError("IMP ausente no float-tap")
        text = binary.get_section("__text")
        text_va = int(text.virtual_address)
        tb = bytes(text.content)
        rel = tap_imp - text_va
        insns = list(md.disasm(tb[rel : rel + 0x360], tap_imp))
        noped = 0
        tbnz_i = None
        for idx, insn in enumerate(insns[:-6]):
            if insn.mnemonic != "add" or len(insn.operands) < 3:
                continue
            if insn.operands[2].type != capstone.arm64.ARM64_OP_IMM:
                continue
            if insn.operands[2].imm != 0x604:
                continue
            for j in range(1, 8):
                cand = insns[idx + j]
                if cand.mnemonic == "tbnz" and cand.operands[1].imm == 0:
                    file_off = _text_file_off(slice_off, binary, cand.address)
                    out[file_off : file_off + 4] = NOP
                    patched += 1
                    noped += 1
                    tbnz_i = idx + j
                    break
            break
        if tbnz_i is None:
            raise RuntimeError("float-tap sem tbnz de 0x604")
        for j in range(tbnz_i + 1, min(len(insns), tbnz_i + 8)):
            cand = insns[j]
            if cand.mnemonic == "tbz" and cand.operands[1].imm == 0:
                file_off = _text_file_off(slice_off, binary, cand.address)
                out[file_off : file_off + 4] = NOP
                patched += 1
                noped += 1
                break
        if noped != 2:
            raise RuntimeError(f"float-tap nops incompletos ({noped})")
    if patched != 4:
        raise RuntimeError(f"esperado 4 patches de float-tap, veio {patched}")
    return bytes(out), patched


def _cstr_va(binary, needle: bytes) -> int | None:
    cstr = binary.get_section("__cstring")
    if cstr is None:
        return None
    raw = bytes(cstr.content)
    hit = raw.find(needle + b"\x00")
    if hit < 0:
        return None
    return int(cstr.virtual_address) + hit


def patch_disable_prerender(blob: bytes) -> tuple[bytes, int]:
    """Timer com.avsd.prerender nao agenda Metal/preRender (calor na injecao)."""
    out = bytearray(blob)
    patched = 0
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        cv = _cstr_va(binary, b"com.avsd.prerender")
        if cv is None:
            raise RuntimeError("cstring com.avsd.prerender ausente")
        text = binary.get_section("__text")
        text_va = int(text.virtual_address)
        insns = list(md.disasm(bytes(text.content), text_va))
        adrp: dict[int, int] = {}
        xref_i = None
        for idx, insn in enumerate(insns):
            if insn.mnemonic == "adrp":
                adrp[insn.operands[0].reg] = insn.operands[1].imm
            elif (
                insn.mnemonic == "add"
                and len(insn.operands) >= 3
                and insn.operands[2].type == capstone.arm64.ARM64_OP_IMM
            ):
                base = insn.operands[1].reg if insn.operands[1].type == capstone.arm64.ARM64_OP_REG else None
                if base in adrp and adrp[base] + insn.operands[2].imm == cv:
                    xref_i = idx
                    break
        if xref_i is None:
            raise RuntimeError("xref com.avsd.prerender ausente")
        start_va = None
        for i in range(xref_i, -1, -1):
            cand = insns[i]
            if cand.mnemonic == "stp" and "!" in cand.op_str:
                if i > 0 and insns[i - 1].mnemonic == "pacibsp":
                    start_va = insns[i - 1].address
                else:
                    start_va = cand.address
                break
            if cand.mnemonic == "pacibsp":
                start_va = cand.address
                break
        if start_va is None:
            raise RuntimeError("prologo preRender ausente")
        file_off = _text_file_off(slice_off, binary, start_va)
        first = next(
            md.disasm(
                bytes(text.content)[start_va - text_va : start_va - text_va + 4],
                start_va,
            )
        )
        if first.mnemonic == "pacibsp":
            out[file_off + 4 : file_off + 12] = MOV_X0_0 + RETAB
        else:
            out[file_off : file_off + 4] = RET
        patched += 1
    if patched != 2:
        raise RuntimeError(f"esperado 2 patches de preRender, veio {patched}")
    return bytes(out), patched


def patch_unlock_show_overlay(blob: bytes) -> tuple[bytes, int]:
    """No unlock, nao exige chave/fwE para mostrar o flutuante."""
    out = bytearray(blob)
    patched = 0
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        fh_sel = _selref_for_name(binary, "forceHideOnLock")
        st_sel = _selref_for_name(binary, "_avs_cfg_st")
        bool_sel = _selref_for_name(binary, "boolValue")
        if None in (fh_sel, st_sel, bool_sel):
            raise RuntimeError("selref ausente no unlock-show")
        fh_stub = _stub_va_for_selref(binary, fh_sel)
        st_stub = _stub_va_for_selref(binary, st_sel)
        bool_stub = _stub_va_for_selref(binary, bool_sel)
        if None in (fh_stub, st_stub, bool_stub):
            raise RuntimeError("stub ausente no unlock-show")
        text = binary.get_section("__text")
        text_va = int(text.virtual_address)
        insns = list(md.disasm(bytes(text.content), text_va))
        lock_i = None
        for idx, insn in enumerate(insns[:-40]):
            if insn.mnemonic != "bl" or insn.operands[0].imm != fh_stub:
                continue
            has_st = False
            for j in range(1, 40):
                cand = insns[idx + j]
                if cand.mnemonic == "bl" and cand.operands[0].imm == st_stub:
                    has_st = True
                    break
            if not has_st:
                continue
            lock_i = idx
            break
        if lock_i is None:
            raise RuntimeError("nao achei handler unlock do overlay")
        noped = 0
        bool_i = None
        for j in range(lock_i, min(len(insns) - 2, lock_i + 80)):
            cand = insns[j]
            if cand.mnemonic == "bl" and cand.operands[0].imm == bool_stub:
                bool_i = j
                break
        if bool_i is None:
            raise RuntimeError("boolValue ausente no unlock-show")
        for j in range(bool_i + 1, min(len(insns), bool_i + 6)):
            cand = insns[j]
            if cand.mnemonic == "cbz":
                file_off = _text_file_off(slice_off, binary, cand.address)
                out[file_off : file_off + 4] = NOP
                patched += 1
                noped += 1
                break
        for j in range(bool_i - 1, max(lock_i, bool_i - 8), -1):
            cand = insns[j]
            if cand.mnemonic == "cbz":
                file_off = _text_file_off(slice_off, binary, cand.address)
                out[file_off : file_off + 4] = NOP
                patched += 1
                noped += 1
                break
        if noped != 2:
            raise RuntimeError(f"unlock-show nops incompletos ({noped})")
    if patched != 4:
        raise RuntimeError(f"esperado 4 patches de unlock-show, veio {patched}")
    return bytes(out), patched


LICENSE_PATH = b"/var/jb/Library/KingVCam/license.json\x00"
NOTIFY_NAME = b"com.kingvcam.showgate\x00"


ACTIVATED_NOTIFY = b"com.kingvcam.activated\x00"

MENU_BLOCK_OLD = (
    b"\x00KingVCam \x00 Stream\x00 USB\x00 Gallery\x00 Galeria\x00 Connect\x00 Conectar\x00"
)
MENU_BLOCK_NEW = (
    b"\x00kingvcam.com\x00Stream\x00USB\x00Gallery\x00Galeria\x00Control\x00Controle\x00"
)

VISUAL_STRING_REPLACEMENTS: list[tuple[bytes, bytes]] = [
    (b"Welcome to KingVCam!", b"Welcome kingvcam.com"),
    (b"Bem-vindo ao KingVCam!", b"Acesse kingvcam.com!  "),
    (b"continue using KingVCam.", b"continue at kingvcam.com"),
    (b"KingVCam Server is running on PC", b"kingvcam.com server running PC  "),
    (b"lordvcam.com", b"kingvcam.com"),
    (b"LordVCAM", b"kingvcam"),
    (b"LordVCam", b"kingvcam"),
    (b"lordvcam", b"kingvcam"),
]

VISUAL_UTF16_REPLACEMENTS: list[tuple[str, str]] = [
    ("Bienvenido a KingVCam!", "Visite kingvcam.com!  "),
]


def _pad_replace(old: bytes, new: bytes) -> bytes:
    if len(new) > len(old):
        raise ValueError(f"replace grande demais: {old!r} -> {new!r}")
    return new + (b"\x00" * (len(old) - len(new)))


def patch_visual_branding(blob: bytes) -> tuple[bytes, int]:
    """UI: marca antiga/LordVCAM/KingVCam visivel -> kingvcam.com."""
    out = bytearray(blob)
    count = 0
    if len(MENU_BLOCK_NEW) > len(MENU_BLOCK_OLD):
        raise RuntimeError("menu block novo maior que o original")
    menu_new = _pad_replace(MENU_BLOCK_OLD, MENU_BLOCK_NEW)
    n_menu = out.count(MENU_BLOCK_OLD)
    if n_menu:
        out[:] = bytes(out).replace(MENU_BLOCK_OLD, menu_new)
        count += n_menu
    for old, new in VISUAL_STRING_REPLACEMENTS:
        padded = _pad_replace(old, new)
        n = bytes(out).count(old)
        if n:
            out[:] = bytes(out).replace(old, padded)
            count += n
    for old, new in VISUAL_UTF16_REPLACEMENTS:
        old_b = old.encode("utf-16le")
        new_b = _pad_replace(old_b, new.encode("utf-16le"))
        n = bytes(out).count(old_b)
        if n:
            out[:] = bytes(out).replace(old_b, new_b)
            count += n
    return bytes(out), count


def _patch_imp_return_const(
    out: bytearray, slice_off: int, binary, name: str, value: int
) -> None:
    selref = _selref_for_name(binary, name)
    if selref is None:
        raise RuntimeError(f"{name} sem selref")
    imp = _imp_for_selref(binary, selref)
    if imp is None:
        raise RuntimeError(f"{name} sem IMP")
    file_off = _text_file_off(slice_off, binary, imp)
    text = binary.get_section("__text")
    rel = imp - int(text.virtual_address)
    first = next(
        capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM).disasm(
            bytes(text.content)[rel : rel + 4], imp
        )
    )
    payload = (MOV_X0_1 if value else MOV_X0_0) + RET
    if first.mnemonic == "pacibsp":
        out[file_off + 4 : file_off + 4 + len(payload)] = payload
    else:
        out[file_off : file_off + len(payload)] = payload


def _find_menu_compact_controls_branch(binary) -> tuple[int, int] | None:
    """cbz menuCompact que pula build dos controles da camera em buildMenuContent."""
    stub = _stub_va_for_selref(binary, _selref_for_name(binary, "menuCompact"))
    if stub is None:
        return None
    text = binary.get_section("__text")
    if text is None:
        return None
    tva = int(text.virtual_address)
    tb = bytes(text.content)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    hits: list[tuple[int, int]] = []
    insns = list(md.disasm(tb, tva))
    for idx, insn in enumerate(insns[:-4]):
        if insn.mnemonic != "bl" or insn.operands[0].imm != stub:
            continue
        nxt = insns[idx + 1]
        if nxt.mnemonic == "b":
            hits.append((nxt.address, int(nxt.operands[0].imm)))
            continue
        cbz = nxt
        fmov = insns[idx + 2]
        fadd = insns[idx + 3]
        skip = insns[idx + 4]
        if cbz.mnemonic != "cbz" or not cbz.op_str.startswith("w0,"):
            continue
        if fmov.mnemonic != "fmov" or fadd.mnemonic != "fadd" or skip.mnemonic != "b":
            continue
        if "#8" not in fmov.op_str:
            continue
        target = int(cbz.operands[-1].imm)
        hits.append((cbz.address, target))
    if len(hits) != 1:
        return None
    return hits[0]


def _find_panel_page_switch_gates(binary) -> list[int]:
    """cbz isVisible que impede scroll menu <-> controles da camera."""
    isvis = _stub_va_for_selref(binary, _selref_for_name(binary, "isVisible"))
    if isvis is None:
        raise RuntimeError("isVisible sem stub")
    text = binary.get_section("__text")
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    insns = list(md.disasm(bytes(text.content), int(text.virtual_address)))
    gates: list[int] = []
    for idx, insn in enumerate(insns[:-5]):
        if insn.mnemonic != "bl" or insn.operands[0].imm != isvis:
            continue
        cbz = insns[idx + 1]
        if cbz.mnemonic != "cbz" or not cbz.op_str.startswith("w0,"):
            continue
        window = insns[max(0, idx - 12):idx]
        has_ldrb = any(i.mnemonic == "ldrb" and i.op_str == "w8, [x19, #0x28]" for i in window)
        has_ldr = any(i.mnemonic == "ldr" and i.op_str == "x0, [x19, #0x20]" for i in window)
        if has_ldrb and has_ldr:
            gates.append(cbz.address)
    if len(gates) < 3:
        raise RuntimeError(f"poucos gates de pagina do painel ({len(gates)})")
    return gates


def _find_panel_visible_skip_gates(binary) -> list[int]:
    """cbz panelVisible que pula rebuildPanel apos injecao."""
    stub = _stub_va_for_selref(binary, _selref_for_name(binary, "panelVisible"))
    if stub is None:
        raise RuntimeError("panelVisible sem stub")
    text = binary.get_section("__text")
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    insns = list(md.disasm(bytes(text.content), int(text.virtual_address)))
    rebuild = _stub_va_for_selref(binary, _selref_for_name(binary, "rebuildPanel"))
    gates: list[int] = []
    for idx, insn in enumerate(insns[:-3]):
        if insn.mnemonic != "bl" or insn.operands[0].imm != stub:
            continue
        cbz = insns[idx + 1]
        if cbz.mnemonic != "cbz" or not cbz.op_str.startswith("w0,"):
            continue
        for j in range(idx + 2, min(idx + 5, len(insns))):
            nxt = insns[j]
            if nxt.mnemonic == "bl" and nxt.operands[0].imm == rebuild:
                gates.append(cbz.address)
                break
    if not gates:
        raise RuntimeError("cbz panelVisible antes de rebuildPanel nao encontrado")
    return gates


def patch_panel_show_controls(blob: bytes) -> tuple[bytes, int]:
    """Menu compacto nao pula mais a tela de controles da camera (pos-injecao)."""
    out = bytearray(blob)
    patched = 0
    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        hit = _find_menu_compact_controls_branch(binary)
        if hit is None:
            continue
        cbz_va, target_va = hit
        file_off = _text_file_off(slice_off, binary, cbz_va)
        cur = bytes(out[file_off : file_off + 4])
        want = encode_arm64_b(cbz_va, target_va)
        if cur == want:
            continue
        out[file_off : file_off + 4] = want
        patched += 1
    return bytes(out), patched


def _find_handle_button_tap_gates(binary) -> list[int]:
    """handleButtonTap: nao retorna cedo por hidePnl/isVisible."""
    tap_sel = _selref_for_name(binary, "handleButtonTap:")
    tap_imp = _imp_for_selref(binary, tap_sel) if tap_sel else None
    if tap_imp is None:
        raise RuntimeError("handleButtonTap sem IMP")
    hide_sel = _selref_for_name(binary, "_avs_ov_hidePnl")
    hide_stub = _stub_va_for_selref(binary, hide_sel) if hide_sel else None
    isvis = _stub_va_for_selref(binary, _selref_for_name(binary, "isVisible"))
    if hide_stub is None or isvis is None:
        raise RuntimeError("handleButtonTap stubs ausentes")
    text = binary.get_section("__text")
    text_va = int(text.virtual_address)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    insns = list(md.disasm(bytes(text.content)[tap_imp - text_va : tap_imp - text_va + 0x500], tap_imp))
    gates: list[int] = []
    for idx, insn in enumerate(insns[:-3]):
        if insn.mnemonic != "bl":
            continue
        target = insn.operands[0].imm
        if target == hide_stub:
            for j in range(idx + 1, min(idx + 8, len(insns))):
                cand = insns[j]
                if cand.mnemonic == "cbz" and cand.op_str.startswith("w20,"):
                    gates.append(cand.address)
                    break
        elif target == isvis:
            for j in range(idx + 1, min(idx + 8, len(insns))):
                cand = insns[j]
                if cand.mnemonic == "cbz" and cand.op_str.startswith("w21,"):
                    gates.append(cand.address)
                    break
    if len(gates) < 3:
        raise RuntimeError(f"poucos gates handleButtonTap ({len(gates)})")
    return gates


def patch_unlock_camera_controls(blob: bytes) -> tuple[bytes, int]:
    """Pos-injecao: controles de video e pagina de sliders liberados (sem quebrar flutuante)."""
    out = bytearray(blob)
    patched = 0
    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        for name, val in (
            ("videoControlsVisible", 1),
            ("menuCompact", 0),
            ("panelCompact", 0),
        ):
            _patch_imp_return_const(out, slice_off, binary, name, val)
            patched += 1
        for gate_va in _find_panel_page_switch_gates(binary):
            file_off = _text_file_off(slice_off, binary, gate_va)
            if bytes(out[file_off : file_off + 4]) != NOP:
                out[file_off : file_off + 4] = NOP
                patched += 1
        for gate_va in _find_panel_visible_skip_gates(binary):
            file_off = _text_file_off(slice_off, binary, gate_va)
            if bytes(out[file_off : file_off + 4]) != NOP:
                out[file_off : file_off + 4] = NOP
                patched += 1
        for gate_va in _find_handle_button_tap_gates(binary):
            file_off = _text_file_off(slice_off, binary, gate_va)
            if bytes(out[file_off : file_off + 4]) != NOP:
                out[file_off : file_off + 4] = NOP
                patched += 1
        reb_sel = _selref_for_name(binary, "rebuildPanel")
        reb_imp = _imp_for_selref(binary, reb_sel) if reb_sel else None
        if reb_imp is None:
            raise RuntimeError("rebuildPanel sem IMP")
        text = binary.get_section("__text")
        text_va = int(text.virtual_address)
        tb = bytes(text.content)
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        md.detail = True
        insns = list(md.disasm(tb[reb_imp - text_va : reb_imp - text_va + 0x40], reb_imp))
        pv_stub = _stub_va_for_selref(binary, _selref_for_name(binary, "panelVisible"))
        for idx, insn in enumerate(insns[:-1]):
            if insn.mnemonic != "bl" or insn.operands[0].imm != pv_stub:
                continue
            cbz = insns[idx + 1]
            if cbz.mnemonic == "cbz" and cbz.op_str.startswith("w0,"):
                file_off = _text_file_off(slice_off, binary, cbz.address)
                if bytes(out[file_off : file_off + 4]) != NOP:
                    out[file_off : file_off + 4] = NOP
                    patched += 1
                break
    if patched < 16:
        raise RuntimeError(f"poucos patches unlock-camera-controls ({patched})")
    return bytes(out), patched


def patch_menu_controls_button(blob: bytes) -> tuple[bytes, int]:
    """Opcao A: botao Connect do menu principal abre switchToControls (brilho/zoom)."""
    out = bytearray(blob)
    patched = 0
    label_swaps = [
        (b"\x00 Connect\x00 Conectar\x00", b"\x00 Control\x00 Controle\x00"),
        (b"\x00Connect\x00Conectar\x00", b"\x00Control\x00Controle\x00"),
    ]
    for old_lab, new_lab in label_swaps:
        if len(old_lab) != len(new_lab):
            raise RuntimeError("labels Control/Controle com tamanho diferente")
        n_lab = bytes(out).count(old_lab)
        if n_lab:
            out[:] = bytes(out).replace(old_lab, new_lab)
            patched += n_lab

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    for slice_off, sdata in fat_slices(bytes(out)):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        conn_sel = _selref_for_name(binary, "connectTapped")
        ctrl_sel = _selref_for_name(binary, "switchToControls")
        add_stub = _stub_va_for_selref(
            binary, _selref_for_name(binary, "addTarget:action:forControlEvents:")
        )
        if conn_sel is None or ctrl_sel is None or add_stub is None:
            raise RuntimeError("selrefs Connect/Controls/addTarget ausentes")
        if (conn_sel & ~0xFFF) != (ctrl_sel & ~0xFFF):
            raise RuntimeError("connectTapped e switchToControls em paginas diferentes")
        text = binary.get_section("__text")
        text_va = int(text.virtual_address)
        tb = bytes(text.content)
        last_adr: dict[int, int] = {}
        sites: list[tuple[int, int, int]] = []
        for insn in md.disasm(tb, text_va):
            if insn.mnemonic == "adrp":
                last_adr[insn.operands[0].reg] = int(insn.operands[1].imm)
                continue
            if insn.mnemonic != "ldr" or insn.operands[1].type != capstone.CS_OP_MEM:
                continue
            base = insn.operands[1].mem.base
            if base not in last_adr:
                continue
            if last_adr[base] + insn.operands[1].mem.disp != conn_sel:
                continue
            off = insn.address - text_va
            ahead = list(md.disasm(tb[off : off + 0x40], insn.address))
            if not any(
                a.mnemonic == "bl" and a.operands[0].imm == add_stub for a in ahead[:12]
            ):
                continue
            rt_name = md.reg_name(insn.operands[0].reg)
            rn_name = md.reg_name(base)
            if not (rt_name.startswith("x") and rn_name.startswith("x")):
                continue
            sites.append((insn.address, int(rt_name[1:]), int(rn_name[1:])))
        if len(sites) < 2:
            raise RuntimeError(f"poucos wires connectTapped no menu ({len(sites)})")
        ctrl_disp = ctrl_sel & 0xFFF
        for va, rt, rn in sites:
            file_off = _text_file_off(slice_off, binary, va)
            want = encode_arm64_ldr64(rt, rn, ctrl_disp)
            if bytes(out[file_off : file_off + 4]) == want:
                continue
            out[file_off : file_off + 4] = want
            patched += 1
    if patched < 6:
        raise RuntimeError(f"poucos patches menu-controls-button ({patched})")
    return bytes(out), patched


def encode_arm64_movz(rd: int, imm16: int, hw: int = 0, is64: bool = True) -> bytes:
    base = 0xD2800000 if is64 else 0x52800000
    return struct.pack("<I", base | (hw << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F))


def encode_arm64_movk(rd: int, imm16: int, hw: int = 0, is64: bool = True) -> bytes:
    base = 0xF2800000 if is64 else 0x72800000
    return struct.pack("<I", base | (hw << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F))


def patch_license_live_revalidate(blob: bytes) -> tuple[bytes, int]:
    """Volume/flutuante sempre revalidam via notify + wait (revogacao imediata)."""
    out = bytearray(blob)
    patched = 0
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    vol_entry = 0x3B21C
    float_entry = 0x3B268
    revalidate_va = 0x3B2A0
    revalidate_limit = 0x3B360
    orig_sub = 0xBB3D0
    vol_ok = 0x67E0
    vol_block = 0x67C8
    bss_page = 0x155000
    str_page = 0x93000
    showgate_off = 0x46E
    activated_off = 0x484

    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        text = binary.get_section("__text")
        text_va = int(text.virtual_address)
        tb = bytes(out[slice_off + int(text.offset) : slice_off + int(text.offset) + int(text.size)])
        gate_probe = list(md.disasm(tb[vol_entry - text_va : vol_entry - text_va + 8], vol_entry))
        if not gate_probe or gate_probe[0].mnemonic != "stp":
            continue

        notify_post = _imported_stub(binary, "_notify_post")
        notify_get = _imported_stub(binary, "_notify_get_state")
        usleep_stub = _imported_stub(binary, "_usleep")

        pos = out.find(LICENSE_PATH, slice_off)
        if pos < 0:
            raise RuntimeError("license path ausente no slice")
        act_off = pos + len(LICENSE_PATH) + len(NOTIFY_NAME)
        out[act_off : act_off + len(ACTIVATED_NOTIFY)] = ACTIVATED_NOTIFY
        pc = revalidate_va
        seq: list[bytes] = []

        def emit(raw: bytes) -> None:
            nonlocal pc
            seq.append(raw)
            pc += 4

        emit(struct.pack("<I", 0xD10083FF))  # sub sp,sp,#0x20
        emit(struct.pack("<I", 0xF9000BE8))  # str x8,[sp,#0x10] (scratch)
        emit(struct.pack("<I", 0xF90013FE))  # str x30,[sp,#0x18]
        emit(encode_arm64_adrp(pc, 20, str_page))
        emit(encode_arm64_add_imm(0, 20, showgate_off))
        emit(encode_arm64_bl(pc, notify_post))
        emit(encode_arm64_movz(19, 150, is64=False))
        loop_pc = pc
        emit(encode_arm64_add_imm(0, 20, activated_off))
        emit(encode_arm64_add_imm(1, 31, 0))
        emit(encode_arm64_bl(pc, notify_get))
        emit(encode_arm64_ldr64(9, 31, 0))
        cbnz_idx, cbnz_pc = len(seq), pc
        emit(bytes(4))
        emit(encode_arm64_movz(0, 0x86A0))
        emit(encode_arm64_movk(0, 1, hw=1))
        emit(encode_arm64_bl(pc, usleep_stub))
        emit(struct.pack("<I", 0x71000673))  # subs w19,w19,#1
        emit(encode_arm64_b(pc, loop_pc))
        fail_pc = pc
        emit(struct.pack("<I", 0x52800000))  # mov w0,#0
        b_done_idx, b_done_pc = len(seq), pc
        emit(bytes(4))
        ok_pc = pc
        emit(struct.pack("<I", 0x52800020))  # mov w0,#1
        done_pc = pc
        seq[b_done_idx] = encode_arm64_b(b_done_pc, done_pc)
        seq[cbnz_idx] = encode_arm64_cbz(cbnz_pc, 9, ok_pc, is64=True, cbnz=True)
        emit(struct.pack("<I", 0xF94013FE))  # ldr x30,[sp,#0x18]
        emit(struct.pack("<I", 0x910083FF))  # add sp,sp,#0x20
        emit(RET)

        revalidate_payload = b"".join(seq)
        if revalidate_va + len(revalidate_payload) > revalidate_limit:
            raise RuntimeError(f"live-revalidate cave grande demais: {len(revalidate_payload)}")

        vseq: list[bytes] = []
        vpc = vol_entry

        def vemit(raw: bytes) -> None:
            nonlocal vpc
            vseq.append(raw)
            vpc += 4

        vemit(struct.pack("<I", 0xA9BC7BFD))
        vemit(struct.pack("<I", 0x910003FD))
        vemit(struct.pack("<I", 0xA90107E0))
        vemit(struct.pack("<I", 0xF90013E8))
        vemit(encode_arm64_bl(vpc, revalidate_va))
        cbz_idx, cbz_pc = len(vseq), vpc
        vemit(bytes(4))
        vemit(encode_arm64_adrp(vpc, 8, bss_page))
        vemit(struct.pack("<I", 0x52800029))
        vemit(encode_arm64_strb(9, 8, 0xB8))
        vemit(encode_arm64_strb(9, 8, 0x604))
        vemit(struct.pack("<I", 0xA94107E0))
        vemit(struct.pack("<I", 0xF94013E8))
        vemit(struct.pack("<I", 0xA8C47BFD))
        vemit(encode_arm64_bl(vpc, orig_sub))
        vemit(encode_arm64_b(vpc, vol_ok))
        fail_pc = vpc
        vseq[cbz_idx] = encode_arm64_cbz(cbz_pc, 0, fail_pc, is64=False)
        vemit(struct.pack("<I", 0xA94107E0))
        vemit(struct.pack("<I", 0xF94013E8))
        vemit(struct.pack("<I", 0xA8C47BFD))
        vemit(encode_arm64_b(vpc, vol_block))

        fseq: list[bytes] = []
        fpc = float_entry

        def femit(raw: bytes) -> None:
            nonlocal fpc
            fseq.append(raw)
            fpc += 4

        femit(struct.pack("<I", 0xA9BC7BFD))
        femit(struct.pack("<I", 0x910003FD))
        femit(struct.pack("<I", 0xA90107E0))
        femit(struct.pack("<I", 0xF90013E8))
        femit(encode_arm64_bl(fpc, revalidate_va))
        fcbz_idx, fcbz_pc = len(fseq), fpc
        femit(bytes(4))
        femit(struct.pack("<I", 0xA94107E0))
        femit(struct.pack("<I", 0xF94013E8))
        femit(struct.pack("<I", 0xA8C47BFD))
        femit(RET)
        ffail_pc = fpc
        fseq[fcbz_idx] = encode_arm64_cbz(fcbz_pc, 0, ffail_pc, is64=False)
        femit(struct.pack("<I", 0xA94107E0))
        femit(struct.pack("<I", 0xF94013E8))
        femit(struct.pack("<I", 0xA8C47BFD))
        femit(RET)

        vol_off = _text_file_off(slice_off, binary, vol_entry)
        out[vol_off : vol_off + len(b"".join(vseq))] = b"".join(vseq)
        float_off = _text_file_off(slice_off, binary, float_entry)
        out[float_off : float_off + len(b"".join(fseq))] = b"".join(fseq)
        rev_off = _text_file_off(slice_off, binary, revalidate_va)
        out[rev_off : rev_off + len(revalidate_payload)] = revalidate_payload

        found_bl = False
        for insn in md.disasm(tb, text_va):
            if insn.mnemonic == "bl" and int(insn.operands[0].imm) == 0x3B294:
                bl_off = _text_file_off(slice_off, binary, insn.address)
                out[bl_off : bl_off + 4] = encode_arm64_bl(insn.address, float_entry)
                found_bl = True
                break
        if not found_bl:
            raise RuntimeError("bl float-gate 0x3b294 nao encontrado")
        patched += 2
    if patched == 0:
        raise RuntimeError("nenhum slice com inline license gate")
    return bytes(out), patched


def patch_license_file_gate(blob: bytes) -> tuple[bytes, int]:
    """Ctor checa license.json; volume/float sem licenca mostram gate."""
    out = bytearray(blob)
    patched = 0
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    for slice_off, sdata in fat_slices(blob):
        parsed = lief.parse(sdata)
        binary = parsed.at(0) if hasattr(parsed, "at") else parsed
        bss = _bss_page(binary, md)
        open_stub = _imported_stub(binary, "_open")
        close_stub = _imported_stub(binary, "_close")
        notify_stub = _imported_stub(binary, "_notify_post")

        tg_sel = _selref_for_name(binary, "openTelegramChannel")
        tg_imp = _imp_for_selref(binary, tg_sel) if tg_sel else None
        if tg_imp is None:
            raise RuntimeError("openTelegramChannel ausente")
        str_va = tg_imp + TELEGRAM_STR_CAVE
        str_data = LICENSE_PATH + NOTIFY_NAME
        str_off = _text_file_off(slice_off, binary, str_va)
        out[str_off : str_off + len(str_data)] = str_data
        path_va = str_va
        notify_va = str_va + len(LICENSE_PATH)

        sps_cave, sps_limit = _sps_http_cave(binary, md)
        pc = sps_cave
        seq: list[bytes] = []

        def emit(raw: bytes) -> None:
            nonlocal pc
            seq.append(raw)
            pc += 4

        emit(struct.pack("<I", 0xA9BF7BFD))
        emit(struct.pack("<I", 0x910003FD))
        emit(encode_arm64_adrp(pc, 0, path_va & ~0xFFF))
        emit(encode_arm64_add_imm(0, 0, path_va & 0xFFF))
        emit(struct.pack("<I", 0x52800001))
        emit(encode_arm64_bl(pc, open_stub))
        emit(struct.pack("<I", 0x7100001F))
        blt_idx, blt_pc = len(seq), pc
        emit(bytes(4))
        emit(encode_arm64_bl(pc, close_stub))
        emit(encode_arm64_adrp(pc, 8, bss))
        emit(struct.pack("<I", 0x52800029))
        emit(encode_arm64_strb(9, 8, 0x5F0))
        emit(encode_arm64_strb(9, 8, 0xA41))
        emit(encode_arm64_strb(9, 8, 0xB8))
        emit(encode_arm64_strb(9, 8, 0x604))
        emit(struct.pack("<I", 0xA8C17BFD))
        emit(RET)
        no_lic_pc = pc
        seq[blt_idx] = struct.pack("<I", 0x5400000B | (((no_lic_pc - blt_pc) >> 2) << 5))
        emit(encode_arm64_adrp(pc, 8, bss))
        emit(struct.pack("<I", 0x52800029))
        emit(encode_arm64_strb(9, 8, 0x5F0))
        emit(encode_arm64_strb(9, 8, 0xA41))
        emit(encode_arm64_strb(31, 8, 0xB8))
        emit(encode_arm64_strb(31, 8, 0x604))
        emit(struct.pack("<I", 0xA8C17BFD))
        emit(RET)

        check_payload = b"".join(seq)
        if len(check_payload) > sps_limit - sps_cave:
            raise RuntimeError(f"check_license {len(check_payload)} > {sps_limit - sps_cave}")
        check_off = _text_file_off(slice_off, binary, sps_cave)
        out[check_off : check_off + len(check_payload)] = check_payload

        text = binary.get_section("__text")
        text_va = int(text.virtual_address)
        tb = bytes(out[slice_off + int(text.offset) : slice_off + int(text.offset) + int(text.size)])
        insns = list(md.disasm(tb, text_va))
        ctor_cave = None
        ctor_b_target = None
        for idx, insn in enumerate(insns[:-6]):
            if insn.mnemonic != "adrp":
                continue
            page = int(insn.operands[1].imm)
            if page != bss:
                continue
            if idx + 6 >= len(insns):
                continue
            if insns[idx + 1].mnemonic != "mov":
                continue
            if not any(
                insns[idx + j].mnemonic == "strb"
                and insns[idx + j].operands[1].type == capstone.arm64.ARM64_OP_MEM
                and insns[idx + j].operands[1].mem.disp == 0x5F0
                for j in range(2, 6)
            ):
                continue
            last = insns[idx + 6]
            if last.mnemonic != "b":
                continue
            ctor_cave = insn.address
            ctor_b_target = int(last.operands[0].imm)
            break
        if ctor_cave is None:
            raise RuntimeError("ctor cave nao encontrada para license gate")
        ctor_payload = encode_arm64_bl(ctor_cave, sps_cave) + encode_arm64_b(ctor_cave + 4, ctor_b_target)
        ctor_off = _text_file_off(slice_off, binary, ctor_cave)
        out[ctor_off : ctor_off + 28] = ctor_payload + NOP * 5

        vol = _volume_handler_entry(binary, md)
        vol_tb = bytes(out[slice_off + int(text.offset) : slice_off + int(text.offset) + int(text.size)])
        vol_insns = list(md.disasm(vol_tb[vol - text_va : vol - text_va + 0x300], vol))
        vol_tbnz = None
        for insn in vol_insns:
            if insn.mnemonic == "tbnz" and insn.operands[1].imm == 0:
                vol_tbnz = insn
                break
        if vol_tbnz is None:
            raise RuntimeError("volume sem tbnz")
        vol_jump_target = int(vol_tbnz.operands[2].imm)
        vt_insns = list(md.disasm(vol_tb[vol_jump_target - text_va : vol_jump_target - text_va + 8], vol_jump_target))
        if len(vt_insns) < 2 or vt_insns[0].mnemonic != "bl":
            raise RuntimeError("volume target nao e bl")
        orig_sub = int(vt_insns[0].operands[0].imm)
        vol_b_back = vt_insns[1].address
        epi_scan = list(md.disasm(vol_tb[vol - text_va : vol_jump_target + 0x20 - text_va], vol))
        vol_epilogue = None
        for i in range(len(epi_scan) - 1, -1, -1):
            if epi_scan[i].mnemonic in ("ret", "retab") and epi_scan[i].address < vol_jump_target:
                for j in range(i - 1, max(0, i - 5), -1):
                    if epi_scan[j].mnemonic == "ldp" and "x29" in epi_scan[j].op_str:
                        vol_epilogue = epi_scan[j].address
                        break
                if vol_epilogue:
                    break
        if vol_epilogue is None:
            raise RuntimeError("volume epilogue ausente")

        vol_gate_cave = sps_cave + len(check_payload)
        vgpc = vol_gate_cave
        vgseq: list[bytes] = []

        def vgemit(raw: bytes) -> None:
            nonlocal vgpc
            vgseq.append(raw)
            vgpc += 4

        vgemit(struct.pack("<I", 0xA9BF7BFD))
        vgemit(struct.pack("<I", 0x910003FD))
        vgemit(encode_arm64_adrp(vgpc, 8, bss))
        vgemit(encode_arm64_ldrb(9, 8, 0x604))
        cbz_idx, cbz_pc = len(vgseq), vgpc
        vgemit(bytes(4))
        vgemit(struct.pack("<I", 0xA8C17BFD))
        vgemit(encode_arm64_bl(vgpc, orig_sub))
        vgemit(encode_arm64_b(vgpc, vol_b_back))
        no_key_pc = vgpc
        vgseq[cbz_idx] = encode_arm64_cbz(cbz_pc, 9, no_key_pc, is64=False)
        vgemit(struct.pack("<I", 0xA8C17BFD))
        vgemit(encode_arm64_adrp(vgpc, 0, notify_va & ~0xFFF))
        vgemit(encode_arm64_add_imm(0, 0, notify_va & 0xFFF))
        vgemit(struct.pack("<I", 0xA9BF7BFD))
        vgemit(struct.pack("<I", 0x910003FD))
        vgemit(encode_arm64_bl(vgpc, notify_stub))
        vgemit(struct.pack("<I", 0xA8C17BFD))
        vgemit(encode_arm64_b(vgpc, vol_epilogue))
        vol_gate_payload = b"".join(vgseq)
        vol_gate_end = vol_gate_cave + len(vol_gate_payload)
        if vol_gate_end > sps_limit:
            raise RuntimeError("vol gate cave nao cabe")
        vol_gate_off = _text_file_off(slice_off, binary, vol_gate_cave)
        out[vol_gate_off : vol_gate_off + len(vol_gate_payload)] = vol_gate_payload
        vol_bl_off = _text_file_off(slice_off, binary, vol_jump_target)
        out[vol_bl_off : vol_bl_off + 4] = encode_arm64_b(vol_jump_target, vol_gate_cave)
        patched += 1

        float_notify_cave = vol_gate_end
        fnpc = float_notify_cave
        fnseq: list[bytes] = []

        def fnemit(raw: bytes) -> None:
            nonlocal fnpc
            fnseq.append(raw)
            fnpc += 4

        fnemit(struct.pack("<I", 0xA9BF7BFD))
        fnemit(struct.pack("<I", 0x910003FD))
        fnemit(encode_arm64_adrp(fnpc, 8, bss))
        fnemit(encode_arm64_ldrb(9, 8, 0x604))
        cbnz_idx, cbnz_pc = len(fnseq), fnpc
        fnemit(bytes(4))
        fnemit(encode_arm64_adrp(fnpc, 0, notify_va & ~0xFFF))
        fnemit(encode_arm64_add_imm(0, 0, notify_va & 0xFFF))
        fnemit(encode_arm64_bl(fnpc, notify_stub))
        ret_pc = fnpc
        fnemit(struct.pack("<I", 0xA8C17BFD))
        fnemit(RET)
        fnseq[cbnz_idx] = encode_arm64_cbz(cbnz_pc, 9, ret_pc, is64=False, cbnz=True)
        float_notify_payload = b"".join(fnseq)
        if float_notify_cave + len(float_notify_payload) > sps_limit:
            raise RuntimeError("float notify cave nao cabe")
        fn_off = _text_file_off(slice_off, binary, float_notify_cave)
        out[fn_off : fn_off + len(float_notify_payload)] = float_notify_payload

        tap_sel = _selref_for_name(binary, "handleButtonTap:")
        tap_imp = _imp_for_selref(binary, tap_sel) if tap_sel else None
        if tap_imp is None:
            raise RuntimeError("handleButtonTap ausente")
        tap_tb = bytes(out[slice_off + int(text.offset) : slice_off + int(text.offset) + int(text.size)])
        tap_insns = list(md.disasm(tap_tb[tap_imp - text_va : tap_imp - text_va + 0x360], tap_imp))
        tap_tbnz_i = None
        for idx2, insn in enumerate(tap_insns[:-6]):
            if insn.mnemonic != "add" or len(insn.operands) < 3:
                continue
            if insn.operands[2].type != capstone.arm64.ARM64_OP_IMM or insn.operands[2].imm != 0x604:
                continue
            for j in range(1, 8):
                cand = tap_insns[idx2 + j]
                if cand.mnemonic == "tbnz" and cand.operands[1].imm == 0:
                    tap_tbnz_i = idx2 + j
                    break
            break
        if tap_tbnz_i is None:
            raise RuntimeError("float-tap sem tbnz de 0x604")
        bl_verif = tap_insns[tap_tbnz_i + 1]
        if bl_verif.mnemonic != "bl":
            raise RuntimeError("float-tap esperado bl")
        tap_bl_off = _text_file_off(slice_off, binary, bl_verif.address)
        out[tap_bl_off : tap_bl_off + 4] = encode_arm64_bl(bl_verif.address, float_notify_cave)
        patched += 1
        patched += 1
    if patched != 6:
        raise RuntimeError(f"esperado 6 patches de license-file-gate, veio {patched}")
    return bytes(out), patched


def write_control(dest: Path) -> None:
    text = "\n".join(
        [
            "Package: com.apple.avservicesd.rootless",
            f"Name: {PACKAGE_DISPLAY_NAME}",
            "Depends: mobilesubstrate | ellekit | libhooker | substitute",
            f"Version: {NEW_VERSION}",
            "Architecture: iphoneos-arm64",
            "Section: Tweaks",
            "Description: KingVCam virtual camera - palera1n rootless / Dopamine 1 (arm64)",
            "Maintainer: KingVCam",
            "Author: KingVCam",
            "Icon: file:///var/jb/Library/KingVCam/icon.png",
            "",
        ]
    )
    dest.write_text(text, encoding="utf-8", newline="\n")


def clone_tree() -> Path:
    if not (EXTRACTED / "control").exists() or not (EXTRACTED / "data").exists():
        raise FileNotFoundError("Rode scripts/extract-deb.py antes.")
    if REPACK.exists():
        shutil.rmtree(REPACK)
    REPACK.mkdir(parents=True)
    shutil.copytree(EXTRACTED / "control", REPACK / "control")
    shutil.copytree(EXTRACTED / "data", REPACK / "data")
    write_control(REPACK / "control" / "control")
    if not ICON_SRC.is_file():
        raise FileNotFoundError(f"icone nao encontrado: {ICON_SRC}")
    icon_dest = REPACK / ICON_REL
    icon_dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ICON_SRC, icon_dest)
    dylib = REPACK / DYLIB_REL
    patched, log = patch_bytes(dylib.read_bytes())
    dylib.write_bytes(patched)
    gate_dest = REPACK / GATE_REL
    gate_dest.mkdir(parents=True, exist_ok=True)
    if GATE_DYLIB.is_file():
        shutil.copy2(GATE_DYLIB, gate_dest / "KingVCamGate.dylib")
        shutil.copy2(GATE_PLIST, gate_dest / "KingVCamGate.plist")
        log.append("gate-dylib copied")
    else:
        raise FileNotFoundError(f"KingVCamGate.dylib ausente: {GATE_DYLIB}")
    (REPACK / "PATCHLOG.txt").write_text("\n".join(log) + "\n", encoding="utf-8")
    return dylib


def tarinfo_base(name: str, size: int, mode: int, is_dir: bool) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = 0 if is_dir else size
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = int(time.time())
    info.type = tarfile.DIRTYPE if is_dir else tarfile.REGTYPE
    return info


def make_control_tar() -> bytes:
    buf = io.BytesIO()
    control_dir = REPACK / "control"
    files = [
        ("./control", 0o644),
        ("./postinst", 0o755),
        ("./postrm", 0o755),
    ]
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.addfile(tarinfo_base(".", 0, 0o755, True))
        for arcname, mode in files:
            path = control_dir / Path(arcname).name
            data = path.read_bytes().replace(b"\r\n", b"\n")
            info = tarinfo_base(arcname, len(data), mode, False)
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), mtime=0)


def make_data_tar() -> bytes:
    data_root = REPACK / "data"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.addfile(tarinfo_base(".", 0, 0o755, True))
        dirs: list[Path] = []
        files: list[Path] = []
        for path in sorted(data_root.rglob("*")):
            if path.is_dir():
                dirs.append(path)
            elif path.is_file():
                files.append(path)
        for path in dirs:
            arc = path.relative_to(data_root).as_posix()
            tar.addfile(tarinfo_base(arc, 0, 0o755, True))
        for path in files:
            arc = path.relative_to(data_root).as_posix()
            mode = 0o755 if path.suffix == ".dylib" else 0o644
            data = path.read_bytes()
            info = tarinfo_base(arc, len(data), mode, False)
            tar.addfile(info, io.BytesIO(data))
    return lzma.compress(buf.getvalue(), format=lzma.FORMAT_ALONE, preset=9)


def ar_header(name: str, size: int, mode: int = 0o100644) -> bytes:
    name_f = name.encode("ascii")
    if len(name_f) > 16:
        raise ValueError(f"nome ar longo: {name}")
    header = (
        name_f.ljust(16)
        + b"0".ljust(12)
        + b"0".ljust(6)
        + b"0".ljust(6)
        + f"{mode:o}".encode("ascii").ljust(8)
        + str(size).encode("ascii").ljust(10)
        + b"`\n"
    )
    if len(header) != 60:
        raise ValueError("header ar invalido")
    return header


def make_deb(control_tar: bytes, data_tar: bytes) -> bytes:
    debian_binary = b"2.0\n"
    members = [
        ("debian-binary", debian_binary),
        ("control.tar.gz", control_tar),
        ("data.tar.lzma", data_tar),
    ]
    out = bytearray(b"!<arch>\n")
    for name, payload in members:
        out += ar_header(name, len(payload))
        out += payload
        if len(payload) % 2 == 1:
            out += b"\n"
    return bytes(out)


def main() -> int:
    dylib = clone_tree()
    DIST.mkdir(parents=True, exist_ok=True)
    deb_name = f"com.apple.avservicesd.rootless_{NEW_VERSION}_iphoneos-arm64.deb"
    deb_path = DIST / deb_name
    deb_path.write_bytes(make_deb(make_control_tar(), make_data_tar()))
    print(f"OK: dylib {dylib} ({dylib.stat().st_size} bytes)")
    print(f"OK: {deb_path} ({deb_path.stat().st_size} bytes)")
    print((REPACK / "PATCHLOG.txt").read_text(encoding="utf-8").rstrip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
