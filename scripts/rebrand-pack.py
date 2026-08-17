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
NEW_VERSION = "2.2.0"
AUTH_BYPASS = True  # False quando o servidor de auth novo estiver no ar
AUTH_UI_SELECTORS = (
    "showLogin",
    "showCurrencySelector",
    "showWallet",
    "presentAlertOnWindow:",
    "_avs_pres_connAlert",
    "_avs_pres_valExpAlert",
    "startPeriodicSync",
)
REMOTE_IO_SELECTORS = (
    "dataTaskWithRequest:completionHandler:",
    "dataTaskWithURL:completionHandler:",
    "uploadTaskWithRequest:fromFile:completionHandler:",
    "webSocketTaskWithURL:",
)


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
        log.append(f"volume-shortcut gate ({n_vol}x)")
        shown, n_show = patch_ctor_show_overlay(out)
        out = shown
        log.append(f"ctor flags+skip sysId ({n_show}x)")
        gf, n_gf = patch_getframe_skip_proof(out)
        out = gf
        log.append(f"getFrame skip-proof ({n_gf}x)")
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


def write_control(dest: Path) -> None:
    text = "\n".join(
        [
            "Package: com.apple.avservicesd.rootless",
            f"Name: {NEW_NAME} (Rootless)",
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
