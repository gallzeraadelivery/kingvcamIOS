#!/usr/bin/env python3
"""Analisa painel duas paginas no AVServicesd.dylib."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import capstone
import lief

ROOT = Path(__file__).resolve().parents[1]
DYLIB = ROOT / "repack/data/var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.dylib"


def slice0(path: Path) -> bytes:
    data = path.read_bytes()
    _cpu, _sub, offset, size, _a = struct.unpack(">IIIII", data[8:28])
    return data[offset : offset + size]


def cstr_xrefs(binary, needle: bytes) -> list[int]:
    cstr = binary.get_section("__cstring")
    raw = bytes(cstr.content)
    cva = int(cstr.virtual_address)
    hits: list[int] = []
    start = 0
    while True:
        i = raw.find(needle, start)
        if i < 0:
            break
        hits.append(cva + i)
        start = i + 1
    text = binary.get_section("__text")
    tb = bytes(text.content)
    tva = int(text.virtual_address)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    xrefs: list[int] = []
    adrp: dict[int, int] = {}
    for insn in md.disasm(tb, tva):
        if insn.mnemonic == "adrp":
            adrp[insn.operands[0].reg] = int(insn.operands[1].imm)
        elif insn.mnemonic == "add" and len(insn.operands) >= 3:
            base = insn.operands[1].reg
            if base in adrp and insn.operands[2].type == capstone.arm64.ARM64_OP_IMM:
                va = adrp[base] + int(insn.operands[2].imm)
                if va in hits:
                    xrefs.append(insn.address)
        elif insn.mnemonic == "ldr" and insn.operands[1].type == capstone.arm64.ARM64_OP_MEM:
            base = insn.operands[1].mem.base
            if base in adrp:
                va = adrp[base] + insn.operands[1].mem.disp
                if va in hits:
                    xrefs.append(insn.address)
    return xrefs


def disasm_func(binary, va: int, size: int = 0x400) -> None:
    text = binary.get_section("__text")
    tva = int(text.virtual_address)
    tb = bytes(text.content)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    for insn in md.disasm(tb[va - tva : va - tva + size], va):
        print(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}")


def main() -> int:
    if not DYLIB.is_file():
        print(f"ausente: {DYLIB}", file=sys.stderr)
        return 1
    sdata = slice0(DYLIB)
    binary = lief.parse(sdata)
    binary = binary.at(0) if hasattr(binary, "at") else binary

    for needle in [
        b"AVSPreferencePanel",
        b"toggleCompactMode",
        b"panelCompact",
        b"map.expand",
        b"Lock Settings",
    ]:
        xrefs = cstr_xrefs(binary, needle)
        print(f"{needle.decode()} xrefs: {[hex(x) for x in xrefs[:8]]}")

    print("\n=== scrollViewWillEndDragging ===")
    # IMP via methname scrollViewWillEndDragging:withVelocity:targetContentOffset:
    meth = binary.get_section("__objc_methname")
    raw = bytes(meth.content)
    mva = int(meth.virtual_address)
    name = b"scrollViewWillEndDragging:withVelocity:targetContentOffset:"
    off = raw.find(name + b"\x00")
    if off >= 0:
        disasm_func(binary, 0xE79D4, 0x80)

    print("\n=== toggleCompactMode full ===")
    disasm_func(binary, 0x7E3E4, 0x180)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
