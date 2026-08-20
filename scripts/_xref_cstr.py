#!/usr/bin/env python3
import struct
import sys
from pathlib import Path

import capstone
import lief

needle = sys.argv[1].encode()
path = Path(r"C:/kingvcamios/repack/data/var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.dylib")
data = path.read_bytes()
_cpu, _sub, offset, size, _a = struct.unpack(">IIIII", data[8:28])
sdata = data[offset : offset + size]
binary = lief.parse(sdata)
binary = binary.at(0) if hasattr(binary, "at") else binary
cstr = binary.get_section("__cstring")
raw = bytes(cstr.content)
cva = int(cstr.virtual_address)
hit = raw.find(needle + b"\x00")
if hit < 0:
    print("not found")
    raise SystemExit(1)
va = cva + hit
print("va", hex(va), raw[hit : hit + 64])
text = binary.get_section("__text")
tb = bytes(text.content)
tva = int(text.virtual_address)
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True
adrp: dict[int, int] = {}
for insn in md.disasm(tb, tva):
    if insn.mnemonic == "adrp":
        adrp[insn.operands[0].reg] = int(insn.operands[1].imm)
    elif insn.mnemonic == "add" and len(insn.operands) >= 3:
        base = insn.operands[1].reg
        if base in adrp and insn.operands[2].type == capstone.arm64.ARM64_OP_IMM:
            if adrp[base] + int(insn.operands[2].imm) == va:
                print("xref add", hex(insn.address))
