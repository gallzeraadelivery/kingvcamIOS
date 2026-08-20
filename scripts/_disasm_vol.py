import capstone, lief, struct
blob = open('extracted/data/var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.dylib','rb').read()
off8 = 8
_cpu, _sub, offset, size, _align = struct.unpack('>IIIII', blob[off8:off8+20])
sdata = blob[offset:offset+size]
parsed = lief.parse(sdata)
binary = parsed.at(0) if hasattr(parsed,'at') else parsed
text = binary.get_section('__text')
tva = int(text.virtual_address)
tb = bytes(text.content)
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

# Find volume handler: sub sp, sp, #0x60 followed by add with 0x5f0
insns = list(md.disasm(tb, tva))
for i, insn in enumerate(insns):
    if insn.mnemonic != 'sub' or 'sp, sp, #0x60' not in insn.op_str:
        continue
    ok = False
    for j in range(i+1, min(i+9, len(insns))):
        cand = insns[j]
        if cand.mnemonic == 'add' and len(cand.operands) >= 3:
            if cand.operands[2].type == capstone.arm64.ARM64_OP_IMM and cand.operands[2].imm == 0x5F0:
                ok = True; break
    if not ok:
        continue
    start = insns[i-1].address if i > 0 and insns[i-1].mnemonic == 'pacibsp' else insn.address
    print(f'Volume handler: {start:#x}')
    # Print 80 insns
    for insn2 in insns[i-1:i+79]:
        print(f'{insn2.address:#x}: {insn2.mnemonic} {insn2.op_str}')
    break
