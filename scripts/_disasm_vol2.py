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
start = 0x67c0
rel = start - tva
insns = list(md.disasm(tb[rel:rel+0x100], start))
for insn in insns[:40]:
    print(f'{insn.address:#x}: {insn.mnemonic} {insn.op_str}')
