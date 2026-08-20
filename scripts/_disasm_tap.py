import capstone, lief, struct, sys
blob = open('extracted/data/var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.dylib','rb').read()
magic = struct.unpack('>I', blob[:4])[0]
off8 = 8
_cpu, _sub, offset, size, _align = struct.unpack('>IIIII', blob[off8:off8+20])
sdata = blob[offset:offset+size]
parsed = lief.parse(sdata)
binary = parsed.at(0) if hasattr(parsed,'at') else parsed
meth = binary.get_section('__objc_methname')
raw = bytes(meth.content)
mva = int(meth.virtual_address)
needle = b'\x00handleButtonTap:\x00'
hit = raw.find(needle)
name_va = mva + hit + 1
sel_sec = binary.get_section('__objc_selrefs')
sel_lo = int(sel_sec.virtual_address)
sel_hi = sel_lo + int(sel_sec.size)
selref = None
for rel in binary.relocations:
    t = getattr(rel,'target',None)
    if t and int(t)==name_va:
        a = int(rel.address)
        if sel_lo <= a < sel_hi:
            selref = a; break
ml = binary.get_section('__objc_methlist')
mlraw = bytes(ml.content)
mlva = int(ml.virtual_address)
i = 0
imp = None
while i + 8 <= len(mlraw):
    es, cnt = struct.unpack_from('<II', mlraw, i)
    es2 = es & 0xFFFF
    if es2 != 12 or cnt == 0 or cnt > 500:
        i += 4; continue
    base = i + 8
    if base + cnt*12 > len(mlraw):
        i += 4; continue
    for k in range(cnt):
        e = base + k*12
        nr,_,ir = struct.unpack_from('<iii', mlraw, e)
        if (mlva+e)+nr == selref:
            imp = (mlva+e+8)+ir; break
    if imp: break
    i = base + cnt*12
print(f'handleButtonTap IMP: {imp:#x}')
text = binary.get_section('__text')
tva = int(text.virtual_address)
tb = bytes(text.content)
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True
rel = imp - tva
insns = list(md.disasm(tb[rel:rel+0x360], imp))
for insn in insns[:90]:
    print(f'{insn.address:#x}: {insn.mnemonic} {insn.op_str}')
