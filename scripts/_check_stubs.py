import capstone, lief, struct
blob = open('extracted/data/var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.dylib','rb').read()
off8 = 8
_cpu, _sub, offset, size, _align = struct.unpack('>IIIII', blob[off8:off8+20])
sdata = blob[offset:offset+size]
parsed = lief.parse(sdata)
binary = parsed.at(0) if hasattr(parsed,'at') else parsed

# Check what 0xda220 is (stub)
stubs = binary.get_section('__objc_stubs')
sb = bytes(stubs.content)
sva = int(stubs.virtual_address)
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

# Find what selector 0xda220 loads
target = 0xda220
rel = target - sva
insns = list(md.disasm(sb[rel:rel+0x20], target))
for insn in insns:
    print(f'{insn.address:#x}: {insn.mnemonic} {insn.op_str}')

# Also find showLogin selref and its stub
meth = binary.get_section('__objc_methname')
raw = bytes(meth.content)
mva = int(meth.virtual_address)
needle = b'\x00showLogin\x00'
hit = raw.find(needle)
if hit >= 0:
    name_va = mva + hit + 1
    print(f'\nshowLogin methname VA: {name_va:#x}')
    sel_sec = binary.get_section('__objc_selrefs')
    sel_lo = int(sel_sec.virtual_address)
    sel_hi = sel_lo + int(sel_sec.size)
    for rel2 in binary.relocations:
        t = getattr(rel2,'target',None)
        if t and int(t)==name_va:
            a = int(rel2.address)
            if sel_lo <= a < sel_hi:
                print(f'showLogin selref: {a:#x}')
                # Find stub for this selref
                pending = {}
                for insn in md.disasm(sb, sva):
                    if insn.mnemonic == 'adrp':
                        pending[insn.operands[0].reg] = (insn.address, insn.operands[1].imm)
                    elif insn.mnemonic == 'ldr' and insn.operands[1].type == capstone.arm64.ARM64_OP_MEM:
                        base = insn.operands[1].mem.base
                        if base in pending:
                            dest = pending[base][1] + insn.operands[1].mem.disp
                            if dest == a:
                                print(f'showLogin stub: {pending[base][0]:#x}')
                break
