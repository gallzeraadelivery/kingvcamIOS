import capstone, lief, struct
blob = open(r'C:\kingvcamios\extracted\data\var\jb\Library\MobileSubstrate\DynamicLibraries\AVServicesd.dylib','rb').read()
off8 = 8
_cpu, _sub, offset, size, _align = struct.unpack('>IIIII', blob[off8:off8+20])
sdata = blob[offset:offset+size]
parsed = lief.parse(sdata)
binary = parsed.at(0) if hasattr(parsed,'at') else parsed

targets = {
    '_notify_post': 0x11c9c0,
    '_open': 0x11c9e0,
    '_close': None,
}
# find _close
for bind in binary.bindings:
    sym = getattr(bind,'symbol',None)
    n = getattr(sym,'name',None) if sym else None
    if n == '_close':
        targets['_close'] = bind.address
        print(f'_close GOT: {bind.address:#x}')

for secname in ('__stubs', '__auth_stubs'):
    sec = binary.get_section(secname)
    if not sec: continue
    sb = bytes(sec.content)
    sva = int(sec.virtual_address)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    pending_page = None
    stub_start = None
    for insn in md.disasm(sb, sva):
        if insn.mnemonic == 'adrp':
            pending_page = int(insn.operands[1].imm)
            stub_start = insn.address
        elif insn.mnemonic == 'add' and pending_page is not None and len(insn.operands) >= 3:
            if insn.operands[2].type == capstone.arm64.ARM64_OP_IMM:
                pending_page += int(insn.operands[2].imm)
        elif insn.mnemonic == 'ldr' and pending_page is not None and stub_start is not None:
            disp = 0
            if insn.operands[1].type == capstone.arm64.ARM64_OP_MEM:
                disp = insn.operands[1].mem.disp
            got = pending_page + disp
            for name, addr in targets.items():
                if addr and got == addr:
                    print(f'{name} stub: {stub_start:#x} (GOT {addr:#x})')
            pending_page = None
            stub_start = None
