import capstone, lief, struct
blob = open('extracted/data/var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.dylib','rb').read()
off8 = 8
_cpu, _sub, offset, size, _align = struct.unpack('>IIIII', blob[off8:off8+20])
sdata = blob[offset:offset+size]
parsed = lief.parse(sdata)
binary = parsed.at(0) if hasattr(parsed,'at') else parsed

# 0xda220 loads selref from 0x150000 + 0xf98
selref_va = 0x150000 + 0xf98
print(f'selref VA: {selref_va:#x}')

# Find what methname this selref points to
for rel in binary.relocations:
    a = int(rel.address)
    if a == selref_va:
        t = getattr(rel,'target',None)
        if t:
            methname_va = int(t)
            print(f'methname VA: {methname_va:#x}')
            meth = binary.get_section('__objc_methname')
            raw = bytes(meth.content)
            mva = int(meth.virtual_address)
            off = methname_va - mva
            end = raw.find(b'\x00', off)
            name = raw[off:end].decode()
            print(f'selector: {name}')
        break
