import lief, struct
blob = open(r'C:\kingvcamios\extracted\data\var\jb\Library\MobileSubstrate\DynamicLibraries\AVServicesd.dylib','rb').read()
off8 = 8
_cpu, _sub, offset, size, _align = struct.unpack('>IIIII', blob[off8:off8+20])
sdata = blob[offset:offset+size]
parsed = lief.parse(sdata)
binary = parsed.at(0) if hasattr(parsed,'at') else parsed
for bind in binary.bindings:
    sym = getattr(bind,'symbol',None)
    n = getattr(sym,'name',None) if sym else None
    if n and 'notify' in n.lower():
        print(f'{n} @ {bind.address:#x}')
# Also check for access
for bind in binary.bindings:
    sym = getattr(bind,'symbol',None)
    n = getattr(sym,'name',None) if sym else None
    if n and n in ('_access', '_open', '_stat'):
        print(f'{n} @ {bind.address:#x}')
