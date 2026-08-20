import plistlib
with open(r"C:\kingvcamios\repack\data\var\jb\Library\MobileSubstrate\DynamicLibraries\AVServicesd.plist", "rb") as f:
    print(plistlib.load(f))
