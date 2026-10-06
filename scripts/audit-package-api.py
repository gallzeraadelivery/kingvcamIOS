"""Decode the shipped runtime's API strings using its unchanged ARM64 code."""
import runpy
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
api = runpy.run_path(str(root / 'scripts/repack-api-only.py'))
runtime = runpy.run_path(str(root / 'scripts/runtime-strings.py'))
candidate = Path(sys.argv[1]) if len(sys.argv) > 1 else api['OUTPUT']
for label, package in [('original', api['SOURCE']), ('kingvcam', candidate)]:
    archive = api['read_ar'](package.read_bytes())
    blob = api['contents'](archive['data.tar.lzma'])[api['DYLIB']]
    values = runtime['decoded_globals'](blob)
    urls = sorted({value for value in values.values() if '://www.' in value or '://kingvcam' in value})
    print(label, urls)
    if label == 'kingvcam':
        assert 'https://www.kingvcam.com/v1' in urls, 'Native decoder does not produce KingVCam API base'
        assert 'https://www.lordvcam.com/v1' not in urls, 'Native decoder still produces old API base'
