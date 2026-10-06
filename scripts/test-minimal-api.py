"""Regression checks for the minimally redirected original package."""
import importlib.util
import io
import plistlib
import tarfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('minimal', Path(__file__).with_name('repack-minimal-api.py'))
minimal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(minimal)
api = minimal.helpers


class MinimalPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = api.read_ar(api.SOURCE.read_bytes())
        cls.patched = api.read_ar(minimal.OUTPUT.read_bytes())
        cls.original_data = api.contents(cls.original['data.tar.lzma'])
        cls.patched_data = api.contents(cls.patched['data.tar.lzma'])

    def test_engine_filter_and_other_files_identical(self):
        self.assertEqual(set(self.patched_data) - set(self.original_data), {api.ENTITLEMENTS})
        self.assertFalse(set(self.original_data) - set(self.patched_data))
        for path, before in self.original_data.items():
            with self.subTest(path=path):
                after = self.patched_data[path]
                if path in (api.DYLIB, api.DAEMON):
                    self.assertEqual(after, minimal.patch_site(api.patch_api(before), 6 if path == api.DYLIB else 2))
                    self.assertEqual(api.executable_sections(after), api.executable_sections(before))
                else:
                    self.assertEqual(after, before)

    def test_original_entitlements_and_install_actions(self):
        expected = api.helpers.original_daemon_entitlements(self.original_data[api.DAEMON])
        self.assertEqual(plistlib.loads(self.patched_data[api.ENTITLEMENTS]), expected)
        original = api.contents(self.original['control.tar.gz'])
        patched = api.contents(self.patched['control.tar.gz'])
        self.assertEqual(patched['postinst'], api.signing_prefix() + original['postinst'].split(b'\n', 1)[1])
        self.assertIn(b'Version: 3.0.44-14\n', patched['control'])
        for path in set(original) - {'control', 'postinst'}:
            self.assertEqual(patched[path], original[path])

    def test_archive_members_and_permissions(self):
        for archive_name in ('data.tar.lzma', 'control.tar.gz'):
            with tarfile.open(fileobj=io.BytesIO(self.original[archive_name]), mode='r:*') as src, tarfile.open(fileobj=io.BytesIO(self.patched[archive_name]), mode='r:*') as dst:
                members = {m.name: m for m in dst}
                for before in src:
                    actual = members[before.name]
                    for key in ('mode', 'uid', 'gid', 'uname', 'gname', 'type', 'linkname'):
                        self.assertEqual(getattr(actual, key), getattr(before, key))


if __name__ == '__main__':
    unittest.main()
