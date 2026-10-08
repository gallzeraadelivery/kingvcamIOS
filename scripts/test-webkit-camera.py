"""Verify 3.0.44-19 changes only the injection filter and version."""
import importlib.util
import plistlib
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "webkit_camera", Path(__file__).with_name("repack-webkit-camera.py")
)
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)
helpers = candidate.helpers


class WebKitCameraTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = helpers.read_ar(candidate.safe.SOURCE.read_bytes())
        cls.target = helpers.read_ar(candidate.OUTPUT.read_bytes())

    def test_data_files(self):
        before = helpers.contents(self.source["data.tar.lzma"])
        after = helpers.contents(self.target["data.tar.lzma"])
        self.assertEqual(before.keys(), after.keys())
        for path in before:
            expected = candidate.webkit_camera_filter(before[path]) if path == candidate.safe.FILTER_PATH else before[path]
            self.assertEqual(after[path], expected, path)

    def test_control_files(self):
        before = helpers.contents(self.source["control.tar.gz"])
        after = helpers.contents(self.target["control.tar.gz"])
        self.assertEqual(before.keys(), after.keys())
        for path in before:
            expected = candidate.versioned_control(before[path]) if path == "control" else before[path]
            self.assertEqual(after[path], expected, path)

    def test_targets(self):
        after = helpers.contents(self.target["data.tar.lzma"])
        targets = plistlib.loads(after[candidate.safe.FILTER_PATH])["Filter"]
        self.assertEqual(targets["Bundles"], [
            "com.apple.mediaserverd", "com.apple.springboard", "com.apple.camera",
            "com.apple.mobilesafari", "com.apple.WebKit.WebContent", "com.apple.WebKit.GPU",
        ])
        self.assertEqual(targets["Executables"], ["mediaserverd", "assetsd"])


if __name__ == "__main__":
    unittest.main()
