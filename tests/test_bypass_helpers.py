import os
import tempfile
import unittest

from portable_scanner.scanners.bypass import contains_homoglyphs, is_spoofed_signature


class TestBypassHelpers(unittest.TestCase):
    def test_contains_homoglyphs_detects_cyrillic(self):
        suspicious_name = "payраl.exe"  # contains Cyrillic "ра"
        self.assertTrue(contains_homoglyphs(suspicious_name))

    def test_contains_homoglyphs_handles_ascii(self):
        benign_name = "notavirus.exe"
        self.assertFalse(contains_homoglyphs(benign_name))

    def test_is_spoofed_signature_detects_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "image.png")
            with open(path, "wb") as handle:
                handle.write(b"MZFakePE")

            self.assertTrue(is_spoofed_signature(path, ".png"))

    def test_is_spoofed_signature_matches_expected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "program.exe")
            with open(path, "wb") as handle:
                handle.write(b"MZFakePE")

            self.assertFalse(is_spoofed_signature(path, ".exe"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
