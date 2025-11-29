import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, Mock, patch

from portable_scanner.context import ScanContext
from portable_scanner.models import ArtifactCategory, ScanOptions, Severity
from portable_scanner.scanners.bypass import (
    OBFUSCATED_CLASS_PATTERNS,
    UNICODE_HOMOGLYPH_PATTERNS,
    BypassAnalyzerScanner,
    contains_homoglyphs,
    is_spoofed_signature,
)


class TestHomoglyphDetection(unittest.TestCase):
    def test_homoglyph_patterns_exist(self):
        self.assertGreater(len(UNICODE_HOMOGLYPH_PATTERNS), 0)

    def test_contains_homoglyphs_with_cyrillic_o(self):
        text = "gοοgle.com"  # Greek omicron
        self.assertTrue(contains_homoglyphs(text))

    def test_contains_homoglyphs_with_cyrillic_a(self):
        text = "pаypal.exe"  # Cyrillic a
        self.assertTrue(contains_homoglyphs(text))

    def test_contains_homoglyphs_with_ascii(self):
        text = "normal_file.exe"
        self.assertFalse(contains_homoglyphs(text))

    def test_contains_homoglyphs_with_numbers(self):
        text = "file123.dll"
        self.assertFalse(contains_homoglyphs(text))


class TestSignatureDetection(unittest.TestCase):
    def test_is_spoofed_jar_as_txt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "notes.txt")
            with open(file_path, "wb") as f:
                f.write(b"PK\x03\x04")  # JAR/ZIP signature

            self.assertTrue(is_spoofed_signature(file_path, ".txt"))

    def test_is_spoofed_exe_as_png(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "image.png")
            with open(file_path, "wb") as f:
                f.write(b"MZ\x90\x00")  # PE signature

            self.assertTrue(is_spoofed_signature(file_path, ".png"))

    def test_is_spoofed_exe_as_exe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "program.exe")
            with open(file_path, "wb") as f:
                f.write(b"MZ\x90\x00")  # PE signature

            self.assertFalse(is_spoofed_signature(file_path, ".exe"))

    def test_is_spoofed_jar_as_jar(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "library.jar")
            with open(file_path, "wb") as f:
                f.write(b"PK\x03\x04")  # JAR signature

            self.assertFalse(is_spoofed_signature(file_path, ".jar"))

    def test_is_spoofed_empty_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "empty.exe")
            with open(file_path, "wb") as f:
                pass  # Empty file

            self.assertFalse(is_spoofed_signature(file_path, ".exe"))

    def test_is_spoofed_nonexistent_file(self):
        self.assertFalse(is_spoofed_signature("/nonexistent/file.exe", ".exe"))


class TestObfuscatedPatterns(unittest.TestCase):
    def test_obfuscated_class_patterns_exist(self):
        self.assertGreater(len(OBFUSCATED_CLASS_PATTERNS), 0)

    def test_obfuscated_single_letter_class(self):
        import re

        pattern = r"^[a-z]\.class$"
        self.assertTrue(re.search(pattern, "a.class"))
        self.assertTrue(re.search(pattern, "z.class"))
        self.assertFalse(re.search(pattern, "MyClass.class"))

    def test_obfuscated_killaura_keyword(self):
        import re

        pattern = r"killaura"
        self.assertTrue(re.search(pattern, "killaura"))
        self.assertTrue(re.search(pattern, "killaura", re.IGNORECASE))
        self.assertTrue(re.search(pattern, "KillAuraModule.class", re.IGNORECASE))
        self.assertFalse(re.search(pattern, "NormalClass.class"))


class TestBypassAnalyzerScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = BypassAnalyzerScanner()

    def test_scanner_category(self):
        self.assertEqual(self.scanner.category, ArtifactCategory.BYPASS_ANALYSIS)

    def test_scanner_name(self):
        self.assertEqual(self.scanner.name, "Bypass & Evasion Analysis")

    @patch("portable_scanner.scanners.bypass.Path")
    def test_scan_on_non_windows(self, mock_path):
        context = MagicMock(spec=ScanContext)
        context.is_windows = False

        findings = list(self.scanner.scan(context))

        self.assertEqual(len(findings), 0)
        context.log.assert_called_once()

    def test_scan_targets_generation(self):
        with patch.dict(
            os.environ,
            {
                "TEMP": "C:\\Temp",
                "LOCALAPPDATA": "C:\\Users\\Test\\AppData\\Local",
                "USERPROFILE": "C:\\Users\\Test",
            },
        ):
            context = MagicMock(spec=ScanContext)
            targets = self.scanner._get_scan_targets(context)

            self.assertIn("C:\\Temp", targets)
            self.assertIn("C:\\Users\\Test\\AppData\\Local", targets)
            downloads_expected = os.path.join("C:\\Users\\Test", "Downloads")
            self.assertIn(downloads_expected, targets)

    def test_read_file_signature_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.bin")
            with open(test_file, "wb") as f:
                f.write(b"MZ\x90\x00TESTDATA")

            from pathlib import Path

            sig = self.scanner._read_file_signature(Path(test_file))
            self.assertEqual(sig, b"MZ\x90\x00")

    def test_extension_to_type_mapping(self):
        self.assertEqual(self.scanner._extension_to_type(".exe"), "PE")
        self.assertEqual(self.scanner._extension_to_type(".dll"), "PE")
        self.assertEqual(self.scanner._extension_to_type(".jar"), "JAR")
        self.assertEqual(self.scanner._extension_to_type(".zip"), "ZIP")
        self.assertIsNone(self.scanner._extension_to_type(".xyz"))

    def test_signature_to_type_pe(self):
        self.assertEqual(self.scanner._signature_to_type(b"MZ\x90\x00"), "PE")

    def test_signature_to_type_jar(self):
        self.assertEqual(self.scanner._signature_to_type(b"PK\x03\x04"), "JAR")

    def test_signature_to_type_png(self):
        self.assertEqual(self.scanner._signature_to_type(b"\x89PNG"), "IMAGE")

    def test_signature_to_type_jpeg(self):
        self.assertEqual(self.scanner._signature_to_type(b"\xff\xd8\xff\xe0"), "IMAGE")

    def test_signature_to_type_pdf(self):
        self.assertEqual(self.scanner._signature_to_type(b"%PDF"), "PDF")

    def test_signature_to_type_unknown(self):
        self.assertIsNone(self.scanner._signature_to_type(b"\x00\x00\x00\x00"))

    def test_normalize_homoglyphs(self):
        result = self.scanner._normalize_homoglyphs("pаypal")
        self.assertIn("pay", result.lower())


class TestEscalation(unittest.TestCase):
    def test_escalate_findings_with_multiple_techniques(self):
        scanner = BypassAnalyzerScanner()

        from portable_scanner.models import Finding

        findings = [
            Finding(
                severity=Severity.HIGH,
                category=ArtifactCategory.BYPASS_ANALYSIS,
                title="Test Finding 1",
                location="/test/file1",
                timestamp=datetime.now(timezone.utc),
                description="Test description 1",
                evidence={},
            ),
            Finding(
                severity=Severity.MEDIUM,
                category=ArtifactCategory.BYPASS_ANALYSIS,
                title="Test Finding 2",
                location="/test/file2",
                timestamp=datetime.now(timezone.utc),
                description="Test description 2",
                evidence={},
            ),
        ]

        technique_hits = {
            "spoofed_extensions": 2,
            "unicode_homoglyphs": 1,
            "obfuscated_classes": 1,
        }

        escalated = scanner._escalate_findings(findings, technique_hits)

        self.assertEqual(len(escalated), 2)
        for finding in escalated:
            self.assertEqual(finding.severity, Severity.CRITICAL)
            self.assertIn("escalation_reason", finding.evidence)
            self.assertIn("technique_summary", finding.evidence)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
