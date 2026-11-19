"""Focused security and regression tests for Phase 1 scanner stabilization."""
import io
import os
import tempfile
import unittest
import warnings
import zipfile
from unittest.mock import patch

import scanner
from app import safe_extract
from scanner import (
    MAX_SOURCE_FILE_BYTES,
    _mask_non_python_strings,
    _strip_source_comments,
    scan_directory,
    scan_file,
)


class ScannerRegressionTests(unittest.TestCase):
    def _scan(self, source, suffix):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "sample" + suffix)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(source)
            return scan_file(path, "sample" + suffix)

    def test_line_comment_does_not_hide_following_crypto_call(self):
        findings = self._scan(
            "// ordinary comment\ncrypto.generateKeyPairSync('rsa', {});\n", ".js"
        )
        self.assertTrue(any(x["algorithm"] == "RSA" for x in findings))

    def test_block_comment_preserves_following_line_number(self):
        findings = self._scan(
            "/* first line\nsecond line */\ncrypto.generateKeyPairSync('rsa', {});\n",
            ".js",
        )
        rsa = next(x for x in findings if x["algorithm"] == "RSA")
        self.assertEqual(rsa["location"], "sample.js:3")

    def test_comment_masker_preserves_crlf_newlines(self):
        source = "const x = 1; // comment\r\ncrypto.generateKeyPairSync('rsa', {});\r\n"
        masked = _strip_source_comments(source, ".js")
        self.assertEqual(masked.count("\n"), source.count("\n"))
        self.assertIn("crypto.generateKeyPairSync", masked)

    def test_go_import_alias_resolves(self):
        findings = self._scan(
            'import cryptorsa "crypto/rsa"\ncryptorsa.GenerateKey(rand.Reader, 2048)\n',
            ".go",
        )
        self.assertTrue(any(x["algorithm"] == "RSA" for x in findings))

    def test_go_dot_import_resolves(self):
        findings = self._scan(
            'import . "crypto/rsa"\nGenerateKey(rand.Reader, 2048)\n',
            ".go",
        )
        rsa = next(x for x in findings if x["algorithm"] == "RSA")
        self.assertEqual(rsa["purpose"], "Key generation")

    def test_openssl_provider_rsa_context_is_detected(self):
        findings = self._scan(
            'ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);\n', ".c"
        )
        self.assertTrue(any(x["algorithm"] == "RSA" for x in findings))

    def test_code_string_mentions_do_not_create_textual_crypto_finding(self):
        findings = self._scan('const message = "RSA-2048";\n', ".js")
        self.assertEqual(findings, [])

    def test_findings_include_normalized_confidence_and_evidence(self):
        findings = self._scan("crypto.generateKeyPairSync('rsa', {});\n", ".js")
        rsa = next(x for x in findings if x["algorithm"] == "RSA")
        self.assertEqual(rsa["confidence_level"], "high")
        self.assertEqual(rsa["evidence_detail"]["source"], "static_analysis")
        self.assertEqual(rsa["evidence_detail"]["location"], "sample.js:1")
        self.assertTrue(rsa["detector_id"])

    def test_oversized_source_returns_diagnostic(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "large.js")
            with open(path, "wb") as handle:
                handle.write(b"x" * (MAX_SOURCE_FILE_BYTES + 1))
            findings = scan_file(path, "large.js")
        self.assertTrue(any(x["asset_type"] == "Scanner diagnostic" for x in findings))

    def test_directory_scanner_skips_symlink_files(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            target = os.path.join(outside, "secret.js")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("crypto.generateKeyPairSync('rsa', {});")
            link = os.path.join(root, "linked.js")
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks are unavailable on this platform.")
            self.assertEqual(scan_directory(root), [])

    def test_candidate_file_count_budget_emits_diagnostic(self):
        with tempfile.TemporaryDirectory() as root:
            for name in ("a.js", "b.js"):
                with open(os.path.join(root, name), "w", encoding="utf-8") as handle:
                    handle.write("const value = 1;")
            with patch.object(scanner, "MAX_SCAN_FILES", 1):
                findings = scan_directory(root)
        self.assertTrue(any(x["algorithm"] == "Scan file-count limit reached" for x in findings))

    def test_aggregate_byte_budget_emits_diagnostic(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "a.js"), "w", encoding="utf-8") as handle:
                handle.write("const value = 1;")
            with patch.object(scanner, "MAX_TOTAL_SOURCE_BYTES", 1):
                findings = scan_directory(root)
        self.assertTrue(any(x["algorithm"] == "Scan byte budget reached" for x in findings))

    def test_wall_clock_budget_emits_diagnostic(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "a.js"), "w", encoding="utf-8") as handle:
                handle.write("const value = 1;")
            with patch("scanner.time.monotonic", side_effect=[0.0, 61.0]):
                findings = scan_directory(root)
        self.assertTrue(any(x["algorithm"] == "Scan time budget reached" for x in findings))

    def test_malformed_package_json_emits_diagnostic(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "package.json"), "w", encoding="utf-8") as handle:
                handle.write("[]")
            findings = scan_directory(root)
        self.assertTrue(any(x["asset_type"] == "Scanner diagnostic" for x in findings))


class ZipExtractionSecurityTests(unittest.TestCase):
    def _archive(self, entries):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries:
                archive.writestr(name, data)
        stream.seek(0)
        return zipfile.ZipFile(stream)

    def test_zip_slip_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            archive = self._archive([("../escape.txt", "no")])
            with archive:
                with self.assertRaises(ValueError):
                    safe_extract(archive, root)
            self.assertFalse(os.path.exists(os.path.join(root, "..", "escape.txt")))

    def test_duplicate_normalized_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            stream = io.BytesIO()
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                with zipfile.ZipFile(stream, "w") as archive:
                    archive.writestr("same.txt", "one")
                    archive.writestr("./same.txt", "two")
            stream.seek(0)
            with zipfile.ZipFile(stream) as archive:
                with self.assertRaises(ValueError):
                    safe_extract(archive, root)

    def test_symlink_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            stream = io.BytesIO()
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = (0o120777 << 16)
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr(info, "target")
            stream.seek(0)
            with zipfile.ZipFile(stream) as archive:
                with self.assertRaises(ValueError):
                    safe_extract(archive, root)

    def test_high_compression_ratio_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            archive = self._archive([("zeros.txt", b"0" * (2 * 1024 * 1024))])
            with archive:
                with self.assertRaises(ValueError):
                    safe_extract(archive, root)


if __name__ == "__main__":
    unittest.main()
