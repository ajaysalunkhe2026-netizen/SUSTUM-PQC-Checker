import io
import json
import os
import tempfile
import unittest
import zipfile

from app import app, safe_extract
from recommend import decide, generate_sbom, recommend
from report import render_report
from scanner import scan_directory
from cbom_validation import validate_sbom


class ScannerTests(unittest.TestCase):
    def test_python_rsa_api_is_reported(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "crypto.py")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                    "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
                )
            findings = scan_directory(root)
            self.assertTrue(any(x["algorithm"] == "RSA" and x["vulnerable"] is True for x in findings))

    def test_aliased_python_crypto_import_is_reported(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "crypto_alias.py")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "from cryptography.hazmat.primitives.asymmetric import rsa as asymmetric_rsa\n"
                    "key = asymmetric_rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
                )
            findings = scan_directory(root)
            self.assertTrue(any(x["algorithm"] == "RSA" for x in findings))

    def test_comments_are_not_text_findings(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "plain.py"), "w", encoding="utf-8") as handle:
                handle.write("# RSA-2048 is mentioned only in this comment\nprint('hello')\n")
            self.assertEqual(scan_directory(root), [])

    def test_dependency_is_inventory_not_vulnerability_proof(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "requirements.txt"), "w", encoding="utf-8") as handle:
                handle.write("cryptography==42.0.0\n")
            findings = scan_directory(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["asset_type"], "Dependency")
            self.assertIsNone(findings[0]["vulnerable"])


    def test_java_rsa_api_is_reported(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "Crypto.java"), "w", encoding="utf-8") as handle:
                handle.write('KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");\n')
            findings = scan_directory(root)
            self.assertTrue(any(x["algorithm"] == "RSA" and x["confidence"] == "High-confidence API call" for x in findings))

    def test_javascript_rsa_api_is_reported(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "crypto.js"), "w", encoding="utf-8") as handle:
                handle.write("crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n")
            findings = scan_directory(root)
            self.assertTrue(any(x["algorithm"] == "RSA" and x["purpose"] == "Key generation" for x in findings))

    def test_go_rsa_api_is_reported(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "crypto.go"), "w", encoding="utf-8") as handle:
                handle.write("key, err := rsa.GenerateKey(rand.Reader, 2048)\n")
            findings = scan_directory(root)
            self.assertTrue(any(x["algorithm"] == "RSA" and x["confidence"] == "High-confidence API call" for x in findings))

    def test_c_openssl_rsa_api_is_reported(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "crypto.c"), "w", encoding="utf-8") as handle:
                handle.write("RSA_generate_key_ex(rsa, bits, e, cb);\n")
            findings = scan_directory(root)
            self.assertTrue(any(x["algorithm"] == "RSA" and "OpenSSL API" in x["confidence"] for x in findings))

    def test_go_mod_is_inventory_only(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "go.mod"), "w", encoding="utf-8") as handle:
                handle.write("module example.com/demo\n\nrequire (\n github.com/example/crypto v1.2.3\n)\n")
            findings = scan_directory(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["asset_type"], "Dependency")
            self.assertIsNone(findings[0]["vulnerable"])

    def test_python_string_and_inline_comment_are_not_text_findings(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "logging.py"), "w", encoding="utf-8") as handle:
                handle.write("message = 'RSA is mentioned in a string'\\nvalue = 1  # ECDH note\\n")
            self.assertEqual(scan_directory(root), [])

    def test_syntax_error_becomes_diagnostic(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "broken.py"), "w", encoding="utf-8") as handle:
                handle.write("def broken(:\n")
            findings = scan_directory(root)
            self.assertTrue(any(x["asset_type"] == "Scanner diagnostic" for x in findings))


class ReportAndRecommendationTests(unittest.TestCase):

    def test_generated_cbom_passes_cyclonedx_16_schema(self):
        item = {"asset_type": "Algorithm", "algorithm": "RSA", "location": "src/a.py:2",
                "purpose": "Key generation", "confidence": "High-confidence API call",
                "evidence": "rsa.generate_private_key", "vulnerable": True}
        result = validate_sbom(generate_sbom([item], "sample"))
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["spec_version"], "1.6")

    def test_invalid_cbom_is_rejected_by_cyclonedx_validator(self):
        result = validate_sbom({"bomFormat": "NotCycloneDX", "specVersion": "1.6"})
        self.assertFalse(result["valid"])
        self.assertTrue(result["errors"])

    def test_html_escapes_untrusted_values(self):
        html = render_report("<script>alert(1)</script>", "NIST", [], "Conditional",
                             "<img src=x onerror=alert(1)>", {}, {"bomFormat": "CycloneDX"})
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("<img src=x onerror=alert(1)>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_manifest_dependency_is_not_given_pqc_replacement(self):
        item = {"asset_type": "Dependency", "library": "cryptography",
                "algorithm": "cryptography", "vulnerable": None}
        result = recommend([item], "nist")[0]
        self.assertEqual(result["mode"], "Inventory only")

    def test_rsa_key_generation_is_not_mapped_to_one_pqc_algorithm(self):
        item = {"asset_type": "Algorithm", "algorithm": "RSA",
                "purpose": "Signature / key establishment", "vulnerable": True}
        result = recommend([item], "nist")[0]
        self.assertEqual(result["mode"], "Manual review")
        self.assertIn("actual RSA key usage", result["recommendation"])

    def test_empty_scan_is_not_declared_safe(self):
        decision, reason = decide([])
        self.assertEqual(decision, "Conditional")
        self.assertIn("does not prove", reason)

    def test_cbom_candidate_contains_evidence_properties(self):
        item = {"asset_type": "Algorithm", "algorithm": "RSA", "location": "x.py:2",
                "purpose": "Signature", "confidence": "High-confidence API call",
                "evidence": "rsa.generate_private_key", "vulnerable": True}
        bom = generate_sbom([item], "sample")
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.6")
        self.assertEqual(bom["components"][0]["type"], "cryptographic-asset")
        self.assertTrue(any(p["name"] == "sustum:evidence"
                            for p in bom["components"][0]["properties"]))


class UploadTests(unittest.TestCase):
    def test_dashboard_route_is_available(self):
        client = app.test_client()
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SUSTUM", response.data)
        self.assertIn(b"Run scan", response.data)
        self.assertIn(b"cbom-validation", response.data)

    def test_zip_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w") as archive:
                archive.writestr("../escape.txt", "not allowed")
            data.seek(0)
            with zipfile.ZipFile(data) as archive:
                with self.assertRaises(ValueError):
                    safe_extract(archive, root)

    def test_scan_endpoint_returns_report_and_cbom(self):
        app.config["TESTING"] = True
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("src/auth.py",
                             "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                             "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
        data.seek(0)
        client = app.test_client()
        response = client.post("/scan", data={
            "file": (data, "sample.zip"),
            "guideline": "nist"
        }, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("report_html", payload)
        self.assertIn("sbom", payload)
        self.assertTrue(payload["sbom_validation"]["valid"], payload["sbom_validation"]["errors"])
        self.assertIn("recommendations", payload)
        self.assertIn("vulnerable_indicator_count", payload)
        self.assertIn("unknown_count", payload)
        self.assertTrue(payload["report_html"].startswith("<!doctype html>"))
        json.dumps(payload["sbom"])


if __name__ == "__main__":
    unittest.main()
