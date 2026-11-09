import os
import tempfile
import unittest

from scanner import scan_file


class PQCAlgorithmClassificationTests(unittest.TestCase):
    def _scan(self, filename, content, binary=False):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, filename)
            mode = "wb" if binary else "w"
            kwargs = {} if binary else {"encoding": "utf-8"}
            with open(path, mode, **kwargs) as handle:
                handle.write(content)
            return scan_file(path, filename)

    def test_ml_dsa_is_not_classified_as_legacy_dsa(self):
        findings = self._scan("algorithms.json", '{"algorithm": "ML-DSA-65"}')
        self.assertTrue(any(x["algorithm"] == "PQC algorithm reference" and
                            x["vulnerable"] is False for x in findings))
        self.assertFalse(any(x["algorithm"] == "DSA" for x in findings))

    def test_slh_dsa_is_not_classified_as_legacy_dsa(self):
        findings = self._scan("algorithms.json", '{"algorithm": "SLH-DSA-SHA2-128s"}')
        self.assertTrue(any(x["algorithm"] == "PQC algorithm reference" and
                            x["vulnerable"] is False for x in findings))
        self.assertFalse(any(x["algorithm"] == "DSA" for x in findings))

    def test_standalone_legacy_dsa_reference_is_still_detected(self):
        findings = self._scan("algorithms.json", '{"algorithm": "DSA"}')
        self.assertTrue(any(x["algorithm"] == "DSA" and
                            x["vulnerable"] is True for x in findings))

    def test_utf8_bom_python_file_parses_without_parse_diagnostic(self):
        source = (
            b"\xef\xbb\xbf"
            b"from cryptography.hazmat.primitives.asymmetric import rsa\n"
            b"key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        )
        findings = self._scan("bom_source.py", source, binary=True)
        self.assertFalse(any(x["asset_type"] == "Scanner diagnostic" and
                             x["algorithm"] == "Python parse error" for x in findings))
        self.assertTrue(any(x["algorithm"] == "RSA" for x in findings))


if __name__ == "__main__":
    unittest.main()
