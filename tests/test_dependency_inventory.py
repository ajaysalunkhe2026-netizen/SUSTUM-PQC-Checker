import json
import os
import tempfile
import unittest

from scanner import scan_directory


class DependencyManifestTests(unittest.TestCase):
    def _scan(self, files):
        with tempfile.TemporaryDirectory() as root:
            for name, value in files.items():
                path = os.path.join(root, name)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                mode = "wb" if isinstance(value, bytes) else "w"
                with open(path, mode) as handle:
                    handle.write(value)
            return scan_directory(root)

    def test_pyproject_pep621_dependencies_and_optional_groups(self):
        findings = self._scan({
            "pyproject.toml": (
                '[project]\nname = "demo"\ndependencies = ["cryptography>=42", "requests==2.31"]\n'
                '[project.optional-dependencies]\ntest = ["pytest>=8"]\n'
            )
        })
        by_name = {item["library"]: item for item in findings}
        self.assertEqual(set(by_name), {"cryptography", "requests", "pytest"})
        self.assertEqual(by_name["cryptography"]["version"], ">=42")
        self.assertEqual(by_name["cryptography"]["version_kind"], "declared")
        self.assertEqual(by_name["pytest"]["dependency_scope"], "optional:test")
        self.assertIsNone(by_name["cryptography"]["vulnerable"])

    def test_pipfile_and_lock_distinguish_declared_from_locked(self):
        findings = self._scan({
            "Pipfile": '[packages]\ncryptography = ">=42"\n[dev-packages]\npytest = "*"\n',
            "Pipfile.lock": json.dumps({
                "default": {"cryptography": {"version": "==42.0.0"}},
                "develop": {"pytest": {"version": "==8.0.0"}}
            })
        })
        declared = [x for x in findings if x.get("source_kind", "").startswith("Pipfile ")]
        locked = [x for x in findings if x.get("source_kind", "").startswith("Pipfile.lock")]
        self.assertEqual(len(declared), 2)
        self.assertTrue(all(x["version_kind"] == "declared" for x in declared))
        self.assertEqual(len(locked), 2)
        self.assertTrue(all(x["version_kind"] == "locked" for x in locked))

    def test_npm_lock_v3_records_nested_package_instances(self):
        findings = self._scan({
            "package-lock.json": json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo"},
                    "node_modules/left-pad": {"version": "1.3.0"},
                    "node_modules/parent/node_modules/child": {"version": "2.0.0"}
                }
            })
        })
        self.assertEqual({x["library"] for x in findings}, {"left-pad", "child"})
        self.assertTrue(all(x["version_kind"] == "locked" for x in findings))

    def test_npm_lock_v1_recurses_nested_dependencies(self):
        findings = self._scan({
            "npm-shrinkwrap.json": json.dumps({
                "dependencies": {
                    "parent": {"version": "1.0.0", "dependencies": {
                        "child": {"version": "2.0.0"}
                    }}
                }
            })
        })
        self.assertEqual({x["library"] for x in findings}, {"parent", "child"})
        child = next(x for x in findings if x["library"] == "child")
        self.assertEqual(child["dependency_relationship"], "transitive")

    def test_go_sum_is_checksum_inventory_not_declared_usage(self):
        findings = self._scan({
            "go.sum": "golang.org/x/crypto v0.24.0 h1:abc123=\n"
                      "golang.org/x/crypto v0.24.0/go.mod h1:def456=\n"
        })
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(x["version_kind"] == "checksum-recorded" for x in findings))
        self.assertTrue(all(x["dependency_relationship"] == "unknown" for x in findings))
        self.assertTrue(all(x["vulnerable"] is None for x in findings))

    def test_malformed_manifest_is_reported_as_no_inventory_not_crash(self):
        findings = self._scan({"pyproject.toml": "[project\ninvalid"})
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
