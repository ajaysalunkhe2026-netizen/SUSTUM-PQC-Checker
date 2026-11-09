import json
import os
import tempfile
import unittest

from scanner import scan_directory
from recommend import generate_sbom
from cbom_validation import validate_sbom


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
                    "": {"name": "demo", "dependencies": {"left-pad": "^1.3.0"}},
                    "node_modules/left-pad": {"version": "1.3.0"},
                    "node_modules/parent/node_modules/child": {"version": "2.0.0"}
                }
            })
        })
        self.assertEqual({x["library"] for x in findings}, {"left-pad", "child"})
        self.assertTrue(all(x["version_kind"] == "locked" for x in findings))
        self.assertEqual(next(x for x in findings if x["library"] == "left-pad")["dependency_relationship"], "direct")
        self.assertEqual(next(x for x in findings if x["library"] == "child")["dependency_relationship"], "transitive")
        self.assertEqual(next(x for x in findings if x["library"] == "child")["location"],
                         "package-lock.json::node_modules/parent/node_modules/child")

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

    def test_dependency_provenance_survives_cbom_serialization(self):
        item = {
            "asset_type": "Dependency", "algorithm": "cryptography",
            "library": "cryptography", "version": "==42.0.0",
            "location": "Pipfile.lock", "purpose": "Dependency inventory",
            "confidence": "Manifest entry", "evidence": "lockfile record",
            "vulnerable": None, "ecosystem": "pypi",
            "source_kind": "Pipfile.lock default", "dependency_scope": "runtime",
            "dependency_relationship": "direct", "version_kind": "locked"
        }
        bom = generate_sbom([item], "sample")
        self.assertTrue(validate_sbom(bom)["valid"])
        properties = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
        self.assertEqual(properties["sustum:version_kind"], "locked")
        self.assertEqual(properties["sustum:dependency_relationship"], "direct")
        self.assertEqual(properties["sustum:ecosystem"], "pypi")

    def test_malformed_manifest_emits_diagnostic_instead_of_silent_empty_inventory(self):
        findings = self._scan({"pyproject.toml": "[project\\ninvalid"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["asset_type"], "Scanner diagnostic")
        self.assertIn("Unable to parse TOML", findings[0]["evidence"])

    def test_invalid_npm_lock_root_emits_diagnostic(self):
        findings = self._scan({"package-lock.json": "[]"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["asset_type"], "Scanner diagnostic")

    def test_npm_resolved_url_is_not_misreported_as_version(self):
        findings = self._scan({"package-lock.json": json.dumps({
            "lockfileVersion": 3,
            "packages": {"": {}, "node_modules/example": {
                "resolved": "https://registry.npmjs.org/example/-/example-1.2.3.tgz"
            }}
        })})
        self.assertEqual(findings[0]["version"], "unspecified")
        self.assertEqual(findings[0]["version_kind"], "unknown")

    def test_nested_copy_of_direct_npm_package_is_transitive(self):
        findings = self._scan({"package-lock.json": json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"shared": "^1.0.0"}},
                "node_modules/shared": {"version": "1.0.0"},
                "node_modules/parent/node_modules/shared": {"version": "2.0.0"}
            }
        })})
        relationships = {x["version"]: x["dependency_relationship"] for x in findings}
        self.assertEqual(relationships, {"1.0.0": "direct", "2.0.0": "transitive"})

    def test_cbom_component_ids_are_stable_and_keep_distinct_dependency_locations(self):
        first = {
            "asset_type": "Dependency", "algorithm": "shared", "library": "shared",
            "version": "1.0.0", "location": "package-lock.json::node_modules/shared",
            "purpose": "Dependency inventory", "confidence": "Manifest entry",
            "evidence": "npm lock", "vulnerable": None
        }
        nested = dict(first, location="package-lock.json::node_modules/parent/node_modules/shared")
        bom_a = generate_sbom([first, nested], "sample")
        bom_b = generate_sbom([nested, first], "sample")
        self.assertEqual(bom_a, bom_b)
        self.assertEqual(len(bom_a["components"]), 2)
        refs = [component["bom-ref"] for component in bom_a["components"]]
        self.assertEqual(len(set(refs)), 2)
        self.assertTrue(validate_sbom(bom_a)["valid"])


if __name__ == "__main__":
    unittest.main()
