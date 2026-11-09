"""Strict CycloneDX JSON validation using the CycloneDX project's validator."""
import json

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator


def validate_sbom(bom):
    """Validate a BOM against the official CycloneDX 1.6 JSON schema."""
    validator = JsonStrictValidator(schema_version=SchemaVersion.V1_6)
    error = validator.validate_str(json.dumps(bom))
    if error is None:
        return {"valid": True, "spec_version": "1.6", "errors": []}
    return {"valid": False, "spec_version": "1.6", "errors": [str(error)]}
