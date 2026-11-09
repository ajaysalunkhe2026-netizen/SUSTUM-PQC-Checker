"""Dependency manifest inventory parsers.

This module inventories declarations and lockfile records. It does not infer that
a package is used for cryptography, nor does it resolve dependency graphs itself.
"""
import json
import re

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


def _record(name, version, path, ecosystem, source_kind, scope="unknown",
            relationship="unknown", version_kind="declared"):
    return {
        "location": path,
        "asset_type": "Dependency",
        "algorithm": name,
        "key_size": "Unknown",
        "purpose": "Dependency inventory",
        "protocol": "-",
        "library": name,
        "version": version or "unspecified",
        "vulnerable": None,
        "confidence": "Manifest entry",
        "evidence": f"{source_kind}; cryptographic usage not established.",
        "notes": "Dependency inventory only; package presence does not prove cryptographic use.",
        "ecosystem": ecosystem,
        "source_kind": source_kind,
        "dependency_scope": scope,
        "dependency_relationship": relationship,
        "version_kind": version_kind,
    }


def _pep508_name(spec):
    # Extract only the normalized project name; retain the original constraint
    # as the version field rather than pretending it is a resolved version.
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", str(spec))
    return (match.group(1), str(spec)[match.end():].strip() or "unspecified") if match else (None, None)


def parse_pyproject(path, rel_path):
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError, TypeError):
        return []
    rows = []
    project = data.get("project") or {}
    for spec in project.get("dependencies", []) or []:
        name, version = _pep508_name(spec)
        if name:
            rows.append(_record(name, version, rel_path, "pypi", "pyproject.toml project.dependencies", "runtime"))
    for scope, specs in (project.get("optional-dependencies") or {}).items():
        for spec in specs or []:
            name, version = _pep508_name(spec)
            if name:
                rows.append(_record(name, version, rel_path, "pypi", "pyproject.toml optional-dependencies", f"optional:{scope}"))
    poetry = (data.get("tool") or {}).get("poetry") or {}
    for group_name, group in (poetry.get("group") or {}).items():
        for name, constraint in (group.get("dependencies") or {}).items():
            if str(name).lower() != "python":
                version = constraint.get("version", "unspecified") if isinstance(constraint, dict) else constraint
                rows.append(_record(name, str(version), rel_path, "pypi", "pyproject.toml poetry group", group_name))
    for name, constraint in (poetry.get("dependencies") or {}).items():
        if str(name).lower() != "python":
            version = constraint.get("version", "unspecified") if isinstance(constraint, dict) else constraint
            rows.append(_record(name, str(version), rel_path, "pypi", "pyproject.toml poetry.dependencies", "runtime"))
    for name, constraint in (poetry.get("dev-dependencies") or {}).items():
        version = constraint.get("version", "unspecified") if isinstance(constraint, dict) else constraint
        rows.append(_record(name, str(version), rel_path, "pypi", "pyproject.toml poetry.dev-dependencies", "development"))
    return rows


def parse_pipfile(path, rel_path):
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError, TypeError):
        return []
    rows = []
    for section, scope in (("packages", "runtime"), ("dev-packages", "development")):
        for name, constraint in (data.get(section) or {}).items():
            version = constraint.get("version", "unspecified") if isinstance(constraint, dict) else constraint
            rows.append(_record(name, str(version), rel_path, "pypi", f"Pipfile {section}", scope))
    return rows


def parse_pipfile_lock(path, rel_path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    rows = []
    for section, scope in (("default", "runtime"), ("develop", "development")):
        for name, item in (data.get(section) or {}).items():
            version = item.get("version", "unspecified") if isinstance(item, dict) else "unspecified"
            rows.append(_record(name, str(version), rel_path, "pypi", f"Pipfile.lock {section}", scope,
                                version_kind="locked"))
    return rows


def _npm_rows(entries, rel_path, source_kind, relationship):
    rows = []
    if not isinstance(entries, dict):
        return rows
    for name, item in entries.items():
        if not isinstance(item, dict):
            continue
        version = item.get("version") or item.get("resolved") or "unspecified"
        dev = bool(item.get("dev", False))
        optional = bool(item.get("optional", False))
        scope = "development" if dev else ("optional" if optional else "runtime")
        rows.append(_record(name, str(version), rel_path, "npm", source_kind, scope,
                            relationship, "locked" if item.get("version") else "resolved-url-or-unspecified"))
    return rows


def parse_npm_lock(path, rel_path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    rows = []
    # npm lockfile v2/v3: package paths include nested node_modules and encode
    # resolved package instances. Root package (empty key) is not a dependency.
    packages = data.get("packages")
    if isinstance(packages, dict):
        for package_path, item in packages.items():
            if not package_path or not isinstance(item, dict):
                continue
            marker = "node_modules/"
            if marker in package_path:
                name = package_path.rsplit(marker, 1)[-1]
                rows.extend(_npm_rows({name: item}, rel_path, "package-lock.json packages", "transitive-or-direct"))
        return rows
    # npm lockfile v1 stores a nested dependencies tree.
    def walk(dependencies, relationship):
        if not isinstance(dependencies, dict):
            return
        for name, item in dependencies.items():
            if not isinstance(item, dict):
                continue
            rows.extend(_npm_rows({name: item}, rel_path, "package-lock.json dependencies", relationship))
            walk(item.get("dependencies"), "transitive")
    walk(data.get("dependencies"), "direct-or-transitive")
    return rows


def parse_go_sum(path, rel_path):
    rows = []
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line_no, raw in enumerate(handle, 1):
                parts = raw.strip().split()
                if len(parts) < 2:
                    continue
                module, version = parts[0], parts[1]
                if version.endswith("/go.mod"):
                    version = version[:-7]
                rows.append(_record(module, version, f"{rel_path}:{line_no}", "go",
                                    "go.sum checksum record", "unknown", "unknown", "checksum-recorded"))
    except OSError:
        return []
    return rows


def parse_manifest(path, rel_path):
    """Return dependency inventory records for supported manifest/lockfile names."""
    name = rel_path.rsplit("/", 1)[-1].lower()
    if name == "pyproject.toml":
        return parse_pyproject(path, rel_path)
    if name == "pipfile":
        return parse_pipfile(path, rel_path)
    if name == "pipfile.lock":
        return parse_pipfile_lock(path, rel_path)
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return parse_npm_lock(path, rel_path)
    if name == "go.sum":
        return parse_go_sum(path, rel_path)
    return []
