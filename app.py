import os
import tempfile
import zipfile
from pathlib import PurePosixPath

from flask import Flask, request, jsonify
from flask_cors import CORS

from scanner import scan_directory
from recommend import recommend, decide, impact, generate_sbom
from report import render_report

app = Flask(__name__)
# Prototype default: local API only. Configure explicit trusted origins before deployment.
CORS(app, resources={r"/health": {"origins": []}, r"/scan": {"origins": []}})
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024
MAX_UNCOMPRESSED_SIZE = 500 * 1024 * 1024
MAX_SINGLE_FILE_SIZE = 100 * 1024 * 1024
MAX_FILES = 10000


def safe_extract(zip_ref, extract_path):
    """Extract ZIP entries with path, symlink, count and size checks."""
    total_size = 0
    infos = zip_ref.infolist()
    if len(infos) > MAX_FILES:
        raise ValueError("Archive contains too many entries.")
    root = os.path.realpath(extract_path)
    for info in infos:
        name = info.filename.replace("\\", "/")
        path = PurePosixPath(name)
        mode = (info.external_attr >> 16) & 0o170000
        if (not name or "\x00" in name or path.is_absolute()
                or (path.parts and ":" in path.parts[0])
                or ".." in path.parts or mode == 0o120000):
            raise ValueError("Unsafe ZIP entry path or symlink detected.")
        if info.file_size < 0 or info.file_size > MAX_SINGLE_FILE_SIZE:
            raise ValueError("An archive entry exceeds the 100 MB file limit.")
        total_size += info.file_size
        if total_size > MAX_UNCOMPRESSED_SIZE:
            raise ValueError("Uncompressed archive exceeds 500 MB limit.")
        if info.is_dir():
            continue
        destination = os.path.realpath(os.path.join(root, *path.parts))
        if os.path.commonpath([root, destination]) != root:
            raise ValueError("ZIP entry escapes extraction directory.")
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        written = 0
        with zip_ref.open(info) as source, open(destination, "wb") as target:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_SINGLE_FILE_SIZE:
                    raise ValueError("An extracted file exceeds the 100 MB file limit.")
                target.write(chunk)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "SUSTUM PQC Checker"})


@app.post("/scan")
def scan_endpoint():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    upload = request.files["file"]
    if not upload.filename or not upload.filename.lower().endswith(".zip"):
        return jsonify({"error": "Upload a ZIP archive with a .zip filename"}), 400
    guideline = request.form.get("guideline", "nist").lower()
    if guideline not in {"nist", "cnsa"}:
        return jsonify({"error": "guideline must be 'nist' or 'cnsa'"}), 400

    safe_name = os.path.basename(upload.filename.replace("\\", "/"))
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "upload.zip")
        upload.save(zip_path)
        extract_dir = os.path.join(tmpdir, "source")
        os.makedirs(extract_dir)
        try:
            with zipfile.ZipFile(zip_path) as archive:
                safe_extract(archive, extract_dir)
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError) as exc:
            return jsonify({"error": str(exc)}), 400

        raw_items = scan_directory(extract_dir)
        recs = recommend(raw_items, guideline)
        decision, reason = decide(recs)
        impact_data = impact(recs)
        sbom = generate_sbom(raw_items, safe_name)
        html_content = render_report(safe_name, guideline.upper(), recs,
                                     decision, reason, impact_data, sbom)
        return jsonify({
            "part": safe_name,
            "guideline": guideline,
            "findings": len(recs),
            "algorithm_findings": sum(1 for row in recs if row.get("asset_type") == "Algorithm"),
            "dependency_count": sum(1 for row in recs if row.get("asset_type") == "Dependency"),
            "decision": decision,
            "reason": reason,
            "report_html": html_content,
            "sbom_generated": True,
            "sbom": sbom,
            "limitations": [
                "Static source and manifest analysis only; no runtime or network discovery.",
                "A manifest entry does not prove that a dependency uses cryptography.",
                "CBOM output requires validation against the selected CycloneDX schema before compliance use."
            ]
        })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, threaded=True)
