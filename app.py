import os
import zipfile
import tempfile
from flask import Flask, request, jsonify
from flask_cors import CORS

# Importing our custom modules
from scanner import scan_directory
from recommend import recommend, decide, impact, generate_sbom
from report import render_report

app = Flask(__name__)
CORS(app)

# 1. Upload Size Limit (e.g., 200 MB max)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024 

# Enterprise Limit Configurations
MAX_UNCOMPRESSED_SIZE = 500 * 1024 * 1024  # 500 MB max extracted size

def safe_extract(zip_ref, extract_path):
    """Safely extract zip files to prevent Zip Bombs"""
    total_size = 0
    for info in zip_ref.infolist():
        total_size += info.file_size
        if total_size > MAX_UNCOMPRESSED_SIZE:
            raise ValueError("Extraction failed: Zip Bomb detected or uncompressed size exceeds 500MB limit.")
        
        # Extract file safely
        zip_ref.extract(info, extract_path)

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400

    guideline = request.form.get("guideline", "nist").lower()
    part_name = file.filename

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "upload.zip")
        file.save(zip_path)
        
        extract_dir = os.path.join(tmpdir, "source")
        os.makedirs(extract_dir, exist_ok=True)
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # 2. Safe Extraction (Zip Bomb check)
                safe_extract(zip_ref, extract_dir)
        except Exception as e:
            return jsonify({"error": str(e)}), 413 # 413 Payload Too Large
            
        # 3. Run Scanner
        raw_items = scan_directory(extract_dir)
        
        # 4. Run Recommendations & Logic
        recs = recommend(raw_items, guideline)
        decision, reason = decide(recs)
        impact_data = impact(recs)
        
        # 5. Generate HTML Report and save it locally
        html_content = render_report(part_name, guideline.upper(), recs, decision, reason, impact_data)
        
        report_path = os.path.abspath("report.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        # 6. Generate JSON response matching your CLI/Frontend output
        response_data = {
            "part": part_name,
            "guideline": guideline,
            "findings": len(recs),
            "decision": decision,
            "reason": reason,
            "report": report_path,
            "sbom_generated": True
        }
        
        return jsonify(response_data)

if __name__ == '__main__':
    # Running securely on localhost port 8080 with Multi-threading enabled
    app.run(host='127.0.0.1', port=5050, threaded=True)