import os
import zipfile
import requests
import webbrowser
import time

print("🏗️ Step 1: Building Dummy Enterprise Repository...")
os.makedirs("dummy_repo", exist_ok=True)

# 1. Python Code (Testing AST Parser)
with open("dummy_repo/auth.py", "w") as f:
    f.write("from cryptography.hazmat.primitives.asymmetric import rsa\n")
    f.write("private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")

# 2. JS / Config (Testing Regex & Context)
with open("dummy_repo/config.js", "w") as f:
    f.write("// Connect securely\n")
    f.write("const tlsConfig = { protocol: 'TLS-1.2', cipher: 'ECDSA-WITH-AES-256-GCM' };\n")

# 3. Environment variables (Testing Config vulnerabilities)
with open("dummy_repo/.env", "w") as f:
    f.write("DEFAULT_SIGNATURE=RSA-2048\nENCRYPTION=AES-256\n")

# 4. Requirements (Testing Supply Chain / SBOM)
with open("dummy_repo/requirements.txt", "w") as f:
    f.write("cryptography==41.0.3\nPyJWT==2.8.0\nrequests==2.31.0\n")

print("📦 Step 2: Zipping the repository...")
with zipfile.ZipFile("test_repo.zip", "w") as zipf:
    for root, _, files in os.walk("dummy_repo"):
        for file in files:
            zipf.write(os.path.join(root, file), file)

print("🚀 Step 3: Sending to SUSTUM PQC Engine for Audit...")
url = "http://127.0.0.1:5050/scan"
with open("test_repo.zip", "rb") as f:
    files = {"file": ("test_repo.zip", f)}
    data = {"guideline": "nist"} 
    
    try:
        response = requests.post(url, files=files, data=data)
        if response.status_code == 200:
            print("✅ Scan Successful! Check the backend logs.")
            
            # Step 4: Auto-open the generated HTML report
            report_path = os.path.abspath("report.html")
            if os.path.exists(report_path):
                print(f"🎉 Opening Executive Report in your browser...")
                webbrowser.open(f"file://{report_path}")
            else:
                print("⚠️ HTML Report nahi mili.")
        else:
            print("❌ Server error:", response.text)
    except Exception as e:
        print("❌ Backend se connect nahi ho paya.", e)