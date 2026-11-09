"""Run a local end-to-end demo using Flask's test client.

Creates demo_report.html and demo_cbom.json in the current directory.
No server or browser is started.
"""
import io
import json
import zipfile

from app import app


def main():
    archive_data = io.BytesIO()
    with zipfile.ZipFile(archive_data, "w") as archive:
        archive.writestr(
            "sample/auth.py",
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
        )
        archive.writestr("requirements.txt", "cryptography==42.0.0\n")
    archive_data.seek(0)

    app.config["TESTING"] = True
    response = app.test_client().post(
        "/scan",
        data={"file": (archive_data, "sample-project.zip"), "guideline": "nist"},
        content_type="multipart/form-data",
    )
    if response.status_code != 200:
        raise SystemExit(f"Demo scan failed: {response.status_code} {response.get_data(as_text=True)}")
    payload = response.get_json()
    with open("demo_report.html", "w", encoding="utf-8") as handle:
        handle.write(payload["report_html"])
    with open("demo_cbom.json", "w", encoding="utf-8") as handle:
        json.dump(payload["sbom"], handle, indent=2)
    print(f"Demo complete: {payload['findings']} indicators")
    print("Created demo_report.html and demo_cbom.json")
    print("This demonstrates the local prototype flow only; it is not a detection-accuracy benchmark.")


if __name__ == "__main__":
    main()
