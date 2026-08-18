#!/usr/bin/env python3
import json

def render_report(name, guideline, items, decision, reason, impact_data):
    total = len(items)
    vulnerable_count = sum(1 for i in items if i.get("vulnerable"))
    safe_count = total - vulnerable_count
    confirmed_count = sum(1 for i in items if i.get("confidence") in ["Confirmed", "Confirmed via AST"])
    suspected_count = total - confirmed_count

    decision_color = "#16a34a" if decision == "Go" else "#d97706"

    # CycloneDX SBOM Payload data embedded into JS for direct client-side download
    sbom_payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": name,
                "guideline": guideline
            }
        },
        "components": [
            {
                "type": "library",
                "name": i.get("library") if i.get("library") != "-" else i.get("algorithm"),
                "version": i.get("key_size", "unknown"),
                "scope": i.get("purpose"),
                "vulnerable_to_quantum": i.get("vulnerable", False)
            } for i in items
        ]
    }
    sbom_json_str = json.dumps(sbom_payload, indent=2)

    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>SUSTUM PQC Checker — Report</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #f4f7fb;
      color: #1e293b;
      margin: 0;
      padding: 30px;
    }}
    .container {{
      max-width: 1200px;
      margin: auto;
      background: #ffffff;
      padding: 32px;
      border-radius: 16px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
      border: 1px solid #e2e8f0;
    }}
    .top-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid #f1f5f9;
      padding-bottom: 20px;
      margin-bottom: 24px;
    }}
    h1 {{
      font-size: 24px;
      margin: 0;
      color: #0f172a;
    }}
    .meta-info {{
      font-size: 13px;
      color: #64748b;
      text-align: right;
    }}
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 30px;
    }}
    .metric-card {{
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      padding: 16px;
      border-radius: 10px;
    }}
    .metric-card .label {{
      font-size: 12px;
      font-weight: 600;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .metric-card .value {{
      font-size: 24px;
      font-weight: 700;
      color: #0f172a;
      margin-top: 6px;
    }}
    .section {{
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 10px;
      padding: 20px;
      margin-bottom: 24px;
    }}
    .section h3 {{
      margin-top: 0;
      font-size: 16px;
      color: #0f172a;
      border-bottom: 1px solid #f1f5f9;
      padding-bottom: 10px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
    }}
    th, td {{
      padding: 10px 12px;
      border: 1px solid #e2e8f0;
      text-align: left;
      font-size: 13px;
    }}
    th {{
      background: #f8fafc;
      font-weight: 600;
      color: #475569;
    }}
    .badge-yes {{
      color: #dc2626;
      font-weight: 600;
    }}
    .badge-no {{
      color: #16a34a;
      font-weight: 600;
    }}
    .btn {{
      background: #1d4ed8;
      color: #fff;
      padding: 10px 18px;
      border-radius: 8px;
      text-decoration: none;
      font-size: 13px;
      font-weight: 600;
      display: inline-block;
      border: none;
      cursor: pointer;
    }}
    .btn:hover {{
      background: #1e40af;
    }}
  </style>
  <script>
    function downloadSBOM() {{
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent({json.dumps(sbom_json_str)});
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", "sustum-pqc-sbom.json");
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    }}
  </script>
</head>
<body>
  <div class="container">
    <div class="top-header">
      <div>
        <h1>SUSTUM PQC Checker — Enterprise Report</h1>
      </div>
      <div class="meta-info">
        Part: <b>{name}</b> | Guideline: <b>{guideline.upper()}</b> | Decision: <span style="color: {decision_color}; font-weight:700;">{decision}</span>
      </div>
    </div>

    <div class="metrics-grid">
      <div class="metric-card">
        <div class="label">Total Findings</div>
        <div class="value">{total}</div>
      </div>
      <div class="metric-card">
        <div class="label">Quantum-Vulnerable</div>
        <div class="value" style="color: #dc2626;">{vulnerable_count}</div>
      </div>
      <div class="metric-card">
        <div class="label">Already Safe</div>
        <div class="value" style="color: #16a34a;">{safe_count}</div>
      </div>
      <div class="metric-card">
        <div class="label">Confirmed / Suspected</div>
        <div class="value">{confirmed_count} / {suspected_count}</div>
      </div>
    </div>

    <div class="section">
      <h3>A. Classical View — Inventory</h3>
      <table>
        <tr>
          <th>Location</th>
          <th>Asset Type</th>
          <th>Algorithm</th>
          <th>Key Size</th>
          <th>Purpose</th>
          <th>Protocol</th>
          <th>Library</th>
          <th>Vulnerable</th>
          <th>Confidence</th>
          <th>Notes</th>
        </tr>
"""
    for i in items:
        vuln_class = "badge-yes" if i.get("vulnerable") else "badge-no"
        vuln_text = "Yes" if i.get("vulnerable") else "No"
        html += f"""
        <tr>
          <td>{i.get("location")}</td>
          <td>{i.get("asset_type")}</td>
          <td><b>{i.get("algorithm")}</b></td>
          <td>{i.get("key_size")}</td>
          <td>{i.get("purpose")}</td>
          <td>{i.get("protocol")}</td>
          <td>{i.get("library")}</td>
          <td><span class="{vuln_class}">{vuln_text}</span></td>
          <td>{i.get("confidence")}</td>
          <td>{i.get("notes")}</td>
        </tr>
        """

    html += f"""
      </table>
    </div>

    <div class="section">
      <h3>B. Recommendation View</h3>
      <table>
        <tr>
          <th>Location</th>
          <th>Asset Type</th>
          <th>Algorithm</th>
          <th>Key Size</th>
          <th>Purpose</th>
          <th>Protocol</th>
          <th>Library</th>
          <th>Vulnerable</th>
          <th>Confidence</th>
          <th>Notes</th>
          <th>Mode</th>
          <th>Recommendation</th>
        </tr>
"""
    for i in items:
        vuln_class = "badge-yes" if i.get("vulnerable") else "badge-no"
        vuln_text = "Yes" if i.get("vulnerable") else "No"
        html += f"""
        <tr>
          <td>{i.get("location")}</td>
          <td>{i.get("asset_type")}</td>
          <td><b>{i.get("algorithm")}</b></td>
          <td>{i.get("key_size")}</td>
          <td>{i.get("purpose")}</td>
          <td>{i.get("protocol")}</td>
          <td>{i.get("library")}</td>
          <td><span class="{vuln_class}">{vuln_text}</span></td>
          <td>{i.get("confidence")}</td>
          <td>{i.get("notes")}</td>
          <td><b>{i.get("mode")}</b></td>
          <td style="color: #1d4ed8; font-weight: 600;">{i.get("recommendation")}</td>
        </tr>
        """

    html += f"""
      </table>
    </div>

    <div class="section">
      <h3>C. Change & Impact Analysis (Payload Growth Metrics)</h3>
      <p style="font-size: 13px; color: #475569;">{impact_data.get('overall_note')}</p>
      <table>
        <tr>
          <th>Algorithm Type</th>
          <th>Public Key Size</th>
          <th>Signature / Ciphertext Size</th>
          <th>Quantum Safe</th>
        </tr>
"""
    for m in impact_data.get('size_metrics', []):
        html += f"""
        <tr>
          <td><b>{m['algorithm']}</b></td>
          <td>{m['pub_key_size']}</td>
          <td>{m['sig_size']}</td>
          <td>{m['quantum_safe']}</td>
        </tr>
        """

    html += f"""
      </table>
      <p style="font-size: 13px; margin-top: 15px;"><b>Expected files/config in this part:</b></p>
      <ul>
"""
    for f in impact_data.get('part_changes', []):
        html += f"<li>{f}</li>"

    html += f"""
      </ul>
    </div>

    <div class="section">
      <h3>D. Decision</h3>
      <p style="font-size: 15px; font-weight: 700; color: {decision_color}; margin-bottom: 5px;">{decision}</p>
      <p style="font-size: 13px; color: #475569; margin-top: 0;">{reason}</p>
      <p style="font-size: 12px; color: #94a3b8; margin-bottom: 20px;">This tool is advisory only. It did not apply any change.</p>
      
      <button class="btn" onclick="downloadSBOM()">📥 Export CycloneDX SBOM (JSON)</button>
    </div>
  </div>
</body>
</html>
    """
    return html