#!/usr/bin/env python3
"""HTML report renderer for SUSTUM.

All report values are escaped before insertion into HTML. The embedded JSON is
serialized separately and escapes HTML-significant characters before being
placed in a script element.
"""
import html
import json


def _e(value):
    return html.escape("" if value is None else str(value), quote=True)


def _json_for_html(value):
    return (json.dumps(value or {}, ensure_ascii=False)
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


def render_report(name, guideline, items, decision, reason, impact_data, sbom=None):
    items = items or []
    impact_data = impact_data or {}
    total = len(items)
    vulnerable_count = sum(1 for item in items if item.get("vulnerable") is True)
    safe_count = sum(1 for item in items if item.get("vulnerable") is False)
    unknown_count = total - vulnerable_count - safe_count
    payload = _json_for_html(sbom or {})
    headers = ("Location", "Asset type", "Algorithm / dependency", "Version / key size",
               "Purpose", "Protocol", "Library", "Quantum-vulnerable indicator",
               "Confidence", "Evidence")
    rows = []
    for item in items:
        values = (
            item.get("location"), item.get("asset_type"), item.get("algorithm"),
            item.get("version") if item.get("asset_type") == "Dependency" else item.get("key_size"),
            item.get("purpose"), item.get("protocol"), item.get("library"),
            ("Yes" if item.get("vulnerable") is True else
             "No" if item.get("vulnerable") is False else "Unknown"),
            item.get("confidence"), item.get("evidence", item.get("notes"))
        )
        rows.append("<tr>" + "".join("<td>" + _e(value) + "</td>" for value in values) + "</tr>")
    if not rows:
        rows.append('<tr><td colspan="10">No indicators found. This is not proof that no cryptography exists.</td></tr>')
    metric_rows = []
    for metric in impact_data.get("size_metrics", []):
        metric_rows.append("<tr>" + "".join(
            "<td>" + _e(metric.get(key)) + "</td>"
            for key in ("algorithm", "pub_key_size", "sig_size", "quantum_safe")
        ) + "</tr>")
    changes = "".join("<li>" + _e(path) + "</li>" for path in impact_data.get("part_changes", []))
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SUSTUM — PQC inventory report</title>
<style>
body{font:15px system-ui,sans-serif;background:#f5f7fb;color:#172033;margin:0;padding:24px}
main{max-width:1200px;margin:auto;background:white;padding:28px;border:1px solid #dce2ea;border-radius:12px}
h1{font-size:24px}h2{font-size:18px;margin-top:28px}
.metrics{display:flex;gap:12px;flex-wrap:wrap}.metric{padding:14px;background:#f1f5f9;border-radius:8px;min-width:120px}
.metric strong{display:block;font-size:24px}table{border-collapse:collapse;width:100%;display:block;overflow-x:auto}
th,td{padding:9px;border:1px solid #dce2ea;text-align:left;font-size:13px;vertical-align:top}
th{background:#f1f5f9}button{padding:10px 14px;background:#1d4ed8;color:white;border:0;border-radius:7px;cursor:pointer}
.note{color:#526075;font-size:13px}
</style></head><body><main>
<h1>SUSTUM — Cryptographic inventory report</h1>
<p><b>Input:</b> __NAME__ &nbsp; <b>Guideline profile:</b> __GUIDELINE__</p>
<div class="metrics">
<div class="metric">Total indicators<strong>__TOTAL__</strong></div>
<div class="metric">Vulnerable indicators<strong>__VULNERABLE__</strong></div>
<div class="metric">Not flagged vulnerable<strong>__SAFE__</strong></div>
<div class="metric">Unknown<strong>__UNKNOWN__</strong></div>
</div>
<h2>Static inventory findings</h2>
<table><thead><tr>__HEADERS__</tr></thead><tbody>__ROWS__</tbody></table>
<h2>Illustrative parameter-size reference</h2>
<p class="note">These are reference parameter sizes, not measurements of this application’s traffic or deployment.</p>
<table><thead><tr><th>Algorithm</th><th>Public key</th><th>Signature / ciphertext</th><th>Quantum resistance note</th></tr></thead><tbody>__METRICS__</tbody></table>
<h2>Files with vulnerable indicators</h2><ul>__CHANGES__</ul>
<h2>Assessment</h2><p><b>Result:</b> __DECISION__</p><p>__REASON__</p>
<p class="note">Advisory static analysis only. It does not establish runtime usage, cryptographic safety, compliance, or production readiness. Review evidence before acting.</p>
<button type="button" id="download">Export CBOM JSON</button>
<script type="application/json" id="cbom-data">__PAYLOAD__</script>
<script>
document.getElementById("download").addEventListener("click", function () {
  const text = document.getElementById("cbom-data").textContent;
  const blob = new Blob([text], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url; link.download = "sustum-cbom.json"; link.click();
  URL.revokeObjectURL(url);
});
</script>
</main></body></html>""".replace("__NAME__", _e(name)).replace(
        "__GUIDELINE__", _e(guideline)).replace("__TOTAL__", str(total)).replace(
        "__VULNERABLE__", str(vulnerable_count)).replace("__SAFE__", str(safe_count)).replace(
        "__UNKNOWN__", str(unknown_count)).replace(
        "__HEADERS__", "".join("<th>" + _e(header) + "</th>" for header in headers)).replace(
        "__ROWS__", "".join(rows)).replace(
        "__METRICS__", "".join(metric_rows) or "<tr><td colspan='4'>No reference data</td></tr>").replace(
        "__CHANGES__", changes or "<li>No vulnerable indicators identified</li>").replace(
        "__DECISION__", _e(decision)).replace("__REASON__", _e(reason)).replace(
        "__PAYLOAD__", payload)
