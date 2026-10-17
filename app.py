from flask import Flask, render_template, request, Response, abort, redirect, url_for
import json
from html import escape
from datetime import datetime

from scanner.scanner import scan_target    # this line connects app.py with scanner/scanner.py

from database.db import (
    initialize_database,
    save_scan,
    get_scan_history,
    get_connection,
    clear_scan_history,
    delete_scan

)

app = Flask(__name__)
initialize_database()

@app.route("/")    # opens /, show the homepage
def home():

    return render_template("index.html")


@app.route("/scan", methods=["POST"]) 
def scan():

    target_url = request.form.get("url", "").strip()

    result = scan_target(target_url)    # actually starts the scan.
    save_scan(target_url, result)    

    return render_template(
        "index.html",
        result=result,
        scanned=True
    )


@app.route("/history")
def history():
    scans = get_scan_history()

    return render_template(
        "history.html",
        scans=scans
    )


@app.route("/clear-history", methods=["POST"])
def clear_history():
    clear_scan_history()
    return redirect(url_for("history"))



@app.route("/delete-scan/<int:scan_id>", methods=["POST"])
def delete_single_scan(scan_id):
    delete_scan(scan_id)
    return redirect(url_for("history"))



@app.route("/report/<int:scan_id>")
def download_report(scan_id):
    connection = get_connection()

    try:
        record = connection.execute(
            """
            SELECT id, target_url, scanned_at, status_code,
                   scan_result, error
            FROM scan_history
            WHERE id = ?
            """,
            (scan_id,)
        ).fetchone()
    finally:
        connection.close()

    if record is None:
        abort(404)

    try:
        result = json.loads(record["scan_result"])
    except (json.JSONDecodeError, TypeError):
        result = {}

    findings = result.get("findings") or []

    def safe(value):
        if value is None or value == "":
            return "Not available"
        if isinstance(value, (dict, list)):
            value = json.dumps(value, indent=2, ensure_ascii=False)
        return escape(str(value))

    sections = []

    for finding in findings:
        sections.append(f"""
        <section>
            <h3>{safe(finding.get('title'))}</h3>
            <p><strong>Severity:</strong> {safe(finding.get('severity'))}</p>
            <p><strong>Description:</strong> {safe(finding.get('description'))}</p>
            <p><strong>Evidence:</strong></p>
            <pre>{safe(finding.get('evidence'))}</pre>
            <p><strong>Impact:</strong> {safe(finding.get('impact'))}</p>
            <p><strong>Recommendation:</strong> {safe(finding.get('recommendation'))}</p>
            <p><strong>OWASP mapping:</strong> {safe(finding.get('owasp'))}</p>
        </section>
        """)

    if not sections:
        sections.append("<p>No findings recorded by the current checks.</p>")

    report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Web Application Security Assessment Report</title><style>
body {{ font-family: Arial, sans-serif; max-width: 900px;
       margin: 35px auto; padding: 0 20px; line-height: 1.6; }}
h1 {{ color: #38318d; }}
section, .summary {{ border: 1px solid #ddd; border-radius: 8px;
                     padding: 16px; margin: 16px 0; }}
pre {{ white-space: pre-wrap; overflow-wrap: anywhere;
       background: #f4f4f8; padding: 10px; }}
@media print {{ .no-print {{ display: none; }} }}
</style>
</head>
<body>
<h1>Web Application Security Assessment</h1>
<p><strong>Generated:</strong> {safe(datetime.now().astimezone().isoformat(timespec='seconds'))}</p>

<h2>Scan Summary</h2>
<div class="summary">
<p><strong>Target:</strong> {safe(record['target_url'])}</p>
<p><strong>Scan date:</strong> {safe(record['scanned_at'])}</p>
<p><strong>HTTP status:</strong> {safe(record['status_code'])}</p>
<p><strong>Findings:</strong> {len(findings)}</p>
<p><strong>Error:</strong> {safe(record['error'])}</p>
<p><strong>Pages discovered:</strong> {safe(result.get('total_pages'))}</p>
<p><strong>Forms discovered:</strong> {safe(result.get('total_forms'))}</p>
</div>

<h2>Security Findings</h2>
{''.join(sections)}

<h2>Limitations</h2>
<p>This report covers only checks performed by this scanner. It does not
guarantee that the website is secure or that every vulnerability was detected.
OWASP labels do not imply complete OWASP Top 10 coverage.</p>
<p>Only test websites you own or have permission to assess.</p>

<div class="no-print">
<button onclick="window.print()">Print / Save as PDF</button>
<a href="/history">Back to history</a>
</div>
</body>
</html>
"""

    return Response(
        report,
        mimetype="text/html",
        headers={
                    "Content-Disposition":
                        'attachment; filename="security_assessment_report.html"'
                }
    )



if __name__ == "__main__":
    app.run(debug=True)