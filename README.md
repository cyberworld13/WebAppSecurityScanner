# Web Application Security Scanner

A Python-based web application security assessment tool built with Flask. The project scans a target web application for selected security indicators and presents the results through a web interface with scan history and downloadable reports.

## Features

- **Web-Based Interface:** Enter a target URL and initiate a scan through a Flask web application.
- **Security Checks:** Identify selected security-related indicators using Python HTTP requests and HTML parsing.
- **Scan History:** Store and review previous scan results using SQLite.
- **Downloadable Reports:** Export scan results as HTML reports.
- **Security Findings:** Display finding details, severity, evidence, impact, and remediation recommendations where available.
- **OWASP Mapping:** Associate applicable findings with relevant OWASP categories where supported.
- **PDF Export:** Use the browser's Print / Save as PDF feature to save a downloaded HTML report as a PDF.

## Technology Stack

- **Language:** Python
- **Web Framework:** Flask
- **HTTP Requests:** Requests
- **HTML Parsing:** BeautifulSoup
- **Database:** SQLite
- **Frontend:** HTML and CSS

## Project Structure

```text
WebAppSecurityScanner/
├── app.py
├── scanner/
│   ├── scanner.py
│   └── vulnerabilities.py
├── database/
│   └── db.py
├── templates/
│   ├── index.html
│   └── history.html
├── static/
│   └── css/
│       └── style.css
├── requirements.txt
├── .gitignore
└── README.md
```

The SQLite database is created locally by the application and is excluded from Git tracking.

## OWASP Top 10:2025 Mapping

The scanner associates selected findings with relevant OWASP Top 10:2025 categories where appropriate. Current mappings include:

- **A02: Security Misconfiguration** — selected security-header, server-information, HTTP-method, directory-listing, and cookie-configuration checks.
- **A04: Cryptographic Failures** — detection of targets accessed without HTTPS.
- **A05: Injection** — reflected-input indicators that require further validation and do not, by themselves, confirm an injection vulnerability.
- **Manual Review** — keyword-based indicators of potentially sensitive information that require human verification.

These mappings represent selected checks only. The scanner does not implement comprehensive detection for all OWASP Top 10:2025 categories.



## Installation and Setup

### 1. Clone the repository

```bash
git clone YOUR_REPOSITORY_URL
cd WebAppSecurityScanner
```

Replace `YOUR_REPOSITORY_URL` with your actual GitHub repository URL.

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the virtual environment

**Windows PowerShell:**

```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

If `requirements.txt` is included in the repository:

```bash
python -m pip install -r requirements.txt
```

### 5. Run the application

```bash
python app.py
```

Open the application in your browser:

`http://127.0.0.1:5000/`

View previous scans at:

`http://127.0.0.1:5000/history`

## How It Works

1. Enter a target URL in the web interface.
2. The Flask application passes the target to the scanner module.
3. The scanner performs its configured checks and collects results.
4. Results are saved to the SQLite database.
5. The user can review previous scans and download an HTML security assessment report.

## Learning Outcomes

- Python web application development using Flask.
- HTTP request handling and HTML parsing.
- Basic web application security assessment concepts.
- SQLite database integration and scan history management.
- Generating security reports and presenting findings.
- Understanding security remediation and OWASP classifications.

## Limitations

This project performs only the checks implemented in its scanner modules. It does not guarantee detection of all vulnerabilities and should not be considered a replacement for a professional security assessment. OWASP mappings do not indicate complete coverage of the OWASP Top 10.

## Ethical Use

Only scan websites and applications that you own or have explicit permission to test. Use this project for educational purposes and authorized security assessments.

## Author

**Sneha Malyal**

Cybersecurity | Web Application Security | Python