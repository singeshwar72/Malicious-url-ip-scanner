<<<<<<< HEAD
# CyberScan – Malicious URL & IP Scanner
### Cyber Threat Detection and Risk Analysis System

> **B.Tech Computer Science & Engineering | Cybersecurity Project**
> Developed as an ICT Academy Defensive Cybersecurity Submission

---

## Table of Contents

1. [Project Description](#1-project-description)
2. [Problem Statement](#2-problem-statement)
3. [Objectives](#3-objectives)
4. [Features](#4-features)
5. [Technology Stack](#5-technology-stack)
6. [Architecture](#6-architecture)
7. [Folder Structure](#7-folder-structure)
8. [Installation](#8-installation)
9. [Environment Variables](#9-environment-variables)
10. [Database Setup](#10-database-setup)
11. [How to Run](#11-how-to-run)
12. [How to Test](#12-how-to-test)
13. [API Documentation](#13-api-documentation)
14. [Security Considerations](#14-security-considerations)
15. [Limitations](#15-limitations)
16. [Future Enhancements](#16-future-enhancements)
17. [Screenshots](#17-screenshots)
18. [Project Use Cases](#18-project-use-cases)
19. [Viva Questions & Answers](#19-viva-questions--answers)

---

## 1. Project Description

**CyberScan** is a full-stack defensive cybersecurity web application that analyses URLs and IP addresses (IPv4/IPv6) for potential threats. It uses a transparent rule-based risk scoring engine, optional external threat intelligence APIs, and stores all results in a local SQLite database.

The application generates detailed security reports with risk scores (0–100), verdicts (SAFE → MALICIOUS), security indicator breakdowns, and actionable recommendations.

---

## 2. Problem Statement

With the rapid growth of phishing attacks, malware distribution networks, and malicious IP infrastructure, users and security analysts need a reliable way to quickly assess whether a URL or IP address is potentially dangerous before interacting with it. Most commercial tools require paid subscriptions or expose sensitive query data to third parties. This project provides a self-hosted, transparent, educational alternative.

---

## 3. Objectives

- Build a defensive cybersecurity web application for URL and IP threat analysis
- Implement a transparent, deterministic risk scoring engine
- Provide a professional SOC-style dashboard with real-time analytics
- Store and manage scan history in a local SQLite database
- Support optional integration with VirusTotal, AbuseIPDB, and IPinfo
- Ensure no offensive, exploitative, or harmful functionality exists in the codebase

---

## 4. Features

| Feature | Description |
|---------|-------------|
| **URL Analysis** | Scheme, domain, TLD, subdomains, encoding, keywords, HTTPS check, DNS resolution |
| **IPv4/IPv6 Analysis** | Classification (public/private/loopback), reverse DNS, reputation lookup |
| **Risk Engine** | Deterministic 0-100 score with transparent weighted rules |
| **Verdicts** | SAFE / LOW RISK / SUSPICIOUS / HIGH RISK / MALICIOUS |
| **Scan History** | Searchable, filterable, paginated history with delete functionality |
| **Dashboard Analytics** | Live Chart.js charts from real database data |
| **External APIs** | Optional VirusTotal, AbuseIPDB, IPinfo integration |
| **Security Headers** | X-Frame-Options, X-Content-Type-Options, XSS-Protection |
| **Rate Limiting** | Per-IP rate limiting on scan endpoint |
| **Input Validation** | Length, format, scheme checks; parameterised SQL; output escaping |

---

## 5. Technology Stack

### Frontend
- HTML5, CSS3, JavaScript (ES6+)
- Bootstrap 5.3
- Chart.js 4.4
- Bootstrap Icons

### Backend
- Python 3.9+
- Flask 3.0
- Flask-Limiter (rate limiting)

### Database
- SQLite (Python stdlib `sqlite3`)

### Analysis Libraries (stdlib only)
- `urllib.parse` – URL parsing
- `ipaddress` – IP classification
- `socket` – DNS resolution
- `re` – Pattern matching
- `hashlib` – URL fingerprinting
- `datetime` – Timestamps

### Optional External APIs
- VirusTotal API v3
- AbuseIPDB API v2
- IPinfo API

---

## 6. Architecture

```
Browser (HTML/CSS/JS/Bootstrap/Chart.js)
         |
         | HTTP/JSON
         v
Flask Application (app.py)
    |          |
    |          +-- validators.py  → input classification
    |          +-- url_scanner.py → URL analysis
    |          +-- ip_scanner.py  → IP analysis
    |          +-- risk_engine.py → score calculation
    |          +-- reputation_service.py → optional external APIs
    |
    v
SQLite Database (scanner_data.db)
```

**Request Flow:**
1. User submits URL/IP via browser form
2. JavaScript sends POST to `/api/scan`
3. Flask validates and classifies input
4. Scanner module performs passive analysis
5. Risk engine calculates deterministic score
6. Result saved to SQLite database
7. JSON response returned to browser
8. JavaScript renders inline result; full report at `/result/<id>`

---

## 7. Folder Structure

```
malicious-url-ip-scanner/
│
├── app.py                    # Flask application entry point
├── config.py                 # Configuration (reads .env)
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── .env.example              # Environment variable template
├── .gitignore                # Git ignore rules
│
├── database/
│   ├── database.py           # SQLite CRUD helpers
│   └── schema.sql            # Table definitions
│
├── scanner/
│   ├── __init__.py           # Package exports
│   ├── validators.py         # Input validation & classification
│   ├── url_scanner.py        # URL analysis module
│   ├── ip_scanner.py         # IP analysis module
│   └── risk_engine.py        # Risk scoring engine
│
├── services/
│   ├── __init__.py
│   ├── reputation_service.py # External API integration
│   └── dns_service.py        # DNS helper utilities
│
├── templates/
│   ├── base.html             # Base layout template
│   ├── index.html            # Dashboard + scanner
│   ├── result.html           # Scan result report
│   ├── history.html          # Scan history page
│   └── about.html            # About page
│
├── static/
│   ├── css/
│   │   └── style.css         # Dark cybersecurity theme
│   └── js/
│       ├── dashboard.js      # Chart.js initialisation
│       └── scanner.js        # AJAX scan form handler
│
└── tests/
    ├── __init__.py
    ├── test_url_scanner.py   # URL scanner unit tests
    ├── test_ip_scanner.py    # IP scanner unit tests
    └── test_risk_engine.py   # Risk engine unit tests
```

---

## 8. Installation

### Prerequisites
- Python 3.9 or higher
- pip
- Internet connection (for external API calls, if configured)

### Steps

```bash
# 1. Clone or download the project
cd malicious-url-ip-scanner

# 2. Create a virtual environment
python -m venv venv

# 3. Activate the virtual environment

# Windows:
venv\Scripts\activate

# macOS / Linux:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Copy environment variables file
copy .env.example .env        # Windows
# cp .env.example .env        # macOS / Linux
```

---

## 9. Environment Variables

Edit `.env` after copying from `.env.example`:

```env
SECRET_KEY=your-random-secret-key-here
FLASK_ENV=development
FLASK_DEBUG=1

# Optional – leave blank for local-only analysis
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
IPINFO_API_KEY=

RATE_LIMIT=30
DATABASE_PATH=scanner_data.db
```

**API keys are never required.** The application works fully without them using local analysis only.

---

## 10. Database Setup

The SQLite database is created **automatically** when the application starts for the first time. No manual setup is required.

Database file: `scanner_data.db` (in the project root by default)

To reset the database, delete `scanner_data.db` and restart the app.

---

## 11. How to Run

```bash
# Make sure your virtual environment is activated

python app.py
```

Then open your browser at:
```
http://127.0.0.1:5000
```

The application will:
- Automatically create the SQLite database
- Display the dashboard
- Be ready for scanning

---

## 12. How to Test

```bash
# Make sure your virtual environment is activated

# Run all tests
pytest tests/ -v

# Run a specific test file
pytest tests/test_risk_engine.py -v

# Run with coverage (if pytest-cov is installed)
pip install pytest-cov
pytest tests/ --cov=scanner --cov-report=term-missing
```

Expected output: All tests pass ✓

---

## 13. API Documentation

### POST /api/scan
Submit a URL or IP address for analysis.

**Request:**
```json
POST /api/scan
Content-Type: application/json

{
  "target": "https://example.com"
}
```

**Response (success):**
```json
{
  "success": true,
  "scan_id": 42,
  "target": "https://example.com",
  "type": "URL",
  "risk_score": 15,
  "verdict": "SAFE",
  "reasons": [],
  "recommendation": "No significant threats detected...",
  "detail_table": [...],
  "technical": {...},
  "scan_time": "2024-01-01T12:00:00+00:00"
}
```

**Response (error):**
```json
{
  "success": false,
  "error": "Target is required."
}
```

### GET /api/scan/{id}
Retrieve a stored scan by ID.

### DELETE /api/scan/{id}
Delete a scan record by ID.

### GET /api/history
List scans with optional filters.

Query params: `page`, `limit`, `search`, `type`, `verdict`

### DELETE /api/history/clear
Delete all scan records.

### GET /api/stats
Return dashboard statistics (totals, daily counts).

---

## 14. Security Considerations

| Control | Implementation |
|---------|---------------|
| SQL Injection | Parameterised queries throughout `database.py` |
| XSS | Jinja2 auto-escaping + explicit `escHtml()` in JS |
| Command Injection | No `os.system()`, `subprocess`, `eval()`, or `exec()` used |
| Input Validation | Length, format, and scheme checks before processing |
| API Key Security | Keys only in `.env`, never in source code |
| Rate Limiting | Flask-Limiter per-IP on `/api/scan` |
| Security Headers | X-Frame-Options, X-Content-Type-Options, X-XSS-Protection |
| No Active Probing | URLs are never visited; only passive DNS + API lookup |

---

## 15. Limitations

- **No real-time traffic analysis** – passive/static analysis only
- **No certificate inspection** – does not validate TLS certificates
- **DNS-dependent** – DNS resolution requires network connectivity
- **No browser sandbox** – does not execute JavaScript from URLs
- **Local API rate limits** – External API quotas depend on your plan
- **IPv6 external checks** – AbuseIPDB has limited IPv6 coverage
- **No user authentication** – single-user local application

---

## 16. Future Enhancements

1. **User Authentication** – Multi-user support with login/logout
2. **Scheduled Scans** – Periodic re-scanning of saved targets
3. **Bulk Import** – CSV upload for mass URL/IP scanning
4. **Threat Feed Integration** – AlienVault OTX, Shodan, etc.
5. **PDF Report Export** – Downloadable scan reports
6. **Email Alerts** – Notify on MALICIOUS verdict
7. **REST API Key Auth** – Secure API access with tokens
8. **WHOIS Lookup** – Domain registration data
9. **SSL Certificate Check** – Inspect TLS cert validity and issuer
10. **Browser Extension** – One-click scan from browser toolbar

---

## 17. Screenshots

> *(Add screenshots here after running the application)*

- `screenshots/dashboard.png` – Dashboard with statistics and scan panel
- `screenshots/scan_result.png` – Security report for a URL
- `screenshots/history.png` – Filtered scan history table
- `screenshots/about.png` – About page

---

## 18. Project Use Cases

| Use Case | Description |
|----------|-------------|
| **Phishing Detection** | Students / employees verify suspicious email links |
| **SOC Triage** | Security analysts quickly score URLs from alerts |
| **Threat Research** | Academic study of malicious URL patterns |
| **IT Admin** | Check IPs attempting to connect to network infrastructure |
| **Education** | Demonstrate cybersecurity concepts in classroom |

---

## 19. Viva Questions & Answers

**Q1: What is the purpose of this project?**
> CyberScan is a defensive cybersecurity tool that analyses URLs and IP addresses for potential threats using passive, read-only techniques. It generates risk scores and verdicts to help users identify suspicious or malicious targets.

**Q2: What is the difference between defensive and offensive cybersecurity?**
> Defensive cybersecurity protects systems, detects threats, and assesses risk without attacking or exploiting targets. Offensive cybersecurity (penetration testing) involves authorised simulation of attacks. This project is purely defensive – it never exploits, scans ports, or interacts harmfully with targets.

**Q3: How is the risk score calculated?**
> The risk engine uses a weighted rule table. Each security indicator (e.g., IP-based hostname = 25 pts, HTTP-only = 15 pts, suspicious keywords = 20 pts) contributes to a total score clamped between 0 and 100. The same input always produces the same score (deterministic). External API results can add up to 50 additional points.

**Q4: What are the risk score bands?**
> 0–19: SAFE | 20–39: LOW RISK | 40–59: SUSPICIOUS | 60–79: HIGH RISK | 80–100: MALICIOUS

**Q5: How are SQL injections prevented?**
> All database queries use parameterised statements (`?` placeholders) via Python's `sqlite3` module. User input is never directly concatenated into SQL strings.

**Q6: How does the application handle missing API keys?**
> All external API integrations are wrapped in try/except blocks. If a key is missing or the API is unreachable, the function returns `{"status": "External reputation service not configured"}` and the application continues with local analysis. It never crashes.

**Q7: What Python libraries are used for analysis?**
> `urllib.parse` for URL parsing, `ipaddress` for IP classification, `socket` for DNS/reverse-DNS resolution, `re` for pattern matching, `hashlib` for URL fingerprinting. All are Python standard library modules.

**Q8: How is XSS prevented in the frontend?**
> Jinja2 templates auto-escape all variables by default. In JavaScript, user-provided data inserted into the DOM is escaped through a custom `escHtml()` function that uses `textContent` assignment rather than `innerHTML`.

**Q9: What is a Punycode/IDN homograph attack?**
> Attackers register domains using Unicode characters that look identical to legitimate ASCII domains (e.g., `pаypal.com` using a Cyrillic 'а'). Browsers encode these as Punycode (e.g., `xn--aypal-uye.com`). CyberScan detects `xn--` in hostnames and adds a risk indicator.

**Q10: Why use SQLite instead of PostgreSQL/MySQL?**
> SQLite is a serverless, zero-configuration file-based database that is part of the Python standard library. It is ideal for a self-contained educational project. In production, the database layer (`database.py`) can be swapped for PostgreSQL with minimal changes using SQLAlchemy.

**Q11: What is rate limiting and why is it implemented?**
> Rate limiting restricts how many requests a single IP address can make per minute. It prevents abuse and denial-of-service attacks on the scan endpoint. Flask-Limiter enforces this using in-memory tracking.

**Q12: How are charts populated with real data?**
> The Flask dashboard route queries the SQLite database using aggregate SQL (`COUNT`, `SUM(CASE WHEN...)`) and passes the JSON statistics to the template. JavaScript reads `window.DASHBOARD_STATS` and builds Chart.js charts from these live values – no hard-coded data.

---

*CyberScan – Defensive Cybersecurity Tool | B.Tech CSE Project | For Authorised Educational Use Only*
=======
# Malicious-url-ip-scanner
🔐 **Malicious URL &amp; IP Scanner** — A cybersecurity web application that analyzes URLs and IP addresses to identify potentially malicious or suspicious activity. Built with Python/Flask, HTML, CSS, and JavaScript, it provides security checks, risk assessment, and easy-to-understand scan results for educational and authorized security analysis.
>>>>>>> 4451477c059d0d0221171ba294558b45373eac71
