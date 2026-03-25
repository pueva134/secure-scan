# SecureScan – Web Vulnerability Scanner

A lightweight Python‑based web vulnerability scanner inspired by OWASP practices.  
Detects missing HTTPS, insecure headers, and exposed ports, with a Flask dashboard and CSV export.

## 🌐 Live Demo

You can try the scanner online:

- **Live URL:**  
  https://secure-scan-uk0e.onrender.com

---

## 🚀 Features

- Checks if a site is reachable over **HTTP vs HTTPS**.
- Detects missing security headers:
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Content-Security-Policy (CSP)`
  - `Strict-Transport-Security (HSTS)`
- Scans common ports: `80`, `443`, `8080`.
- Exports scan results to **CSV** for later analysis.
- Simple **Flask + Bootstrap** dashboard for viewing reports.

---

## 📁 Project Structure

secure-scan/
├── app.py # Flask web dashboard



├── scanner.py # Core scanner logic
├── requirements.txt # Python dependencies
└── templates/
├── index.html # Scan input page
└── report.html # Results page


---

## 🛠 Tech Stack

- Python
- Flask
- Requests
- BeautifulSoup4 (for future XSS/SQLi detection)
- Bootstrap 5
- Git + GitHub
- Render (free hosting)

---

## 🖥 How to Run Locally

1. Clone the repo:

   ```bash
   git clone https://github.com/pueva134/secure-scan.git
   cd secure-scan
