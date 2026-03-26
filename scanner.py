import requests
import socket
from urllib.parse import urlparse
import csv
import os
from datetime import datetime



def is_https(url):
    return urlparse(url).scheme == "https"



def get_status(url):
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        uses_https = resp.url.startswith("https://")
        missing_https = not uses_https
        return resp.status_code, missing_https, resp
    except Exception as e:
        print(f"[!] Error connecting to {url}: {e}")
        return None, None, None



def check_security_headers(resp):
    issues = []
    headers = resp.headers

    if "X-Content-Type-Options" not in headers:
        issues.append("missing X-Content-Type-Options")
    if "X-Frame-Options" not in headers:
        issues.append("missing X-Frame-Options")
    if "Content-Security-Policy" not in headers:
        issues.append("missing Content-Security-Policy (CSP)")
    if "Strict-Transport-Security" not in headers and resp.url.startswith("https://"):
        issues.append("missing HSTS (Strict-Transport-Security)")

    return issues



def check_port(host, port, timeout=2):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False



def scan_ports(url, ports=(80, 443, 8080)):
    parsed = urlparse(url)
    host = parsed.hostname
    results = {}
    for p in ports:
        results[p] = check_port(host, p)
    return results



def run_scan(url):
    code, missing_https, response = get_status(url)

    uses_https = not missing_https if missing_https is not None else None
    is_reachable = code is not None

    header_issues = []
    if response is not None:
        header_issues = check_security_headers(response)

    port_results = scan_ports(url)

    return {
        "target": url,
        "status_code": code,
        "is_reachable": is_reachable,
        "uses_https": uses_https,
        "header_issues": header_issues,
        "port_results": port_results
    }



def save_csv_report(results, dir_path="reports"):
    """Save scan results to CSV."""
    os.makedirs(dir_path, exist_ok=True)

    # Build filename
    now = datetime.now().strftime("%Y-%m-%d_%H-%M")
    filename = os.path.join(dir_path, f"scan_{now}.csv")

    # Flattened security issues
    sec_issues_str = "; ".join(results["header_issues"]) if results["header_issues"] else "none"

    # Port booleans → OPEN/CLOSED
    ports = results["port_results"]
    row = {
        "url": results["target"],
        "status_code": results["status_code"],
        "uses_https": results["uses_https"],
        "missing_https": not results["uses_https"] if results["uses_https"] is not None else None,
        "security_issues": sec_issues_str,
        "port_80": "OPEN" if ports.get(80, False) else "CLOSED",
        "port_443": "OPEN" if ports.get(443, False) else "CLOSED",
        "port_8080": "OPEN" if ports.get(8080, False) else "CLOSED",
    }

    # Write CSV
    fieldnames = list(row.keys())
    exists = os.path.exists(filename)

    with open(filename, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        writer.writerow(row)

    print(f"[✓] Report saved to {filename}")

def scan_url(url):
    """Main entry point for web scanning"""
    vulnerabilities = []
    
    # Your existing scan logic here
    # For now, return mock data matching UI
    vulnerabilities = [
        {"title": "XSS Vulnerability", "description": f"Reflected XSS at {url}"},
        {"title": "Security Headers Missing", "description": "No CSP header found"},
        {"title": "Outdated Components", "description": "Vulnerable libraries detected"}
    ]
    
    return vulnerabilities




# ========================
# TEST BLOCK – only run when executed directly
# ========================
if __name__ == "__main__":
    target = "https://httpbin.org/headers"

    code, missing_https, response = get_status(target)
    print(f"Status: {code}, HTTPS missing: {missing_https}")

    if response is not None:
        header_issues = check_security_headers(response)
        if header_issues:
            print("[!] Security header issues:")
            for issue in header_issues:
                print(f"   - {issue}")
        else:
            print("[✓] Security headers look good")

    port_results = scan_ports(target)
    print("\n[+] Open ports:")
    for port, is_open in port_results.items():
        status = "OPEN" if is_open else "CLOSED"
        print(f"   {port} → {status}")
