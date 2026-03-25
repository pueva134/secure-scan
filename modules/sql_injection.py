import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def get_forms(url):
    s = requests.Session()
    s.headers["User-Agent"] = "SecureScan/0.1"
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")

def form_details(form):
    details = {}
    details["action"] = form.attrs.get("action", "")
    details["method"] = form.attrs.get("method", "get").lower()
    inputs = []
    for inp in form.find_all("input"):
        t = inp.attrs.get("type", "text")
        n = inp.attrs.get("name")
        v = inp.attrs.get("value", "")
        inputs.append({"type": t, "name": n, "value": v})
    details["inputs"] = inputs
    return details

def is_vulnerable_sql(response):
    errors = [
        "sql syntax",
        "syntax error",
        "you have an error in your sql syntax",
    ]
    text = response.text.lower()
    for e in errors:
        if e in text:
            return True
    return False

def scan_sql_injection(url):
    forms = get_forms(url)
    for form in forms:
        details = form_details(form)
        action = urljoin(url, details["action"])
        for c in "'\"":
            data = {}
            for inp in details["inputs"]:
                if inp["type"] == "hidden" or inp["value"]:
                    data[inp["name"]] = inp["value"] + c
                elif inp["type"] != "submit":
                    data[inp["name"]] = f"test{c}"
            try:
                if details["method"] == "post":
                    resp = requests.post(action, data=data, timeout=5)
                else:
                    resp = requests.get(action, params=data, timeout=5)
                if is_vulnerable_sql(resp):
                    return {
                        "type": "SQL Injection",
                        "target": action,
                        "risk": "High",
                        "details": f"SQL error detected for form at {action}"
                    }
            except Exception:
                pass
    return None  # no SQLi found
