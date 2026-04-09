from fastapi import FastAPI
import requests

app = FastAPI()


# 1. SQL Injection

def test_sqli(url):
    payload = "' OR 1=1 --"
    test_url = f"{url}?id={payload}"

    try:
        res = requests.get(test_url, timeout=5)
        if "sql" in res.text.lower() or "error" in res.text.lower():
            return {"type": "SQL Injection", "status": "Possible"}
    except:
        return None



# 2. Reflected XSS

def test_xss(url):
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?q={payload}"

    try:
        res = requests.get(test_url, timeout=5)
        if payload in res.text:
            return {"type": "XSS", "status": "Reflected"}
    except:
        return None



# 3. Broken Authentication

def test_auth(url):
    try:
        res = requests.get(url + "/dashboard", timeout=5)

        if res.status_code == 200:
            return {
                "type": "Broken Authentication",
                "status": "Access without login possible"
            }
    except:
        return None



# 4. Open Redirect

def test_redirect(url):
    payload = "http://evil.com"
    test_url = f"{url}?next={payload}"

    try:
        res = requests.get(test_url, allow_redirects=False, timeout=5)

        if "Location" in res.headers and payload in res.headers["Location"]:
            return {"type": "Open Redirect", "status": "Vulnerable"}
    except:
        return None



# 5. Security Misconfiguration

def test_headers(url):
    issues = []

    try:
        res = requests.get(url, timeout=5)
        headers = res.headers

        if "Content-Security-Policy" not in headers:
            issues.append("Missing CSP")

        if "X-Frame-Options" not in headers:
            issues.append("Missing X-Frame-Options")

        if url.startswith("http://"):
            issues.append("Not using HTTPS")

        if issues:
            return {
                "type": "Security Misconfiguration",
                "issues": issues
            }
    except:
        return None

# MAIN SCAN API

@app.get("/scan")
def scan(url: str):
    results = []

    for test in [test_sqli, test_xss, test_auth, test_redirect, test_headers]:
        result = test(url)
        if result:
            results.append(result)

    return {
        "target": url,
        "vulnerabilities": results
    }