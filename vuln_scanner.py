# Lab: Web Application Security Pt 1.
# vuln_scanner.py

import requests
from bs4 import BeautifulSoup

# Configurable variables
BASE_URL = "http://localhost:5000/search?q="  # Change if needed

# Payloads for XSS

payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(2)>",
    "<svg/onload=alert(3)>"
]

def check_http(url):
    if url.startswith("https://"):
        print("[✓] Secure protocol detected (HTTPS).")
    else:
        print("[!] Insecure login detected: Form is submitted over HTTP.")

def check_csrf_token(form_html):
    soup = BeautifulSoup(form_html, "html.parser")
    token = soup.find("input", {"name": "csrf_token"})
    if token:
        print("[✓] CSRF token detected.")
    else:
        print("[!] CSRF token not found in form fields.")

def check_rate_limiting(headers):
    rate_limit_headers = ["X-RateLimit-Limit", "Retry-After"]
    found = False
    for header in rate_limit_headers:
        if header in headers:
            found = True
            print(f"[✓] Rate limiting header detected: {header} = {headers[header]}")
    if not found:
        print("[!] No rate limiting headers detected.")

def test_payload(payload):
    """Submit the payload and check if it is reflected in the response."""
    try:
        full_url = BASE_URL + payload
        response = requests.get(full_url, timeout=5)

        if payload in response.text:
            print(f"[!] Potential XSS vulnerability detected with payload: {payload}")
        else:
            print(f"[✓] No reflection found for payload: {payload}")

    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed for payload: {payload}")
        print(f"    Error: {e}")

def main():
    try:
        print(f"\n[+] Connecting to {BASE_URL}...\n")
        response = requests.get(BASE_URL)

        if response.status_code != 200:
            print(f"[!] Failed to connect. Status Code: {response.status_code}")
            return

        check_http(BASE_URL)
        check_csrf_token(response.text)
        check_rate_limiting(response.headers)

        for payload in payloads:
            test_payload(payload)

    except requests.exceptions.RequestException as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
