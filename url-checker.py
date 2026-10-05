#!/usr/bin/env python3
"""
Phishing URL Checker
---------------------
Heuristic-based URL risk scanner, with optional Google Safe Browsing
lookup if an API key is supplied.

Usage:
    python phishing_url_checker.py "https://example.com/login"
    python phishing_url_checker.py --file urls.txt
    GOOGLE_SAFE_BROWSING_API_KEY=xxxx python phishing_url_checker.py "https://..."

This tool flags SUSPICIOUS patterns. It does not prove a URL is malicious,
and a clean result does not guarantee a URL is safe. Use it as one signal
among others (sender reputation, context, org policy).
"""

import argparse
import ipaddress
import os
import re
import sys
import urllib.parse as urlparse

try:
    import requests
except ImportError:
    requests = None

# --- Reference data -----------------------------------------------------

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click",
    "link", "work", "support", "lol", "surf", "icu", "rest", "cam",
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

# Brands commonly impersonated — extend this list for your organisation
BRAND_KEYWORDS = [
    "maybank", "cimb", "publicbank", "rhb", "hongleong", "bsn", "bankislam",
    "lhdn", "jpj", "epf", "kwsp", "socso", "perkeso", "mycsl", "spa",
    "microsoft", "office365", "google", "paypal", "dhl", "poslaju",
    "touchngo", "tng", "shopee", "lazada", "grab",
]

URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)


# --- Heuristic checks -----------------------------------------------------

def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def check_url(url: str) -> dict:
    flags = []
    score = 0

    if not URL_PATTERN.match(url):
        url_to_parse = "http://" + url
    else:
        url_to_parse = url

    parsed = urlparse.urlparse(url_to_parse)
    host = parsed.hostname or ""
    full = url.lower()

    # 1. No HTTPS
    if parsed.scheme != "https":
        flags.append("Tidak guna HTTPS")
        score += 1

    # 2. IP address instead of domain name
    if is_ip_address(host):
        flags.append("Guna alamat IP sebagai domain (bukan nama domain biasa)")
        score += 3

    # 3. '@' symbol in URL (browser ignores everything before it)
    if "@" in url:
        flags.append("Mengandungi simbol '@' — boleh menyembunyikan domain sebenar")
        score += 3

    # 4. Punycode / IDN homograph attempt
    if "xn--" in host:
        flags.append("Domain guna punycode (xn--) — mungkin cuba meniru domain lain")
        score += 3

    # 5. Suspicious TLD
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"Guna TLD yang kerap disalahgunakan untuk scam (.{tld})")
        score += 2

    # 6. Known URL shortener (hides real destination)
    if host in KNOWN_SHORTENERS:
        flags.append("URL shortener — destinasi sebenar disembunyikan")
        score += 2

    # 7. Excessive subdomains (e.g. login.secure.maybank.verify.nascloud.lol)
    subdomain_count = host.count(".")
    if subdomain_count >= 3:
        flags.append(f"Terlalu banyak subdomain ({subdomain_count}) — corak biasa phishing")
        score += 2

    # 8. Brand keyword present but not as the actual registered domain
    registrable = ".".join(host.split(".")[-2:]) if "." in host else host
    for brand in BRAND_KEYWORDS:
        if brand in full and brand not in registrable:
            flags.append(f"Nama jenama '{brand}' muncul dalam URL tetapi bukan domain sebenar")
            score += 3
            break

    # 9. Hyphen-heavy domain (typosquatting pattern)
    if host.count("-") >= 2:
        flags.append("Domain mengandungi banyak tanda sempang — corak typosquatting")
        score += 1

    # 10. Overly long URL
    if len(url) > 100:
        flags.append("URL sangat panjang — boleh digunakan untuk mengelirukan")
        score += 1

    # 11. Suspicious keywords in path/query
    for word in ["verify", "update", "secure", "account", "confirm", "login", "signin"]:
        if word in full:
            flags.append(f"Mengandungi kata kunci sensitif ('{word}') biasa dalam phishing")
            score += 1
            break

    if score >= 7:
        risk = "TINGGI"
    elif score >= 3:
        risk = "SEDERHANA"
    else:
        risk = "RENDAH"

    return {
        "url": url,
        "host": host,
        "score": score,
        "risk": risk,
        "flags": flags,
    }


def check_safe_browsing(url: str, api_key: str) -> dict | None:
    """Optional: query Google Safe Browsing API v4."""
    if not requests:
        print("  (requests tidak dipasang — skip Safe Browsing check)")
        return None

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phishing-url-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data
    except Exception as e:
        print(f"  (Safe Browsing API error: {e})")
        return None


def print_result(result: dict, sb_result: dict | None):
    print(f"\nURL     : {result['url']}")
    print(f"Domain  : {result['host']}")
    print(f"Risiko  : {result['risk']}  (skor heuristik: {result['score']})")
    if result["flags"]:
        print("Petanda mencurigakan:")
        for f in result["flags"]:
            print(f"  - {f}")
    else:
        print("Tiada petanda mencurigakan dikesan oleh heuristik.")

    if sb_result is not None:
        if sb_result.get("matches"):
            print("⚠ Google Safe Browsing: URL ini DISENARAIKAN sebagai berbahaya.")
        else:
            print("Google Safe Browsing: tiada padanan ancaman diketahui.")


def main():
    parser = argparse.ArgumentParser(description="Phishing URL heuristic checker")
    parser.add_argument("url", nargs="?", help="URL untuk disemak")
    parser.add_argument("--file", help="Fail teks berisi satu URL setiap baris")
    args = parser.parse_args()

    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")

    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            urls.extend(line.strip() for line in f if line.strip())

    if not urls:
        parser.print_help()
        sys.exit(1)

    for url in urls:
        result = check_url(url)
        sb_result = check_safe_browsing(url, api_key) if api_key else None
        print_result(result, sb_result)

    if not api_key:
        print(
            "\n(Nota: set GOOGLE_SAFE_BROWSING_API_KEY untuk aktifkan semakan "
            "reputasi dalam talian tambahan.)"
        )


if __name__ == "__main__":
    main()
