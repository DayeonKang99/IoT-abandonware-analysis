#!/usr/bin/env python3
"""
url_check_pipeline.py

Usage:
    python url_check_pipeline.py urls.txt

Output:
    results.csv
"""

import os
import sys
import csv
import time
import requests
import base64
import urllib.parse
from pathlib import Path
from collections import defaultdict
import ipaddress

# ---------------------------
# Config / API keys (edit)
# ---------------------------
GOOGLE_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")  # set via env var, do not hardcode
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")                # set via env var, do not hardcode
# Optional: URLhaus: either provide path to your local URLhaus list (one URL per line)
URLHAUS_LOCAL_DB = "data/urlhauze.txt"  # if you already have list (one URL per line)
# Adserver/Ad-network list (we will fetch pgl.yoyo.org by default)
ADSERVER_LIST_URL = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&mimetype=plaintext&showintro=0"

# Rate-limit management
SLEEP_BETWEEN_VT = 15   # seconds between VirusTotal calls (adjust for your plan)
SLEEP_BETWEEN_GSB = 1   # short sleep between Google requests (you can batch up to 500 urls)
SLEEP_BETWEEN_URLHAUS = 1

# Output file
OUT_CSV = "results/vulnerability_checks.csv"

# ---------------------------
# Utility helpers
# ---------------------------
# def normalize_url(u: str) -> str:
#     u = u.strip()
#     if not u:
#         return ""
#     # If missing scheme, assume http for parsing
#     if not urllib.parse.urlparse(u).scheme:
#         u = "http://" + u
#     return u


# def normalize_url(u: str) -> str:
#     """
#     Normalize a URL string:
#       - strip whitespace
#       - ensure there's a scheme (assume http if missing)
#       - return "" for unparsable URLs
#       - return "" if the hostname is a private/loopback/link-local IP or 'localhost'
#       - otherwise return the normalized URL (with scheme)
#     """
#     if not isinstance(u, str):
#         return ""
#     u = u.strip()
#     if not u:
#         return ""

#     # Ensure scheme exists for parsing
#     parsed = urllib.parse.urlparse(u)
#     if not parsed.scheme:
#         u = "http://" + u
#         parsed = urllib.parse.urlparse(u)

#     # Must have a hostname portion
#     hostname = parsed.hostname
#     if not hostname:
#         return ""

#     # Reject explicit 'localhost'
#     if hostname.lower() == "localhost":
#         return ""

#     # If hostname is an IP (v4 or v6), reject private/loopback/link-local addresses
#     try:
#         # for IPv6 parsed.hostname may include no brackets; ip_address accepts both
#         ip = ipaddress.ip_address(hostname)
#         # check for any non-public characteristics
#         if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
#             return ""
#         # otherwise it's a public IP — accept
#         return u
#     except ValueError:
#         # hostname is not a literal IP (it's a domain). Accept it.
#         # Optionally, you can do an additional sanity check on domain (e.g., require a dot),
#         # but many valid internal domains may not have one — so we leave it as-is.
#         return u

import urllib.parse
import ipaddress
import re

def normalize_url(u: str) -> str:
    """
    Normalize and validate a URL string:
      - Strips whitespace
      - Adds http:// if missing
      - Rejects unparsable or invalid hostnames
      - Rejects private, loopback, or link-local IPs
    """
    if not isinstance(u, str):
        return ""
    u = u.strip()
    if not u:
        return ""

    # Ensure scheme exists for parsing
    parsed = urllib.parse.urlparse(u)
    if not parsed.scheme:
        u = "http://" + u
        parsed = urllib.parse.urlparse(u)

    hostname = parsed.hostname
    if not hostname:
        return ""

    # Reject localhost and obvious placeholders
    if hostname.lower() == "localhost":
        return ""

    # Reject hostnames that are too short or malformed
    # e.g., ".", "-", "...", "-example", "example-", etc.
    if len(hostname) < 2 or not re.search(r"[a-zA-Z0-9]", hostname):
        return ""
    if hostname.startswith((".", "-")) or hostname.endswith((".", "-")):
        return ""
    if re.match(r"^[.\-]+$", hostname):  # only dots or dashes
        return ""

    # Check if it's an IP and reject private/non-public ones
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
            return ""
        return u
    except ValueError:
        # Not an IP — domain check
        # Optionally ensure it has at least one '.' (to avoid junk like 'abc' or '-')
        if "." not in hostname:
            return ""
        return u


def extract_domain(url: str) -> str:
    try:
        p = urllib.parse.urlparse(url)
        host = p.hostname or ""
        return host.lower()
    except Exception:
        return ""

def load_urls_from_file(path: str):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{path} not found")
    urls = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        urls.append(normalize_url(line))
    return sorted(set(urls))

# function to fetch urls from json file. urls are currently grouped as lists under applications. For now, we need just the urls. so load the json file, and combine all values as a single list
def load_urls_from_json(path: str):
    import json
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{path} not found")
    with open(path, 'r') as f:
        data = json.load(f)
    urls = []
    for app, url_list in data.items():
        url_list = [normalized for u in url_list if (normalized := normalize_url(u))]
        urls.extend(url_list)
    return sorted(set(urls))

# ---------------------------
# Ad-network / adserver list
# ---------------------------
def fetch_adserver_list(url=ADSERVER_LIST_URL):
    """
    Fetch a hosts-format adserver list and return a set of domains.
    pgl.yoyo provides a plain-text hosts format that we parse.
    """
    print(f"[+] Fetching adserver list from {url} ...")
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    domains = set()
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Format: "0.0.0.0 domain" or "127.0.0.1 domain"
        parts = line.split()
        if len(parts) >= 2:
            dom = parts[1].strip()
            # handle entries that might be comments or localhost entries
            if dom and dom != "localhost":
                domains.add(dom.lower())
    print(f"[+] Got {len(domains)} adserver domains")
    return domains

def is_ad_network(domain: str, adserver_set: set):
    """Check domain or its parent domains against adserver set."""
    if not domain:
        return False
    domain = domain.lower()
    # check exact match or parent suffixes
    parts = domain.split('.')
    for i in range(len(parts)-1):
        candidate = ".".join(parts[i:])  # progressively check example.com, sub.example.com -> example.com etc
        if candidate in adserver_set:
            return True
    # final check full domain
    if domain in adserver_set:
        return True
    return False

# ---------------------------
# Google Safe Browsing (v4) Lookup
# Docs: threatMatches.find method; batch up to 500 urls per POST.
# ---------------------------
def check_google_safe_browsing(urls, api_key=GOOGLE_API_KEY):
    """
    urls: list of URLs (max 500 per request). Returns dict url -> bool (True if unsafe).
    Reference: threatMatches.find method of Safe Browsing API v4.
    """
    if not api_key:
        raise ValueError("Google Safe Browsing API key not configured")
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    results = {}
    # API allows up to 500 urls per request; we'll batch
    batch_size = 500
    headers = {"Content-Type": "application/json"}
    for i in range(0, len(urls), batch_size):
        batch = urls[i:i+batch_size]
        body = {
            "client": {
                "clientId": "url-checker",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in batch]
            }
        }
        resp = requests.post(endpoint, json=body, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])
            matched_urls = set()
            for m in matches:
                # match contains threat: {url: ...}
                if "threat" in m and "url" in m["threat"]:
                    matched_urls.add(m["threat"]["url"])
            for u in batch:
                results[u] = (u in matched_urls)
        else:
            # on error - treat as unknown (False) but record note
            print(f"[!] Google Safe Browsing API error: {resp.status_code} {resp.text}")
            for u in batch:
                results[u] = False
        time.sleep(SLEEP_BETWEEN_GSB)
    return results

# ---------------------------
# VirusTotal v3 URL report
# Docs: POST /api/v3/urls to submit -> then GET /api/v3/urls/{id}, id = base64url(url)
# ---------------------------
def vt_url_id(url: str) -> str:
    # per VT docs: url id = base64url(url) without '=' padding
    b = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return b

def check_virustotal(url, api_key=VT_API_KEY):
    """
    Return summary dict: {'malicious': bool, 'malicious_count': int, 'raw': <json or None>}
    """

    if not api_key:
        raise ValueError("VirusTotal API key not configured")
    headers = {"x-apikey": api_key}
    url_id = vt_url_id(url)
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    resp = requests.get(endpoint, headers=headers, timeout=30)
    if resp.status_code == 200:
        j = resp.json()
        # analysis stats commonly found under data.attributes.last_analysis_stats
        stats = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return {"malicious": (malicious > 0 or suspicious > 0),
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "raw": j}
    elif resp.status_code == 404:
        # not found — optionally submit for scanning (requires POST /api/v3/urls)
        return {"malicious": False, "malicious_count": 0, "suspicious_count": 0, "raw": None}
    else:
        print(f"[!] VirusTotal error {resp.status_code}: {resp.text}")
        return {"malicious": False, "malicious_count": 0, "suspicious_count": 0, "raw": None}

# ---------------------------
# URLhaus check (local DB style)
# ---------------------------
def load_urlhaus_local(path=URLHAUS_LOCAL_DB):
    p = Path(path)
    if not p.exists():
        print(f"[!] URLhaus local DB {path} not found; continuing without it")
        return set()
    s = set()
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        s.add(line.lower())
    print(f"[+] Loaded {len(s)} urlhaus entries from {path}")
    return s

def check_urlhaus_local(url, urlhaus_set):
    return url.lower() in urlhaus_set

# ---------------------------
# Main pipeline
# ---------------------------
def main(input_file):
    urls = load_urls_from_json(input_file)
    print(f"[+] Loaded {len(urls)} unique URLs from merged json file")

    # urls = load_urls_from_file(input_file)
    # print(f"[+] Loaded {len(urls)} unique URLs from {input_file}")

    # domains
    domains = {u: extract_domain(u) for u in urls}

    # fetch adserver list
    try:
        adset = fetch_adserver_list()
    except Exception as e:
        print(f"[!] Failed to fetch adserver list: {e}")
        adset = set()

    # load URLhaus local DB
    urlhaus_set = load_urlhaus_local(URLHAUS_LOCAL_DB)

    # Google Safe Browsing checks (batch) -- skipping for now
    # print("[+] Running Google Safe Browsing checks ...")
    # try:
    #     gsb_results = check_google_safe_browsing(urls, api_key=GOOGLE_API_KEY)
    # except Exception as e:
    #     print(f"[!] Google Safe Browsing failed: {e}")
    #     gsb_results = {u: False for u in urls}

    # Prepare output CSV
    # fieldnames = ["url", "domain", "is_ad_network", "gsb_flag", "vt_malicious", "vt_malicious_count", "urlhaus_malicious", "notes"]
    fieldnames = ["url", "domain", "is_ad_network", "urlhaus_malicious"]

    rows = []

    # Iterate and check VirusTotal and URLhaus per URL
    for idx, u in enumerate(urls):
        dom = domains.get(u, "")
        is_ad = is_ad_network(dom, adset) if dom else False

        # GSB
        # gsb_flag = gsb_results.get(u, False)

        # URLhaus local check (pure in-memory set lookup, no rate limiting needed)
        urlhaus_flag = False
        if urlhaus_set:
            urlhaus_flag = check_urlhaus_local(u, urlhaus_set)

        # VirusTotal -- skipping for now
        # try:
        #     vt = check_virustotal(u, api_key=VT_API_KEY)
        # except Exception as e:
        #     print(f"[!] VirusTotal check error for {u}: {e}")
        #     vt = {"malicious": False, "malicious_count": 0, "suspicious_count": 0, "raw": None}
        # # rate limit sleep to be polite
        # time.sleep(SLEEP_BETWEEN_VT)

        notes = []
        if is_ad:
            notes.append("ad_network_match")
        # if gsb_flag:
        #     notes.append("gsb_flagged")
        # if vt.get("malicious"):
        #     notes.append(f"vt_malicious({vt.get('malicious_count',0)})")
        if urlhaus_flag:
            notes.append("urlhaus_malicious")
        row = {
            "url": u,
            "domain": dom,
            "is_ad_network": is_ad,
            # "gsb_flag": gsb_flag,
            # "vt_malicious": vt.get("malicious"),
            # "vt_malicious_count": "NA", #vt.get("malicious_count"),
            "urlhaus_malicious": urlhaus_flag,
            # "notes": ";".join(notes)
        }
        rows.append(row)
        # progress print
        if (idx+1) % 10 == 0:
            print(f"[+] Processed {idx+1}/{len(urls)}")

    # write CSV
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    print(f"[+] Done. Wrote {len(rows)} results to {OUT_CSV}")

if __name__ == "__main__":
    # if len(sys.argv) != 2:
    #     print("Usage: python url_check_pipeline.py urls.txt")
    #     sys.exit(1)
    # input_file = sys.argv[1]
    input_file = "../urls/urls_merged.json"
    os.makedirs("results", exist_ok=True)
    main(input_file)
