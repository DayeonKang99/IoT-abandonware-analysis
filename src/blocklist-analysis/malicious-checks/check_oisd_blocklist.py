#!/usr/bin/env python3
"""
Check URLs against OISD blocklist
---------------------------------
This script downloads the OISD domain blocklist and compares it with a list
of URLs you provide (in a text file). It outputs a CSV report of blocked and allowed URLs.

Usage:
    python3 check_oisd_blocklist.py urls.txt output.csv
"""

import json
import os
import re
import sys
import csv
import requests
from urllib.parse import urlparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

OISD_URL = "https://big.oisd.nl/domainswild"

# Regex to extract domain-like tokens (allow many subdomain levels and digits/hyphens)
DOMAIN_RE = re.compile(r'([a-z0-9][a-z0-9\.-]+\.[a-z]{2,63})', re.IGNORECASE)

def load_oisd_domains(filepath):
    """
    Parse an OISD 'domains (wildcards)' file and return a cleaned set of domains.
    Handles lines like:
      *.example.com
      0.0.0.0 example.com
      ||example.com^
      example.com
    Ignores comments (#), blank lines, separators like '*.' and odd junk.
    """
    domains = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            # Skip comments
            if line.startswith("#"):
                continue
            # Skip lines that are just a single star or single wildcard token
            if line in ("*", "*.", "||", "."):
                continue

            # Remove common hostfile prefixes
            # e.g. "0.0.0.0 example.com" or "127.0.0.1 example.com"
            if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
                parts = line.split()
                if len(parts) >= 2:
                    candidate = parts[1]
                else:
                    continue
            else:
                candidate = line

            # Remove adblock style wrappers: leading "||", trailing "^", or leading "|" or "!" or "@@"
            candidate = candidate.lstrip("|@!")     # remove leading '|', '@' (whitelists), '!'
            candidate = re.sub(r'^\|\|', '', candidate)
            candidate = candidate.rstrip("^/")

            # Remove leading wildcard tokens like "*." or "." that appear before domain
            candidate = candidate.lstrip("*.")  # strips leading "*." or "." if present

            # Now try to extract a domain-like substring (the first match)
            m = DOMAIN_RE.search(candidate)
            if m:
                domain = m.group(1).lower()
                # optionally strip leading/trailing dots
                domain = domain.strip(".")
                # basic normalization: remove leading www.
                if domain.startswith("www."):
                    domain = domain[4:]
                domains.add(domain)
            else:
                # if no direct match, skip the line (could log if desired)
                # e.g. lines like "*.someweirdtoken" or separators
                continue

    return domains

def normalize_domain(url):
    try:
        domain = urlparse(url).netloc.lower()
        return domain.lstrip("www.")
    except Exception:
        return ""

def is_blocked(url, blocked_domains):
    domain = normalize_domain(url)
    if not domain:
        return False
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        sub = ".".join(parts[i:])
        if sub in blocked_domains:
            return True
    return False

def process_app(app_name, urls, oisd_domains):
    app_domains = set()
    for url in urls:
        domain = normalize_domain(url)
        if domain:
            app_domains.add(domain)
    blocked_domains = [d for d in app_domains if is_blocked(d, oisd_domains)]
    return app_name, blocked_domains

def main():
    url_file = "../urls/urls_merged.json"
    output_file = "results/oisd_blocked_summary.csv"
    oisd_blocklist = "oisd_basic.txt"
    oisd_domains_path = "oisd_domains.json"

    # Step 1: load OISD
    # if oisd_domains.json does not exist, load from oisd_basic.txt
    if not os.path.exists(oisd_domains_path):
        oisd_domains = load_oisd_domains(oisd_blocklist)
        #save oisd domains to json
        with open(oisd_domains_path, "w") as f:
            json.dump(list(oisd_domains), f, indent=2)
    else:
        with open(oisd_domains_path, "r") as f:
            oisd_domains = set(json.load(f))
    
    print(f"[+] Loaded {len(oisd_domains):,} domains from OISD blocklist.")

    # Step 2: Load URLs from json file
    with open(url_file, "r") as f:
        url_data = json.load(f)
    
    # Step 3: Check each URL against OISD
    global_blocked_domains = {}
    for app, urls in url_data.items():
        print(f"[+] {app}: {len(urls)} URLs found.")
       
        # extract the domains from urls
        app_domains = set()
        for url in urls:
            domain = normalize_domain(url)
            if domain:
                app_domains.add(domain)
        print(f"[+] {app}: {len(app_domains)} unique domains found.")
        
        # check which domains are blocked by OISD
        blocked_domains = [d for d in app_domains if is_blocked(d, oisd_domains)]
        print(f"[+] {app}: {len(blocked_domains)} domains blocked by OISD.")
        global_blocked_domains[app] = blocked_domains

    # Step 4: save blocked domains to json
    os.makedirs("results", exist_ok=True)
    with open("results/blocked_domains.json", "w") as f:
        json.dump(global_blocked_domains, f, indent=2)

    # step 5 Write CSV report
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["App", "Blocked_Domains_Count"])
        for app, blocked in global_blocked_domains.items():
            writer.writerow([app, len(blocked)])

def main_multiprocesses():
    url_file = "../urls/urls_merged.json"
    output_file = "results/oisd_blocked_summary.csv"
    oisd_blocklist = "oisd_basic.txt"
    oisd_domains_path = "oisd_domains.json"

    # Step 1: load OISD
    # if oisd_domains.json does not exist, load from oisd_basic.txt
    if not os.path.exists(oisd_domains_path):
        oisd_domains = load_oisd_domains(oisd_blocklist)
        #save oisd domains to json
        with open(oisd_domains_path, "w") as f:
            json.dump(list(oisd_domains), f, indent=2)
    else:
        with open(oisd_domains_path, "r") as f:
            oisd_domains = set(json.load(f))
    
    print(f"[+] Loaded {len(oisd_domains):,} domains from OISD blocklist.")

    # Step 2: Load URLs from json file
    with open(url_file, "r") as f:
        url_data = json.load(f)
    

    num_workers = min(8, multiprocessing.cpu_count())  # cap to avoid oversubscription
    print(f"[+] Using {num_workers} parallel workers.")

    # Step 3: Check each URL against OISD
    global_blocked_domains = {}
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = {
            executor.submit(process_app, app, urls, oisd_domains): app
            for app, urls in url_data.items()
        }

        for future in as_completed(futures):
            app_name = futures[future]
            try:
                app, blocked = future.result()
                global_blocked_domains[app] = blocked
                print(f"[✓] {app}: {len(blocked)} domains blocked.")
            except Exception as e:
                print(f"[!] Error processing {app_name}: {e}")

    # Step 4: save blocked domains to json
    os.makedirs("results", exist_ok=True)
    with open("results/blocked_domains.json", "w") as f:
        json.dump(global_blocked_domains, f, indent=2)

    # step 5 Write CSV report
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["App", "Blocked_Domains_Count"])
        for app, blocked in global_blocked_domains.items():
            writer.writerow([app, len(blocked)])


if __name__ == "__main__":
    main_multiprocesses()
