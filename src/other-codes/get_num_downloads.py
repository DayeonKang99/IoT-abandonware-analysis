# This code will extract the number of downloads of each app from either the PlayStore, or Androzoo if the app does not exist in the playstore anymore.

import json
import subprocess
from google_play_scraper import app
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import csv

# Track successful retrievals
playstore = 0
androzoo = 0
lock = threading.Lock()  # For thread-safe counter updates

def get_installs_from_playscraper(package_name):
    """Try to get install count using google-play-scraper"""
    global playstore
    try:
        data = app(package_name, lang="en", country="us")
        installs = data.get("realInstalls")
        if installs:
            with lock:
                playstore += 1
        return installs
    except Exception as e:
        print(f"[PlayScraper] Could not get installs for {package_name}: {e}")
        return None

def get_installs_from_androzoo(package_name, api_key):
    """Fallback: Get install count using AndroZoo API"""
    global androzoo
    try:
        result = subprocess.run([
            "curl", "-G",
            "-d", f"apikey={api_key}",
            f"https://androzoo.uni.lu/api/get_gp_metadata/{package_name}"
        ], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"[AndroZoo] Error fetching metadata for {package_name}")
            return None

        data = json.loads(result.stdout)
        if not data:
            print(f"[AndroZoo] Empty response for {package_name}")
            return None

        app_data = data[0]  # take first entry
        installs = (
            app_data.get("details", {})
                    .get("appDetails", {})
                    .get("numDownloads", None)
        )

        if installs:
            with lock:
                androzoo += 1

        return installs
    except Exception as e:
        print(f"[AndroZoo] Could not get installs for {package_name}: {e}")
        return None

def get_app_installs(package_name, api_key):
    """Get installs either from Play Store or AndroZoo fallback"""
    installs = get_installs_from_playscraper(package_name)
    if installs:
        source = "Play Store"
    else:
        installs = get_installs_from_androzoo(package_name, api_key)
        source = "AndroZoo" if installs else "Unavailable"

    return {"package_name": package_name, "installs": installs, "source": source}

def read_packages_from_file(filepath):
    """Reads package names from a text file (one per line)"""
    with open(filepath, "r") as f:
        packages = [line.strip().replace(".apk", "") for line in f if line.strip()]
    return packages

def read_packages_from_csv(filepath):
    """Reads package names from a CSV file with a column named 'package_name'."""
    packages = []
    with open(filepath, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        if "package_name" not in reader.fieldnames:
            raise ValueError("CSV file must contain a 'package_name' column")

        for row in reader:
            pkg = row["package_name"].strip().replace(".apk", "")
            if pkg:
                packages.append(pkg)
    return packages

# ---------- MAIN EXECUTION ----------
api_key = "Insert your androzoo api key here"
package_file = "your csv file of apps list"   # your CSV file
packages = read_packages_from_csv(package_file)
print(f"Loaded {len(packages)} package names from {package_file}")

results = []

# Use ThreadPoolExecutor for multithreading
max_workers = 20  # adjust based on your CPU and network capacity
with ThreadPoolExecutor(max_workers=max_workers) as executor:
    future_to_pkg = {executor.submit(get_app_installs, pkg, api_key): pkg for pkg in packages}

    for i, future in enumerate(as_completed(future_to_pkg), start=1):
        info = future.result()
        results.append(info)
        print(f"[{i}/{len(packages)}] {info}")

# Save results
output_file = "app_installs.json"
with open(output_file, "w") as f:
    json.dump(results, f, indent=4)

print(f"\nSaved results to {output_file}")
print(f"PlayScraper successes: {playstore}")
print(f"AndroZoo successes: {androzoo}")
print(f"Total processed: {len(packages)}")
