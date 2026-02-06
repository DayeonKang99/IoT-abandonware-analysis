import json
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import tldextract
import tempfile

# Prevent cache locking issues on NFS
tldextract.extract = tldextract.TLDExtract(
    cache_dir=tempfile.mkdtemp(),
    suffix_list_urls=None
)

from utils import create_logger

create_logger(os.path.basename(__file__))

# ======== CONFIG ========
INPUT_PATH = "path to file with extracted urls"           # input JSONL file
OUTPUT_DIR = "path to store files of each app's unique domains"    # directory to store per-app FQDN files
MAX_WORKERS = 50                               # number of parallel workers
# ========================


def extract_fqdns(urls):
    """Extract FQDNs from a list of URLs."""
    fqdns = set()
    for url in urls:
        tld = tldextract.extract(url)
        if tld.fqdn:  # non-empty fqdn
            fqdns.add(tld.fqdn)
    return sorted(fqdns)


def process_app(app, urls):
    """Process a single app and write its FQDN list to a JSON file."""
    fqdns = extract_fqdns(urls)
    output_path = os.path.join(OUTPUT_DIR, f"{app}.json")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({"app": app, "fqdn": fqdns}, f, indent=4)

    logging.info(f"Saved {len(fqdns)} FQDNs for {app}")
    return app, len(fqdns)


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    total_apps = 0
    total_fqdns = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor, open(INPUT_PATH, "r") as infile:
        futures = {}

        for line in infile:
            record = json.loads(line.strip())
            app, urls = next(iter(record.items()))
            futures[executor.submit(process_app, app, urls)] = app

        for i, future in enumerate(as_completed(futures), 1):
            app, fqdn_count = future.result()
            total_apps += 1
            total_fqdns += fqdn_count
            print(f"[{i}] Saved {app} with {fqdn_count} FQDNs")

    print(f"\n? Completed: {total_apps} apps processed, {total_fqdns} total FQDNs extracted.")


if __name__ == "__main__":
    main()
