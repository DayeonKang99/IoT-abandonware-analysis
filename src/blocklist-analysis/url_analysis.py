#!/usr/bin/env python3

import os
import re
import json
import csv
import time
import glob
import logging
import argparse
import ipaddress
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor
from collections import Counter, defaultdict

import tldextract
from tqdm import tqdm

# ---------------- CONFIG (change paths if you need) ----------------
INPUT_JSON_GLOB = "urls/urls_merged.json"
BLOCKLIST_DIR = "blocklists"
OUTPUT_DIR = "results"
DEFAULT_WORKERS = None  # None -> os.cpu_count() or fallback
CHECKPOINT_EVERY = 1000          # how many processed results to flush to checkpoint file
CHECKPOINT_FILE = os.path.join(OUTPUT_DIR, "results_checkpoint.jsonl")
FINAL_RESULTS_JSON = os.path.join(OUTPUT_DIR, "results.json")
FINAL_RESULTS_CSV = os.path.join(OUTPUT_DIR, "results.csv")
SUMMARY_JSON = os.path.join(OUTPUT_DIR, "summary.json")
SUMMARY_CSV = os.path.join(OUTPUT_DIR, "summary.csv")
LOG_FILE = os.path.join(OUTPUT_DIR, "scanner.log")

BLOCKLIST_MAP = {
    "ads": ["ads.json"],
    "malware": ["malware.json", "hijack.json"],
    "spyware": ["spyware.json"],
    "phishing": ["phishing.json"],
    "spam": ["spam.json"],
    "tracking": ["tracking-telemetry.json"],
    "scams": ["scams.json"],
    "shocksites": ["shocksites.json"],
    "suspicious": ["suspicious.json", "fb_blacklist.json", "mvps_hosts.json", "neo_hosts.json"]
}


CATEGORY_ORDER = ["ads", "malware", "spyware", "phishing", "spam", "tracking", "scams", "suspicious"]

os.makedirs(OUTPUT_DIR, exist_ok=True)

logger = logging.getLogger("blocklist_scanner")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(LOG_FILE)
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(fh)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(ch)

SCHEME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://')

def safe_parse_url(raw_url: str):
    """Return (normalized_full(host+path), host, path). Does not remove 'www' here;
    tldextract will handle subdomain logic."""
    if not raw_url or not isinstance(raw_url, str):
        return "", "", ""
    s = raw_url.strip()
    if not s:
        return "", "", ""
    if not SCHEME_RE.match(s):
        s = "http://" + s
    try:
        p = urlparse(s)
        host = p.hostname or ""
        path = p.path or ""
        if p.query:
            path += "?" + p.query
        full = (host + path).lower()
        return full, host.lower(), path
    except Exception as e:
        logger.debug(f"safe_parse_url failed for {raw_url!r}: {e}")
        # fallback: strip common prefixes and return raw as host
        stripped = re.sub(r'^(?:https?://|ftp://)?(?:www\.)?', '', raw_url, flags=re.IGNORECASE).strip().lower()
        if "/" in stripped:
            host, path = stripped.split("/", 1)
            return host + "/" + path, host, "/" + path
        return stripped, stripped, ""

def is_ip(host: str):
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

def registered_domain(host: str):
    if not host:
        return ""
    if is_ip(host):
        return host
    ext = tldextract.extract(host)
    if ext.registered_domain:
        return ext.registered_domain.lower()
    # fallback heuristic
    parts = host.split(".")
    return ".".join(parts[-2:]).lower() if len(parts) >= 2 else host.lower()

def subdomain_representation(host: str):
    return host.lower() if host else ""

def normalize_blocklist_entry(entry: str):
    if not entry or not isinstance(entry, str):
        return ""
    s = entry.strip().lower()
    # strip scheme
    s = re.sub(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', '', s)
    # strip leading www.
    if s.startswith("www."):
        s = s[4:]
    # strip trailing slash
    if s.endswith("/"):
        s = s[:-1]
    return s


def load_blocklists(blocklist_dir: str, mapping: dict):
    categories = {}
    for cat, files in mapping.items():
        merged = set()
        for fname in files:
            path = os.path.join(blocklist_dir, fname)
            if not os.path.exists(path):
                logger.warning(f"Blocklist file not found: {path}")
                continue
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    if not isinstance(data, list):
                        logger.warning(f"Blocklist {path} is not a JSON list — skipping.")
                        continue
                    for e in data:
                        ne = normalize_blocklist_entry(e)
                        if ne:
                            merged.add(ne)
            except Exception as e:
                logger.exception(f"Failed to load blocklist {path}: {e}")
        categories[cat] = merged
        logger.info(f"Loaded category '{cat}': {len(merged)} unique entries.")
    total = sum(len(s) for s in categories.values())
    logger.info(f"Total blocklist entries (sum of categories): {total}")
    return categories

def check_url_task(task_tuple):
    app_name, url, categories = task_tuple
    start = time.time()
    result = {
        "app": app_name,
        "url_original": url,
        "normalized_full": "",
        "host": "",
        "registered_domain": "",
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "match": False,
        "category": None,
        "match_level": None,   # full | subdomain | domain
        "matched_entry": None,
        "processing_time_s": None,
        "error": None
    }
    try:
        full, host, path = safe_parse_url(url)
        result["normalized_full"] = full
        result["host"] = host
        result["registered_domain"] = registered_domain(host)

        for cat in CATEGORY_ORDER:
            entries = categories.get(cat, set())
            # check full
            if full and full in entries:
                result.update({
                    "match": True,
                    "category": cat,
                    "match_level": "full",
                    "matched_entry": full
                })
                break
            # subdomain/host
            if host:
                # try host direct
                if host in entries:
                    result.update({
                        "match": True,
                        "category": cat,
                        "match_level": "subdomain",
                        "matched_entry": host
                    })
                    break
                
                parts = host.split(".")
                for i in range(len(parts)):
                    suffix = ".".join(parts[i:])
                    if suffix in entries:
                        result.update({
                            "match": True,
                            "category": cat,
                            "match_level": "subdomain_suffix",
                            "matched_entry": suffix
                        })
                        break
                if result["match"]:
                    break
            # registered domain
            if result["registered_domain"]:
                if result["registered_domain"] in entries:
                    result.update({
                        "match": True,
                        "category": cat,
                        "match_level": "domain",
                        "matched_entry": result["registered_domain"]
                    })
                    break
        # done checking categories
    except Exception as e:
        result["error"] = str(e)
    result["processing_time_s"] = round(time.time() - start, 4)
    return result

def get_all_tasks(input_glob: str, blocklists, resume_processed_set=None):
    input_files = sorted(glob.glob(input_glob))
    if not input_files:
        logger.error(f"No input JSON files found (pattern: {input_glob})")
        return []
    tasks = []
    skipped = 0
    total_urls = 0
    for path in input_files:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if not isinstance(data, dict):
                    logger.warning(f"Skipping input {path}: root JSON is not a dict.")
                    continue
                for app, urls in data.items():
                    if not isinstance(urls, list):
                        logger.warning(f"Skipping app '{app}' in {path}: value is not a list.")
                        continue
                    for u in urls:
                        total_urls += 1
                        key = (app, u)
                        if resume_processed_set and key in resume_processed_set:
                            skipped += 1
                            continue
                        # Each task is a tuple; blocklists are included so the worker has them (picklable)
                        tasks.append((app, u, blocklists))
        except Exception as e:
            logger.exception(f"Failed to load input {path}: {e}")
    logger.info(f"Prepared tasks: {len(tasks)} urls to scan (skipped {skipped} already processed). total urls found={total_urls}")
    return tasks

def load_resume_set(checkpoint_file):
    processed = set()
    if not os.path.exists(checkpoint_file):
        return processed
    try:
        with open(checkpoint_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    j = json.loads(line)
                    key = (j.get("app"), j.get("url_original"))
                    processed.add(key)
                except Exception:
                    continue
        logger.info(f"Loaded {len(processed)} processed entries from checkpoint.")
    except Exception as e:
        logger.exception(f"Failed to read checkpoint file {checkpoint_file}: {e}")
    return processed

def append_results_to_checkpoint(results_batch, checkpoint_file):
    if not results_batch:
        return
    try:
        with open(checkpoint_file, "a", encoding="utf-8") as fh:
            for r in results_batch:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.exception(f"Failed to append to checkpoint {checkpoint_file}: {e}")

def write_final_results_jsonl_to_aggregate(checkpoint_file, final_json_path):
    results = []
    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except Exception:
                    continue
    # Write aggregated JSON
    try:
        with open(final_json_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.exception(f"Failed to write final results JSON {final_json_path}: {e}")
    return results

def write_final_csv_from_results(results, csv_path):
    if not results:
        logger.warning("No results to write to CSV.")
        return
    # header keys in stable order
    keys = ["app", "url_original", "normalized_full", "host", "registered_domain",
            "checked_at", "match", "category", "match_level", "matched_entry",
            "processing_time_s", "error"]
    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=keys)
            writer.writeheader()
            for r in results:
                # ensure all keys exist
                out = {k: r.get(k, "") for k in keys}
                writer.writerow(out)
    except Exception as e:
        logger.exception(f"Failed to write results CSV: {e}")

def generate_summary(results):
    summary = {
        "run_at": datetime.utcnow().isoformat() + "Z",
        "total_urls": len(results),
        "matched_count": 0,
        "unmatched_count": 0,
        "by_category": {},
        "top_domains_by_category": {}
    }
    cat_counter = Counter()
    unmatched = 0
    for r in results:
        if r.get("match"):
            cat = r.get("category") or "unknown"
            cat_counter[cat] += 1
        else:
            unmatched += 1
    summary["matched_count"] = sum(cat_counter.values())
    summary["unmatched_count"] = unmatched
    summary["by_category"] = dict(cat_counter)
    # top offending domains per category
    tops = {}
    domain_by_cat = defaultdict(Counter)
    for r in results:
        if r.get("match"):
            cat = r.get("category")
            # prefer matched_entry, else registered_domain, else host
            domain = r.get("matched_entry") or r.get("registered_domain") or r.get("host")
            if domain:
                domain_by_cat[cat][domain] += 1
    for cat, counter in domain_by_cat.items():
        tops[cat] = counter.most_common(20)
    summary["top_domains_by_category"] = tops
    return summary

def main(argv=None):
    
    global OUTPUT_DIR, CHECKPOINT_FILE, FINAL_RESULTS_JSON, FINAL_RESULTS_CSV, SUMMARY_JSON, SUMMARY_CSV, LOG_FILE

    parser = argparse.ArgumentParser(description="Blocklist URL scanner with resume and summary.")
    parser.add_argument("--workers", "-w", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--checkpoint-every", "-c", type=int, default=CHECKPOINT_EVERY)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--blocklist-dir", type=str, default=BLOCKLIST_DIR)
    parser.add_argument("--input-glob", type=str, default=INPUT_JSON_GLOB)
    parser.add_argument("--output-dir", type=str, default=OUTPUT_DIR)
    args = parser.parse_args(argv)

    # update paths if output dir changed
    OUTPUT_DIR = args.output_dir
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    CHECKPOINT_FILE = os.path.join(OUTPUT_DIR, "results_checkpoint.jsonl")
    FINAL_RESULTS_JSON = os.path.join(OUTPUT_DIR, "results.json")
    FINAL_RESULTS_CSV = os.path.join(OUTPUT_DIR, "results.csv")
    SUMMARY_JSON = os.path.join(OUTPUT_DIR, "summary.json")
    SUMMARY_CSV = os.path.join(OUTPUT_DIR, "summary.csv")
    LOG_FILE = os.path.join(OUTPUT_DIR, "scanner.log")

    logger.info("Starting blocklist scanner")
    logger.info(f"Loading blocklists from: {args.blocklist_dir}")
    categories = load_blocklists(args.blocklist_dir, BLOCKLIST_MAP)

    # remove - for testing only
    proceed = input(f"Proceed to scan URLs from '{args.input_glob}' and write results to '{OUTPUT_DIR}'? (y/n): ")
    if proceed.strip().lower() != "y":
        logger.info("Aborting as per user input.")
        return

    resume_set = set()
    if args.resume:
        resume_set = load_resume_set(CHECKPOINT_FILE)
        proceed = input(f"Proceed to resume from checkpoint file? (y/n): ")
        if proceed.strip().lower() != "y":
            logger.info("Aborting as per user input.")
            return

    tasks = get_all_tasks(args.input_glob, categories, resume_set)
    if not tasks:
        logger.info("No tasks to process. Exiting.")
        return

    workers = args.workers or os.cpu_count() or 2
    logger.info(f"Using {workers} worker processes.")

    processed_count = 0
    batch = []
    with ProcessPoolExecutor(max_workers=workers) as exe:
        it = exe.map(check_url_task, tasks, chunksize=32)
        for res in tqdm(it, total=len(tasks), desc="Scanning URLs", unit="url"):
            batch.append(res)
            processed_count += 1
            if len(batch) >= args.checkpoint_every:
                append_results_to_checkpoint(batch, CHECKPOINT_FILE)
                logger.info(f"Checkpointed {len(batch)} results (total processed this run: {processed_count})")
                batch = []
    if batch:
        append_results_to_checkpoint(batch, CHECKPOINT_FILE)
        logger.info(f"Final checkpointed {len(batch)} results.")

    # aggregate final results into a JSON array
    results = write_final_results_jsonl_to_aggregate(CHECKPOINT_FILE, FINAL_RESULTS_JSON)
    write_final_csv_from_results(results, FINAL_RESULTS_CSV)

    summary = generate_summary(results)
    try:
        with open(SUMMARY_JSON, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, ensure_ascii=False)
        logger.info(f"Wrote summary JSON to {SUMMARY_JSON}")
    except Exception as e:
        logger.exception(f"Failed to write summary JSON: {e}")
    try:
        with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["metric", "value"])
            writer.writerow(["run_at", summary["run_at"]])
            writer.writerow(["total_urls", summary["total_urls"]])
            writer.writerow(["matched_count", summary["matched_count"]])
            writer.writerow(["unmatched_count", summary["unmatched_count"]])
            writer.writerow([])
            writer.writerow(["category", "count"])
            for cat, cnt in summary["by_category"].items():
                writer.writerow([cat, cnt])
        logger.info(f"Wrote summary CSV to {SUMMARY_CSV}")
    except Exception as e:
        logger.exception(f"Failed to write summary CSV: {e}")

    logger.info("Done. Final results saved:")
    logger.info(f" - full results (JSON array): {FINAL_RESULTS_JSON}")
    logger.info(f" - results CSV: {FINAL_RESULTS_CSV}")
    logger.info(f" - summary JSON: {SUMMARY_JSON}")
    logger.info(f" - summary CSV: {SUMMARY_CSV}")
    logger.info(f" - checkpoint file (JSONL): {CHECKPOINT_FILE}")

if __name__ == "__main__":
    main()

#python url_analysis.py --workers 24 --checkpoint-every 1000
#       --resume --blocklist-dir iot-abandonware/firebog_lists/final-blocklists --input-glob iot-abandonware/data/urls/urls_merged.json
#       --output-dir iot-abandonware/firebog_lists/results