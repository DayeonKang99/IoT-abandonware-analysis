import os
import json
import csv
from tqdm import tqdm
from google_play_scraper import app
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import threading
import logging

# Paths
APP_DIR = "path to decompiled apps"
OUTPUT_FILE = "path to save output results"
STATS_FILE = "path to save stats file"
NOT_FOUND_FILE = "path to save list of apps whose categories are not found"
MAX_WORKERS = 50
LOG_FILE = "path to save log"

# Thread-safe counters and lock
genre_counter = Counter()
# genreid_counter = Counter()
category_counter = Counter()
lock = threading.Lock()

# Create directories/files if not present
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
for fpath in [OUTPUT_FILE, NOT_FOUND_FILE]:
    if not os.path.exists(fpath):
        open(fpath, "w", encoding="utf-8").close()

# -----------------------
# Setup Logging
# -----------------------
logging.basicConfig(
    filename=LOG_FILE,
    filemode="a",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
console.setFormatter(formatter)
logging.getLogger().addHandler(console)


def fetch_app_info(app_id):
    """Fetch genre info for one app from Play Store."""
    try:
        details = app(app_id, lang="en", country="us")
        genre = details.get("genre")
        genre_id = details.get("genreId")
        categories = details.get("categories", [])

        # Prepare result dict
        result = {
            "app_id": app_id,
            "genre": genre,
            "genreId": genre_id,
            "categories": categories
        }

        # Write app result to file immediately
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")

        # Update counters safely
        with lock:
            if genre:
                genre_counter[genre] += 1
            # if genre_id:
            #     genreid_counter[genre_id] += 1
            for cat in categories:
                if isinstance(cat, dict) and "name" in cat:
                    category_counter[cat["name"]] += 1
                elif isinstance(cat, str):
                    category_counter[cat] += 1
	
        logging.info(f"? Processed {app_id}")
        return app_id, True

    except Exception as e:
        # Log failed app immediately
        with lock, open(NOT_FOUND_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([app_id, str(e)])
        logging.warning(f"?? Failed {app_id}: {e}")
        return app_id, str(e)


def main():
    app_ids = [folder for folder in os.listdir(APP_DIR)
               if os.path.isdir(os.path.join(APP_DIR, folder))]

    print(f"🔍 Found {len(app_ids)} apps to process...")
    logging.info(f"?? Found {len(app_ids)} apps to process...")


    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_app_info, app_id): app_id for app_id in app_ids}
        for future in tqdm(as_completed(futures), total=len(futures)):
            app_id, status = future.result()
            if status is not True:
                print(f"⚠️ {app_id}: {status}")
                logging.error(f"? {app_id}: {status}")


    # Save aggregated stats
    stats = {
        "genre_counts": dict(sorted(genre_counter.items(), key=lambda x: x[1], reverse=True)),
        # "genreId_counts": dict(sorted(genreid_counter.items(), key=lambda x: x[1], reverse=True)),
        "category_counts": dict(sorted(category_counter.items(), key=lambda x: x[1], reverse=True))
    }

    with open(STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=4, ensure_ascii=False)

    print(f"\n✅ Done.")
    print(f"   Results saved in: {OUTPUT_FILE}")
    print(f"   Stats saved in: {STATS_FILE}")
    print(f"   Not found apps saved in: {NOT_FOUND_FILE}")

    logging.info("? Done.")
    logging.info(f"Results saved in: {OUTPUT_FILE}")
    logging.info(f"Stats saved in: {STATS_FILE}")
    logging.info(f"Not found apps saved in: {NOT_FOUND_FILE}")
    logging.info(f"Logs saved in: {LOG_FILE}")

if __name__ == "__main__":
    main()