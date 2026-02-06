import csv
import datetime
import logging
from google_play_scraper import app
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Config ---
INPUT_CSV = "bert_iot_filtered.csv"       # CSV with column: package_name
OUTPUT_CSV = "app_obsolete_flags.csv"
LOG_FILE = "obsolete_flag_checker.log"
MAX_WORKERS = 40

# --- Logging ---
logging.basicConfig(
    filename=LOG_FILE,
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# --- Date threshold ---
now = datetime.datetime.now()
two_years_ago = now - datetime.timedelta(days=730)

# --- Check app ---
def is_obsolete(app_id):
    try:
        print(f"Checking app: {app_id}")
        result = app(app_id, lang='en', country='us')

        if 'updated' in result:
            updated_date = datetime.datetime.fromtimestamp(result['updated'])
            if updated_date < two_years_ago:
                logging.info(f"{app_id} is outdated: last updated {updated_date}")
                return 1
            else:
                return 0
        else:
            logging.info(f"{app_id} has no update info.")
            return 1
    except Exception as e:
        logging.warning(f"{app_id} not found or error: {e}")
        return 1  # Not found or error → treat as obsolete

# --- Main ---
def main():
    with open(INPUT_CSV, 'r') as infile, open(OUTPUT_CSV, 'w', newline='') as outfile:
        reader = csv.DictReader(infile)
        writer = csv.writer(outfile)
        writer.writerow(['package_name', 'is_obsolete'])  # header

        for row in reader:
            app_id = row['package_name']
            flag = is_obsolete(app_id)
            writer.writerow([app_id, flag])

    print(f"Finished. Results saved to {OUTPUT_CSV}")

# --- Main ---
def main():
    with open(INPUT_CSV, 'r') as infile:
        reader = csv.DictReader(infile)
        app_ids = [row['package_name'].strip() for row in reader if row['package_name'].strip()]

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(is_obsolete, app_id): app_id for app_id in app_ids}

        for future in as_completed(futures):
            app_id, flag = future.result()
            results.append((app_id, flag))

    with open(OUTPUT_CSV, 'w', newline='') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(['package_name', 'is_obsolete'])  # header
        for app_id, flag in results:
            writer.writerow([app_id, flag])

    print(f"Finished checking {len(results)} apps.")
    logging.info(f"Finished checking {len(results)} apps.")

# --- Run ---
if __name__ == "__main__":
    main()