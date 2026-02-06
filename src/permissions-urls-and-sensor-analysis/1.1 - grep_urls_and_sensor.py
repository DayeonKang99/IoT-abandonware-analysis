import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils import create_logger

create_logger(os.path.basename(__file__))

NOT_COMPLETED_LIST = 'use this to point to a list of specific apps you would like to extract from, else point to csv with list of all apps'
BASE_DIR = 'path to decompiled apps'
URL_OUTPUT_FILE = 'path to store output of urls extracted'   # JSON Lines file
SENSOR_OUTPUT_FILE = 'path to store output of sensors extracted'
MAX_WORKERS = 50  # number of apps processed in parallel

# Load the list of not completed apps
with open(NOT_COMPLETED_LIST, 'r') as f:
    apps_to_process = json.load(f)

# Precompile regex for performance
URL_PATTERN = re.compile(
    r"(http|https)://([a-zA-Z0-9\.-]+|[0-9]{1,3}(\.[0-9]{1,3}){3})(:[0-9]+)?(/[a-zA-Z0-9\./?=_%:-]*)?"
)

SENSOR_PATTERN = re.compile(r"\bSensor\.TYPE_[A-Z_]+\b")


def extract_data_from_file(filepath):
    """Extract all URLs from a single file (ignoring binaries)."""
    urls = set()
    sensors = set()
    try:
        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                for url_match in URL_PATTERN.finditer(line):
                    urls.add(url_match.group(0))

                sensor_matches = SENSOR_PATTERN.findall(line)
                if sensor_matches:
                    sensors.update(sensor_matches)
                
    except Exception as e:
        logging.debug(f"Skipping {filepath} due to error: {e}")
    return urls, sensors


def extract_data_from_app(app_dir):
    """Walk through all files in app_dir and extract URLs."""
    urls = set()
    sensors = set()
    app_path = os.path.join(BASE_DIR, app_dir)
    if not os.path.exists(app_path):
        logging.warning(f"App directory not found: {app_dir}")
        return app_dir, [], []

    logging.info(f"Extracting domains from {app_dir}")
    for root, _, files in os.walk(app_path):
        for file in files:
            filepath = os.path.join(root, file)
            new_urls, new_sensors = extract_data_from_file(filepath)
            urls.update(new_urls)
            sensors.update(new_sensors)

    logging.info(f"Completed extraction from {app_dir} with {len(urls)} urls and {len(sensors)} sensors")
    return app_dir, sorted(urls), sorted(sensors)


def main():
    os.makedirs(os.path.dirname(URL_OUTPUT_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(SENSOR_OUTPUT_FILE), exist_ok=True)
    sensor_counts = {}


    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor, \
            open(URL_OUTPUT_FILE, 'a') as url_out_file, \
                open(SENSOR_OUTPUT_FILE, 'a') as sensor_out_file:  # keep file open once
        futures = {executor.submit(extract_data_from_app, d): d for d in apps_to_process}

        for i, future in enumerate(as_completed(futures), 1):

            app, urls, sensors = future.result()

            # Update sensor counts
            for sensor in sensors:
                sensor_counts[sensor] = sensor_counts.get(sensor, 0) + 1

            url_record = {app: urls}
            sensor_record = {app : sensors}
            url_out_file.write(json.dumps(url_record) + "\n")
            sensor_out_file.write(json.dumps(sensor_record) + "\n")
            url_out_file.flush()  # flush to disk so progress isn�t lost
            sensor_out_file.flush()
            print(f"[{i}/{len(apps_to_process)}] Saved {app} with {len(urls)} URLs and {len(sensors)} sensors")

            with open("data/sensor_counts_part5.json", "w") as f_counts:
                json.dump(sensor_counts, f_counts, indent=4)

if __name__ == "__main__":
    main()
