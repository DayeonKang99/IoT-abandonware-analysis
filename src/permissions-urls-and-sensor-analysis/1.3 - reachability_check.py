import json
import logging
import os.path
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from os import walk

import dns.resolver

from utils import create_logger

my_resolver = dns.resolver.Resolver()
create_logger(os.path.basename(__file__))

INPUT_DIR = 'path to unique domains'
OUTPUT_DIR = 'output path to store each files reachability results'
SELECTED_FILE = 'path to csv file of apps you want to check, else point to csv containing all apps list'  # path to your selection list

@lru_cache(maxsize=None)
def check_reachability(domain):
    try:
        answers = my_resolver.resolve(domain, 'A')
        return [record.address for record in answers]
    except Exception as e:
        return str(e)


def execute(filename):
    logging.info(f'Checking for {filename}')
    input_path = os.path.join(INPUT_DIR, filename)
    output_path = os.path.join(OUTPUT_DIR, filename)

    try:
        with open(input_path, 'r') as reader:
            info = json.load(reader)
    except Exception as e:
        logging.error(f'Failed to read {input_path}: {e}')
        return

    fqdns = info.get('fqdns', [])
    reachability = {}

    for d in fqdns:
        ips = check_reachability(d)
        reachability[d] = ips

    with open(output_path, 'w') as writer:
        json.dump(reachability, writer, indent=4)

    logging.info(f'Completed for {filename}')


if __name__ == '__main__':
    # Load the app list JSON
    with open(SELECTED_FILE, 'r') as f:
        app_list = json.load(f)

    # Create filenames from keys (e.g., "app1.json", "app2.json", ...)
    selected_files = [f"{app}.json" for app in app_list.keys()]

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with ThreadPoolExecutor(max_workers=40) as executor:
        for f in selected_files:
            input_path = os.path.join(INPUT_DIR, f)
            if os.path.exists(input_path):
                executor.submit(execute, f)
            else:
                logging.warning(f'Skipping {f}: file not found in {INPUT_DIR}')