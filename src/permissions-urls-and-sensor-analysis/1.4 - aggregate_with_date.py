import json
import logging
import datetime
from os import walk
from google_play_scraper import app

# Directories
INPUT_DIR = 'path of reachability results'
OUTPUT_DIR = 'path to store aggregated results'

# Logging
logging.basicConfig(
    filename='reachability_with_updates.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

def get_unreachable(file) -> dict:
    with open(INPUT_DIR + file, 'r') as reader:
        data = json.load(reader)

    info = {
        'total': 0,
        'unreachable': 0,
        'reachable_fqdn': [],
        'unreachable_fqdn': [],
    }

    for datum in data:
        info['total'] += 1
        if type(data[datum]) is str:
            info['unreachable'] += 1
            info['unreachable_fqdn'].append(datum)
        else:
            info['reachable_fqdn'].append(datum)

    return info

def get_last_updated(app_id):
    try:
        result = app(app_id, lang='en', country='us')
        updated_timestamp = result.get('updated')
        if updated_timestamp:
            updated_date = datetime.datetime.fromtimestamp(updated_timestamp).isoformat()
            return updated_date
    except Exception as e:
        logging.warning(f"Failed to fetch updated date for {app_id}: {e}")
    return None

def main():
    filenames = next(walk(INPUT_DIR), (None, None, []))[2]

    counts_per_app = {}
    aggregate_counts = {
        'total': 0,
        'unreachable': 0,
        'unique_unreachable': 0,
        'unique_reachable': 0,
        'unreachable_fqdn': set(),
        'reachable_fqdn': set()
    }

    for f in filenames:
        info = get_unreachable(f)

        # Extract app ID from filename like com.example.apk.json ? com.example
        app_id = f.replace('.apk.json', '')

        # Try to get the last updated date from Google Play
        updated_date = get_last_updated(app_id)
        info['last_updated'] = updated_date

        counts_per_app[f] = info

        # Aggregate
        aggregate_counts['total'] += info['total']
        aggregate_counts['unreachable'] += info['unreachable']
        aggregate_counts['unreachable_fqdn'].update(info['unreachable_fqdn'])
        aggregate_counts['reachable_fqdn'].update(info['reachable_fqdn'])

    aggregate_counts['unreachable_fqdn'] = list(aggregate_counts['unreachable_fqdn'])
    aggregate_counts['reachable_fqdn'] = list(aggregate_counts['reachable_fqdn'])
    aggregate_counts['unique_unreachable'] = len(aggregate_counts['unreachable_fqdn'])
    aggregate_counts['unique_reachable'] = len(aggregate_counts['reachable_fqdn'])

    with open(OUTPUT_DIR + 'counts_per_app_with_date.json', 'w') as writer:
        json.dump(counts_per_app, writer, indent=4)

    with open(OUTPUT_DIR + 'aggregate_counts_new.json', 'w') as writer:
        json.dump(aggregate_counts, writer, indent=4)

if __name__ == '__main__':
    main()
