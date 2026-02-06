import os
import json
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from collections import Counter

# Base directory containing apps
base_directory = "path/to/decompiled/apps"

# Paths for output
jsonl_output_path = "/path/to/output/json/results"
summary_output_path = "/path/to/output/results/summary"

# Dangerous permissions list
dangerous_permissions = {
    "READ_CALENDAR",
    "WRITE_CALENDAR",
    "CAMERA",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "GET_ACCOUNTS",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "RECORD_AUDIO",
    "READ_PHONE_STATE",
    "CALL_PHONE",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "ADD_VOICEMAIL",
    "USE_SIP",
    "PROCESS_OUTGOING_CALLS",
    "BODY_SENSORS",
    "SEND_SMS",
    "RECEIVE_SMS",
    "READ_SMS",
    "RECEIVE_WAP_PUSH",
    "RECEIVE_MMS",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
}

# Configure logging
logging.basicConfig(
    filename="v3_permissions_extraction.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

def extract_permissions_from_manifest(manifest_path):
    """Extract dangerous permissions from AndroidManifest.xml"""
    dangerous_found = []
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        for elem in root.findall("uses-permission"):
            perm = elem.get("{http://schemas.android.com/apk/res/android}name")
            if perm and perm.split(".")[-1] in dangerous_permissions:
                dangerous_found.append(perm)  # keep full permission name
    except Exception as e:
        logging.error(f"Error parsing {manifest_path}: {e}")
    return dangerous_found

def process_app(app_dir):
    """Process a single app directory"""
    manifest_path = os.path.join(app_dir, "resources", "AndroidManifest.xml")
    if not os.path.isfile(manifest_path):
        logging.warning(f"No manifest found for {app_dir}")
        return app_dir, []
    dangerous_perms = extract_permissions_from_manifest(manifest_path)
    return app_dir, dangerous_perms

def main():
    permission_counter = Counter()

    # Open JSONL file in append mode
    with open(jsonl_output_path, "a") as jsonl_file:
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {
                executor.submit(process_app, os.path.join(base_directory, d)): d
                for d in os.listdir(base_directory)
                if os.path.isdir(os.path.join(base_directory, d))
            }

            for future in as_completed(futures):
                app, perms = future.result()

                # ? Append per-app result (one JSON object per line)
                jsonl_file.write(json.dumps({"app": app, "permissions": perms}) + "\n")

                # ? Update global counter
                for p in set(perms):
                    permission_counter[p] += 1

                logging.info(f"Processed {app}: {perms}")

    # ? Save final summary counts
    summary_output = {
        "dangerous_permission_counts": dict(permission_counter)
    }
    with open(summary_output_path, "w") as f:
        json.dump(summary_output, f, indent=4)

    # ? Print summary to console
    print(json.dumps(summary_output, indent=4))

if __name__ == "__main__":
    main()
