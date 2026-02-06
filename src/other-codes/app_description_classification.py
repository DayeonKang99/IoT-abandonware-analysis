import json
import csv
import logging
from transformers import pipeline
from tqdm import tqdm

# ---------------- CONFIG ----------------
input_csv = "path to app descriptions from androzoo"
unmatched_csv = "path to csv list of apps you want to classify"
output_jsonl = "path to save output json"
log_file = "path to save output log"

categories = [
    "Tools", "Health & Fitness", "Business", "Productivity", "Lifestyle",
    "Auto & Vehicles", "Entertainment", "Music & Audio", "House & Home",
    "Communication", "Education", "Photography", "Video Players & Editors", 
    "Weather"
    
]
# ----------------------------------------

# Logging setup
logging.basicConfig(
    filename=log_file,
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logging.info("=== Classification run started ===")

# Load unmatched app list
with open(unmatched_csv, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    unmatched_apps = {
        row["package_name"].strip().replace(".apk", "")
        for row in reader
        if row.get("package_name")
    }

logging.info(f"Loaded {len(unmatched_apps)} unmatched app IDs.")

# Load CSV and filter rows
with open(input_csv, "r", encoding="utf-8") as f:
    reader = list(csv.DictReader(f))

filtered_rows = [row for row in reader if row["package_name"].strip().replace(".apk", "") in unmatched_apps]
logging.info(f"Filtered {len(filtered_rows)} apps from CSV that match the unmatched list.")

# Initialize classifier
classifier = pipeline(
    "zero-shot-classification",
    model="MoritzLaurer/deberta-v3-base-zeroshot-v2.0",
    device=0  # use GPU, set -1 for CPU
)

# Process sequentially and save after each classification
with open(output_jsonl, "a", encoding="utf-8") as out:
    for row in tqdm(filtered_rows, desc="Classifying apps"):
        pkg = row["package_name"].strip()
        desc = row.get("description", "").strip()

        if not desc:
            logging.warning(f"Skipping {pkg} - no description found.")
            continue

        try:
            res = classifier(desc, categories)
            best_label = res["labels"][0]
            best_score = round(res["scores"][0], 3)

            record = {
                "app_id": pkg,
                "category": best_label,
                "confidence": best_score
            }

            # Write immediately to JSONL
            out.write(json.dumps(record) + "\n")
            out.flush()

            logging.info(f"{pkg}: {best_label} ({best_score})")

        except Exception as e:
            logging.error(f"Error processing {pkg}: {e}")

logging.info("=== Classification run completed successfully ===")
print(f"\n? Classification complete. Results saved to {output_jsonl}")
