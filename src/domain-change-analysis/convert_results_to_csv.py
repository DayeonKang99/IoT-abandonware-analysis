import json
import csv

def json_to_csv(json_input_path, csv_output_path):
    """
    Convert a JSON file (list of dicts) to CSV with 'domain' as the first column.
    """

    with open(json_input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if not isinstance(data, list) or len(data) == 0:
        raise ValueError("JSON file must contain a non-empty list of objects")

    # Define column order
    fieldnames = [
        "domain",
        "changed",
        "confidence",
        "reason",
        "first_date",
        "last_date",
        "years_span"
    ]

    # Fallback: include any unexpected fields at the end
    extra_fields = set()
    for row in data:
        extra_fields.update(row.keys())

    for field in fieldnames:
        extra_fields.discard(field)

    fieldnames.extend(sorted(extra_fields))

    with open(csv_output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

    print(f"Converted {len(data)} records to CSV.")
    print(f"Output written to: {csv_output_path}")

if __name__ == "__main__":
    json_input = "results/validation_results_ground_truth.json"   # path to your JSON file
    csv_output = "results/validation_results_ground_truth.csv"   # desired CSV output path

    json_to_csv(json_input, csv_output)
