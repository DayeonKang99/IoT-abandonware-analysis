import json
from collections import Counter

# Path to filtered JSON
filtered_json_path = "path to your extracted sensors list"

# Path for the sensor counts output
sensor_counts_path = "path to save results of sensor counts"

# Load filtered apps JSON
with open(filtered_json_path, "r") as f:
    apps_data = json.load(f)

# Count number of apps per sensor
sensor_counter = Counter()
for perms in apps_data.values():
    for sensor in perms:
        sensor_counter[sensor] += 1

# Save counts to JSON
with open(sensor_counts_path, "w") as f:
    json.dump(dict(sensor_counter), f, indent=4)

print(f"Saved sensor counts for {len(sensor_counter)} sensors to {sensor_counts_path}")
