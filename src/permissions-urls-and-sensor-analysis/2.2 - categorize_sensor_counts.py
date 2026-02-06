def categorize_sensor(sensor_name: str) -> str:
    s = sensor_name.upper()

    # Motion & Orientation
    if any(k in s for k in [
        "ACCELEROMETER", "GYRO", "ROTATION", "GRAVITY",
        "ORIENTATION", "MOTION", "HINGE", "FREE_FALL"
    ]):
        return "Motion & Orientation"

    # Environmental sensing
    if any(k in s for k in [
        "TEMPERATURE", "HUMIDITY", "PRESSURE", "LIGHT"
    ]):
        return "Environmental"

    # Location & Proximity
    if any(k in s for k in [
        "LOCATION", "GPS", "CELL", "WIFI", "PROXIMITY", "NMEA"
    ]):
        return "Location & Proximity"

    # Device interaction / I/O
    if any(k in s for k in [
        "CAMERA", "NFC", "BLUETOOTH", "HEADSET"
    ]):
        return "Device Interaction"

    # Health & activity
    if any(k in s for k in [
        "STEP", "HEART", "OFFBODY"
    ]):
        return "Health & Activity"

    # Smart home / IoT actuators
    if any(k in s for k in [
        "DOOR", "LOCK", "BLIND", "CURTAIN", "PLUG",
        "GAS", "FIRE", "STATION", "PET_FEEDER",
        "SOFA", "SWITCH"
    ]):
        return "Smart Home / IoT Actuators"

    # System / aggregated
    if any(k in s for k in [
        "ALL", "SUMMARY", "SENSOR_ANA", "SENSOR_DIG", "SENSOR"
    ]):
        return "System / Aggregated"

    # Vendor-specific or opaque
    return "Vendor / Custom Sensors"


from collections import defaultdict

def aggregate_by_category(sensor_counts: dict):
    category_counts = defaultdict(int)
    categorized_sensors = defaultdict(list)

    for sensor, count in sensor_counts.items():
        category = categorize_sensor(sensor)
        category_counts[category] += count
        categorized_sensors[category].append((sensor, count))

    return dict(category_counts), dict(categorized_sensors)


import json

# Load merged sensor counts
with open("path to sensor counts") as f:
    sensor_counts = json.load(f)

category_counts, categorized_sensors = aggregate_by_category(sensor_counts)

# Save category totals
with open("sensor_category_counts.json", "w") as f:
    json.dump(category_counts, f, indent=2)

#save per-category breakdown for appendix
with open("sensor_category_breakdown.json", "w") as f:
    json.dump(categorized_sensors, f, indent=2)
