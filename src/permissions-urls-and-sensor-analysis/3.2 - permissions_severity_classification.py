import json
import matplotlib.pyplot as plt
import os

# ---- CONFIG ----
data_file = "/path/to/extracted/permissions/json"      # Path to your JSON file
output_json = "/path/to/output/json"   # JSON output
output_pdf = "/path/to/output/graph"      # PDF output

# ---- SEVERITY LISTS ----
high_severity = [
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECEIVE_WAP_PUSH",
    "RECEIVE_MMS", "READ_CONTACTS", "WRITE_CONTACTS",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "READ_PHONE_STATE", "CALL_PHONE", "ANSWER_PHONE_CALLS",
    "USE_SIP", "RECORD_AUDIO"
]

medium_severity = [
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "CAMERA",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES",
    "READ_MEDIA_VIDEO", "BLUETOOTH_CONNECT", "BODY_SENSORS"
]

low_severity = [
    "INTERNET", "VIBRATE", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE",
    "WAKE_LOCK", "FOREGROUND_SERVICE", "BLUETOOTH", "BLUETOOTH_ADMIN"
]

# # ---- LOAD PERMISSION DATA ----
# if not os.path.exists(data_file):
#     raise FileNotFoundError(f"Could not find data file: {data_file}")

# with open(data_file, "r") as f:
#     app_permissions = json.load(f)  # {app_name: [permissions list], ...}

# # ---- COUNT APPS USING EACH SEVERITY ----
# severity_counts = {"High": 0, "Medium": 0, "Low": 0}

# for app, perms in app_permissions.items():
#     # Only keep the part after last '.'
#     cleaned_perms = [p.split(".")[-1] for p in perms]

#     if any(p in high_severity for p in cleaned_perms):
#         severity_counts["High"] += 1
#     elif any(p in medium_severity for p in cleaned_perms):
#         severity_counts["Medium"] += 1
#     elif any(p in low_severity for p in cleaned_perms):
#         severity_counts["Low"] += 1

# # ---- PRINT RESULTS ----
# print("\n===== Permission Severity Summary =====")
# for level, count in severity_counts.items():
#     print(f"{level} severity: {count} apps")

# # ---- SAVE JSON ----
# with open(output_json, "w") as f:
#     json.dump(severity_counts, f, indent=4)
# print(f"\n? JSON saved to: {output_json}")

# # ---- SAVE BAR CHART AS PDF ----
# severity_labels = list(severity_counts.keys())
# counts = [severity_counts[l] for l in severity_labels]
# colors = ["#e74c3c", "#f39c12", "#27ae60"]  # red, orange, green

# plt.figure(figsize=(6, 4))
# plt.bar(severity_labels, counts, color=colors, width=0.6)
# plt.title("App Counts by Permission Severity", fontsize=13)
# plt.ylabel("Number of Apps", fontsize=11)
# plt.grid(axis="y", linestyle="--", alpha=0.6)
# plt.tight_layout()
# plt.savefig(output_pdf)
# plt.show()
# print(f"? Bar chart saved as: {output_pdf}")

# ---- LOAD PERMISSION DATA FROM JSONL ----
app_permissions = {}
with open(data_file, "r") as f:
    for line in f:
        if line.strip():
            data = json.loads(line)
            app_name = os.path.basename(data["app"]).replace(".apk", "")
            app_permissions[app_name] = data.get("permissions", [])

# ---- COUNT APPS USING EACH SEVERITY ----
severity_counts = {"High": 0, "Medium": 0, "Low": 0, "No Permissions": 0}

for app, perms in app_permissions.items():
    if not perms:
        severity_counts["No Permissions"] += 1
        continue

    cleaned_perms = [p.split(".")[-1] for p in perms]  # only the last part

    if any(p in high_severity for p in cleaned_perms):
        severity_counts["High"] += 1
    elif any(p in medium_severity for p in cleaned_perms):
        severity_counts["Medium"] += 1
    elif any(p in low_severity for p in cleaned_perms):
        severity_counts["Low"] += 1

# ---- PRINT RESULTS ----
print("\n===== Permission Severity Summary =====")
for level, count in severity_counts.items():
    print(f"{level}: {count} apps")

# ---- SAVE JSON ----
with open(output_json, "w") as f:
    json.dump(severity_counts, f, indent=4)
print(f"\n? JSON saved to: {output_json}")

# ---- SAVE BAR CHART AS PDF ----
severity_labels = list(severity_counts.keys())
counts = [severity_counts[l] for l in severity_labels]
colors = ["#e74c3c", "#f39c12", "#27ae60", "#95a5a6"]  # gray for No Permissions

plt.figure(figsize=(7, 4))
plt.bar(severity_labels, counts, color=colors, width=0.6)
plt.title("App Counts by Permission Severity", fontsize=13)
plt.ylabel("Number of Apps", fontsize=11)
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.tight_layout()
plt.savefig(output_pdf)
plt.show()
print(f"? Bar chart saved as: {output_pdf}")