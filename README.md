# IoT-Abandonware

We present the security analysis framework for abandoned IoT companion apps. 
The dataset we used is in `/dataset` directory and codes for analysis are in `/src`

## Configuring IoT Abandonware Dataset

The dataset is provided in the `dataset/` directory. You may skip the construction steps and proceed directly to [Download IoT Abandonware APKs](#download-iot-abandonware-apks) if you wish to use the provided dataset as-is.

### Dataset Overview

The `dataset/` directory contains the following files:

| File | Description |
|------|-------------|
| `abandoned_apps.csv` | 61,500 abandoned IoT app package IDs. The `is_obsolete` field indicates whether an app is abandoned because it was removed from the Play Store (`True`) or has not been updated in over two years (`True`). |
| `abandoned_apps_with_versions.csv` | Abandoned apps with their AndroZoo SHA256 hashes and version information, used for APK download. |
| `top_500_active_iot_apps_with_versions.csv` | Top 500 active (non-abandoned) IoT apps by install count, used as a comparison baseline for RQ4. |

An app is defined as **abandoned** if, as of March 2025, it either:
- is **no longer available** on the Google Play Store, or
- has **not received an update since March 2023** (i.e., no update in over two years).

The dataset comprises 54,886 apps removed from the Google Play Store and 6,614 apps that remain listed but have not been updated for more than two years.

The source location (in Play Store and not in Play Store) information is in `src/iotflow/data/61k_app_installs.json`.

### IoT Abandonware Configuration

The dataset was constructed by running the four numbered scripts in `dataset/` in sequence. Each step consumes the output of the previous one.

#### Prerequisites

- **AndroZoo API key**: Required to download app metadata and APKs. Register at [https://androzoo.uni.lu](https://androzoo.uni.lu) to obtain a key.
- **AndroZoo APK list CSV**: Download the full list of available APKs from AndroZoo ("Obtaining SHA256 Hashes" section). This CSV maps each APK to its SHA256 hash, package name, and version.
- **IoTSpotter BERT model**: Download from [IoTSpotter](https://github.com/IoTSpotter/IoTSpotter) for Step 2.
- **Dependencies**:

```bash
pip install requests google-play-scraper
```

#### Step 1 — Retrieve App Descriptions

```bash
python "dataset/1. get_app_descriptions.py"
```

Fetches the Google Play Store description for each app in the AndroZoo CSV via the AndroZoo metadata API (`https://androzoo.uni.lu/api/get_gp_metadata/<package_name>`). Before running, deduplicate the CSV by keeping only the **latest version** of each package name.

Set your AndroZoo API key in the script (`api_key` variable) before running.

#### Step 2 — Classify Apps as IoT or Non-IoT

```bash
python "dataset/2. bert_description_classification.py"
```

Applies [IoTSpotter](https://github.com/IoTSpotter/IoTSpotter)'s BERT-based classifier to the app descriptions from Step 1 to label each app as **IoT** or **Non-IoT**.

#### Step 3 — Filter IoT Apps

```bash
python "dataset/3. classification_iot_filter.py"
```

Retains only apps classified as IoT companion apps, producing `bert_iot_filtered.csv`. This yields **95,058 IoT candidate apps** that are passed to the abandonment check.

#### Step 4 — Identify Abandoned Apps

```bash
python "dataset/4. check_if_abandoned.py"
```

Checks the current Play Store status of each IoT app using [google-play-scraper](https://pypi.org/project/google-play-scraper/). An app is marked **abandoned** (`is_obsolete = True`) if:
- it is **no longer listed** on the Google Play Store, or
- its **last update date** is more than 730 days before the collection date (March 2025).

Output is written to `app_obsolete_flags.csv`. After filtering, the final dataset contains **61,500 abandoned IoT companion apps**.

⚠️ This number can be different because we configured the dataset with an AndroZoo snapshot in March 2025. 

---

### Download IoT Abandonware APKs

Use the SHA256 hashes in `abandoned_apps_with_versions.csv` to download APKs from AndroZoo:

```bash
curl -O "https://androzoo.uni.lu/api/download?apikey=<YOUR_API_KEY>&sha256=<SHA256>"
```

> **Note**: Downloading all 61,500 APKs requires significant storage (~several TB).  

---

### Decompile IoT Abandonware APKs

Decompile each downloaded APK using [Jadx](https://github.com/skylot/jadx):

```bash
jadx -d <output_dir>/ <apk_file>.apk
```

The decompiled source output is used as input for all subsequent analyses (Embedded Resource Analysis).

---
## Embedded Resource Analysis

The embedded resource analysis extracts and assesses three types of artifacts from decompiled APKs: **static URLs and domain names** (for at-risk domain analysis), **IoT sensor accesses**, and **declared permissions**. All scripts are in `src/permissions-urls-and-sensor-analysis/`.

**Prerequisite**: Decompiled APK directories from the [Decompile IoT Abandonware APKs](#decompile-iot-abandonware-apks) step.

Install required packages:
```bash
pip install tldextract dnspython google-play-scraper matplotlib
```

Before running any script, update the path variables at the top of each file to point to your decompiled app directories and desired output locations.

---

### Outdated Dependencies Analysis

This pipeline identifies libraries bundled in each decompiled APK and cross-references them against the National Vulnerability Database (NVD) to flag CVEs published after the app's last update. All scripts are in `src/cve-search/`.

Install required packages:
```bash
pip install ijson nvdlib packaging tqdm requests
```

---

#### Step 0 — Download NVD JSON Feeds (Offline Path Only)

Download the NVD JSON data feeds from:

> **https://nvd.nist.gov/vuln/data-feeds**

Download all available annual JSON feed files (e.g., `nvdcve-2.0-2002.json` through `nvdcve-2.0-modified.json`) and place them in a single directory (e.g., `nvd-feeds/`). These feeds are required by `nvd_db_build.py` to build the local search index.

⚠️ Since the current JSON feed files were updated on September 18, 2026, the analysis pipeline may not reproduce the same result as the paper because we downloaded the JSON feed files before August 1, 2026.

#### Step 1 — Build the Local NVD Database (Offline Path Only)

```bash
python src/cve-search/nvd_db_build.py
```

Ingests all NVD JSON feed files from the directory specified above and builds a local SQLite database (`nvd_local.db`) with two tables:

- `cves` — stores each CVE's ID, published date, and full JSON payload
- `cve_search` — an FTS5 full-text search virtual table indexed on CVE ID and English description

Files are parsed using `ijson` for memory-efficient streaming. Update `nvd_folder` and `db_path` in the script before running.

| Variable | Description |
|---|---|
| `nvd_folder` | Path to the directory containing downloaded NVD JSON feed files |
| `db_path` | Output path for the SQLite database (e.g., `nvd_local.db`) |

#### Step 2 — Extract Bundled Library Names from Decompiled APKs

```bash
python src/cve-search/cve_lib_parsing.py
```

Scans the resource directories of each decompiled APK to extract bundled library names and their versions (inferred from subdirectory structure and `BuildConfig.java` files). Outputs a list of `library_name,version` pairs per app for CVE lookup.

Set the following before running:

| Variable | Description |
|---|---|
| `jadx_output_file` | Path to a text file listing the app directories to process |

> **Offline path**: Leave the API key empty. The library names extracted here are used as input to `cve_search_offline.py` in the next step.

#### Step 3 — Search CVEs Offline (Offline Path Only)

```bash
python src/cve-search/cve_search_offline.py
```

Reads a shard of library names (format: `library_name,version` or `library_name` per line) and searches the local SQLite FTS5 database from Step 1 for matching CVE entries. Performs version-aware filtering using `packaging.version` to confirm whether the library version falls within the CVE's affected range. Runs parallel SQLite read queries across up to `MAX_WORKERS` threads.

For large datasets, split the library list into multiple shard files and run this script once per shard in parallel (e.g., across multiple machines or processes). Each run produces one output shard (e.g., `output/libraries_with_cves_00.json`).

| Variable | Description |
|---|---|
| `DB_PATH` | Path to the SQLite database from Step 1 |
| `LIBRARIES_FILE` | Path to the shard input file (one `name,version` per line) |
| `OUTPUT_JSON` | Output path for this shard's CVE results |
| `MAX_WORKERS` | Number of parallel SQLite reader threads (default: 10) |

#### Step 4 — Merge CVE Search Shards into a Library Directory

```bash
python src/cve-search/generate_lib_dir.py
```

Merges all per-shard JSON output files from Step 3 (matched by `swarm-output/libraries_with_cves_*.json`) into a single consolidated `lib_dir.json`. When the same library name appears in multiple shards, a rank-based conflict resolution rule is applied:

| Rank | Meaning |
|---|---|
| 2 | Searched; CVEs found |
| 1 | Searched; confirmed zero CVEs |
| 0 | Heuristically skipped; status unknown |

The highest-rank entry is kept per library name. Update `SHARD_FILES` to match your shard file paths before running.

#### Step 5 — Attach CVEs to Per-App Library Data

```bash
python src/cve-search/merge_data.py
```

Joins `lib_dir.json` (from Step 4) with per-app parsed library data files (`parsed_libraries_0{N}.json` from Step 2) to produce a final dataset where each app's bundled libraries are annotated with their matching CVE records. Libraries absent from `lib_dir.json` are flagged as `failed`; heuristically skipped entries are flagged as `skipped_kept`. The merged output is used for the CVE severity analysis and figures in the paper.

Update the input/output file paths at the top of the script before running.

#### Step 6 — Count and Classify CVEs by Confidence

```bash
python src/cve-search/create_cve_count.py
```

Reads the merged per-app library data from Step 5 (`./final-output/parsed_libraries_*.json`) using `ijson` for memory-efficient streaming across multiple shards. For each app, performs version-aware CVE matching using `packaging.version` and classifies each CVE-library association by confidence level. Produces two output files:

| Output File | Description |
|---|---|
| `cve_analysis_count.jsonl` | Per-app CVE counts annotated with confidence levels |
| `confirmed_outdated_libraries.jsonl` | Library entries confirmed as outdated (CVE published after app's last update date) |

Configure the following variables before running:

| Variable | Description |
|---|---|
| `INPUT_FILES` | Glob pattern matching the merged shard files from Step 5 (default: `./final-output/parsed_libraries_*.json`) |
| `output` | Output path for the per-app CVE count results |
| `confirmed_outdated_output` | Output path for confirmed outdated library records |

> **Note**: If shard filenames or ordering are not consistent via glob, replace `INPUT_FILES` with an explicit list (see the commented-out example in the script).

#### Step 7 — Plot CVE Analysis Results

Open and run `src/cve-search/plot-cve-analysis.ipynb` in Jupyter Notebook to reproduce the CVE severity distribution figures from the paper.

```bash
jupyter notebook src/cve-search/plot-cve-analysis.ipynb
```


---

### At-Risk Domain Analysis

This pipeline extracts static URLs from decompiled source code, resolves the unique domains, classifies them as reachable or unreachable (Steps 1.1–1.4 below), checks them against category blocklists, and flags domains that appear to have changed ownership since the app was last updated (Steps 1.5–1.6).

#### Step 1.1 — Extract URLs and Sensor References

```bash
python "src/permissions-urls-and-sensor-analysis/1.1 - grep_urls_and_sensor.py"
```

Recursively scans all non-binary files under each decompiled app directory and applies two regex patterns:

- **URLs** — `(http|https)://...`: extracts all static HTTP/HTTPS links and hard-coded IPv4 addresses
- **Sensors** — `\bSensor\.TYPE_[A-Z_]+\b`: extracts all Android sensor constant references (used in Steps 2.1–2.2)

Configure the following variables before running:

| Variable | Description |
|---|---|
| `BASE_DIR` | Root directory containing decompiled app folders |
| `NOT_COMPLETED_LIST` | Path to a JSON or CSV file listing the package names to process |
| `URL_OUTPUT_FILE` | Output path for extracted URLs (JSON Lines format) |
| `SENSOR_OUTPUT_FILE` | Output path for extracted sensor references (JSON) |
| `MAX_WORKERS` | Number of parallel workers (default: 50) |

#### Step 1.2 — Extract Unique FQDNs per App

```bash
python "src/permissions-urls-and-sensor-analysis/1.2 - unique_domains_extraction.py"
```

Parses the URL JSON Lines file from Step 1.1 and extracts the unique FQDN for each URL using `tldextract`. Writes one JSON file per app containing its unique domain set.

| Variable | Description |
|---|---|
| `INPUT_PATH` | Path to the URL JSONL output from Step 1.1 |
| `OUTPUT_DIR` | Directory to store per-app FQDN files |
| `MAX_WORKERS` | Number of parallel workers (default: 50) |

#### Step 1.3 — DNS Reachability Check

```bash
python "src/permissions-urls-and-sensor-analysis/1.3 - reachability_check.py"
```

Performs recursive DNS A-record resolution for every FQDN from Step 1.2, querying Google's public resolver (`8.8.8.8`). A domain is classified as **reachable** if it resolves to at least one IPv4 address and **unreachable** if it returns NXDOMAIN, has no A records, or times out. Results are cached with `lru_cache` to avoid redundant lookups across apps.

| Variable | Description |
|---|---|
| `INPUT_DIR` | Directory of per-app FQDN files from Step 1.2 |
| `OUTPUT_DIR` | Directory to store per-app reachability result files |
| `SELECTED_FILE` | Path to a CSV listing the apps to process |

#### Step 1.4 — Aggregate Reachability Results with App Date

```bash
python "src/permissions-urls-and-sensor-analysis/1.4 - aggregate_with_date.py"
```

Aggregates the per-app reachability JSON files from Step 1.3 and enriches each entry with the app's last-update date retrieved via Google Play Scraper. Produces a per-app summary containing total, reachable, and unreachable FQDN counts alongside the app's update date.

| Variable | Description |
|---|---|
| `INPUT_DIR` | Directory of per-app reachability results from Step 1.3 |
| `OUTPUT_DIR` | Directory to store the aggregated output |

#### Step 1.5 — Blocklist Matching

```bash
python src/blocklist-analysis/url_analysis.py
```

Checks every extracted URL (Step 1.1's output, merged into one corpus) against category blocklists — ads, malware, spyware, phishing, spam, tracking, scams, and suspicious — to flag apps that embed known-risky domains. A supplementary `malicious-checks/` sub-pipeline cross-checks the same URLs against the OISD and URLhaus blocklists and a live ad-network list.

See [`src/blocklist-analysis/README.md`](src/blocklist-analysis/README.md) for setup, exact commands, and the included full reference run.

#### Step 1.6 — Domain Ownership Change Detection

```bash
python src/domain-change-analysis/ownership_change_analysis.py
```

Uses WHOIS history (via the WhoisXMLAPI *WHOIS History* API) to detect whether a domain referenced by an app has changed ownership since the app was last updated — a signal that the app may now point at a re-registered, parked, or seized domain. Ground truth comes from non-redacted registrant fields where available; the detection algorithm itself relies only on GDPR-compliant proxy signals (registrar, nameserver behavior, DNSSEC, etc.), so it still works once registrant info is redacted.

See [`src/domain-change-analysis/README.md`](src/domain-change-analysis/README.md) for setup, exact commands, and included reference data — reproducing the reported results does not require a WhoisXMLAPI key.

---

### Sensor Analysis

These scripts count and categorize the IoT device sensor types accessed across the dataset, using the sensor extraction output from Step 1.1.

#### Step 2.1 — Count Sensor References per App

```bash
python "src/permissions-urls-and-sensor-analysis/2.1 - sensors_count.py"
```

Reads the sensor JSON from Step 1.1 and counts how many apps reference each `Sensor.TYPE_*` constant, producing a frequency table across the dataset.

| Variable | Description |
|---|---|
| `filtered_json_path` | Path to the sensor output from Step 1.1 |
| `sensor_counts_path` | Output path for the per-sensor app counts (JSON) |

#### Step 2.2 — Categorize Sensor Types

```bash
python "src/permissions-urls-and-sensor-analysis/2.2 - categorize_sensor_counts.py"
```

Groups individual `Sensor.TYPE_*` constants into semantic categories. Update the input/output paths at the top of the script before running.

| Category | Example Sensor Types |
|---|---|
| Motion & Orientation | `ACCELEROMETER`, `GYROSCOPE`, `ROTATION_VECTOR` |
| Environmental | `AMBIENT_TEMPERATURE`, `RELATIVE_HUMIDITY`, `PRESSURE`, `LIGHT` |
| Location & Proximity | `PROXIMITY`, `GPS`-related, Wi-Fi/cell references |
| Device Interaction | `CAMERA`, `NFC`, `BLUETOOTH`, `HEADSET` |
| Health & Activity | `STEP_COUNTER`, `HEART_RATE`, `BODY_TEMPERATURE` |

---

### Permissions Analysis

These scripts extract declared permissions from each app's `AndroidManifest.xml` and classify them by sensitivity level.

#### Step 3.1 — Extract Permissions

```bash
python "src/permissions-urls-and-sensor-analysis/3.1 - permissions_extraction.py"
```

Parses the `AndroidManifest.xml` file in each decompiled app folder using `xml.etree.ElementTree`, extracts all `<uses-permission>` entries, and flags those belonging to Android's dangerous-permission group. Writes per-app results to a JSONL file and a dataset-wide frequency summary.

| Variable | Description |
|---|---|
| `base_directory` | Root directory containing decompiled app folders |
| `jsonl_output_path` | Output path for per-app permission results (JSONL) |
| `summary_output_path` | Output path for the dataset-wide permission summary |

#### Step 3.2 — Classify Permissions by Severity

```bash
python "src/permissions-urls-and-sensor-analysis/3.2 - permissions_severity_classification.py"
```

Reads the extracted permissions from Step 3.1 and classifies them into three severity tiers:

| Severity | Example Permissions |
|---|---|
| High | `READ_SMS`, `RECORD_AUDIO`, `READ_CONTACTS`, `READ_CALL_LOG`, `PROCESS_OUTGOING_CALLS` |
| Medium | `ACCESS_FINE_LOCATION`, `CAMERA`, `READ_EXTERNAL_STORAGE`, `BODY_SENSORS` |
| Low | `INTERNET`, `ACCESS_NETWORK_STATE`, `BLUETOOTH`, `WAKE_LOCK` |

Outputs a severity-annotated JSON file and a distribution bar chart saved as PDF.

| Variable | Description |
|---|---|
| `data_file` | Path to the permissions JSON from Step 3.1 |
| `output_json` | Output path for the severity-classified JSON |
| `output_pdf` | Output path for the permission distribution chart (PDF) |


## IoTFlow

**Prerequisite**: 
- Install [Docker](https://docs.docker.com/engine/install/).
- Clone IoTFlow repository under the `src/iotflow/` folder.

```bash
git clone https://github.com/SecPriv/iotflow.git
cp flowanalysis.py FlowAnalysis/docker/
cp vsa_analysis.py VSA/docker/
```

### Data Flow Analysis
1. `cd FlowAnalysis/docker`
2. Add `apk` files to the folder `apps_to_analyze/`
3. `docker compose up`
4. Results will be placed into `results/`
5. Change the total number of apps, variable `app_num`, in the flow analysis script `flowanalysis.py` according to the final numbers that IoTFlow reverse-engineered
6. Run flow analysis script `python flowanalysis.py`
7. Copy the analysis script output to `/src/iotflow/plot-codes`
8. You can draw the plot with `plot-flowanalysis.ipynb`

### Cryptographic Analysis
1. `cd VSA/docker`
2. Add `apk` files to the folder `apps_to_analyze/`
3. `docker compose up`
4. Results will be placed into `results/`
5. Run cryptographic analysis script `python vsa_analysis.py`
6. Copy the analysis script output to `/src/iotflow/plot-codes`
7. You can draw the plot with `plot-vsa-analysis.ipynb`