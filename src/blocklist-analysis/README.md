# Blocklist Analysis

Scans URLs referenced by the (abandoned) IoT companion apps against category
blocklists — ads, malware, spyware, phishing, spam, tracking, scams, and
"suspicious" — to flag domains that are known to be risky. This corresponds
to the **Embedded Resource Analysis** section of the top-level project
README.

## Contents

```
blocklist-analysis/
├── url_analysis.py             # main scanner (Firebog-style category blocklists)
├── url_domains_extractor.py    # merges per-batch URL files -> urls_merged.json (see below)
├── blocklists/                 # category blocklists (domain lists, JSON arrays)
├── urls/urls_merged.json       # input: app -> [urls] mapping, full corpus (tracked via Git LFS)
├── results/                    # includes a full reference run (results.csv, via Git LFS)
└── malicious-checks/           # supplementary checks against public sources (OISD, URLhaus, ad-network list)
```

## Requirements

Python 3.9+ and:

```bash
pip install tldextract tqdm
```

(everything else the main scanner uses — `json`, `csv`, `argparse`,
`concurrent.futures`, etc. — is standard library.)

## Input data

The scanner reads app → URL mappings from a JSON file matched by
`--input-glob` (default `urls/urls_merged.json`), shaped like:

```json
{
  "com.example.app": ["http://example.com/foo", "tracker.example.net"],
  "com.other.app": ["..."]
}
```

`urls_merged.json` is the full corpus: 61,500 apps, 8,566,646 URLs.

**Tracked via Git LFS**, not a regular git blob — at ~514MB it's well over
GitHub's per-file limit for normal blobs, and it's raw extracted data
rather than something derivable from anything else in this repo
(regenerating it means redecompiling and re-scanning all 61,500 APKs).
Make sure you have [Git LFS](https://git-lfs.com/) installed
(`git lfs install`, once per machine) *before* cloning, or run
`git lfs pull` after cloning if you already have a checkout — otherwise
you'll get a small text pointer file instead of the real data.

`results/results.csv` (the full scan output, one row per URL, also via
Git LFS) is a completed reference run over the same `urls_merged.json` —
1.6GB, 8,566,646 rows. It's also fully regenerable without it: just run
`url_analysis.py` against `urls_merged.json` and `blocklists/` (both free,
no paid API), which takes roughly 6-8 hours with `--workers 24`.
`results/results_summary_per_app.csv` (a small per-app rollup, see below)
is a normal (non-LFS) git blob.

`urls_merged.json` was originally produced across 5 separate batch files
(`urls_part1_merged.json` … `urls_part5_merged.json`, outputs of the
URL-extraction pipeline in
[`src/permissions-urls-and-sensor-analysis/`](../permissions-urls-and-sensor-analysis)).
Merging those batches is a trivial union of `app -> [urls]` dicts, so only
the single merged result is kept here — the batch files aren't shipped.
`url_domains_extractor.py` is the merge utility (`merge_json_files()`
reads every `*.json` file in a directory and unions their URL lists per
app); it also does a bit more, extracting per-app unique registered domains
and IPs from the merged data
(`results/unique_app_domains*.json`) — that part is optional and not
required for `url_analysis.py` itself. Run it from inside
`blocklist-analysis/` (`python url_domains_extractor.py`); it points at
`urls/` and will populate `results/unique_app_domains*.json`. If you have
the 5 batch files and want to reconstruct `urls_merged.json` from them
directly, point `apps_urls` at the directory containing them.

## Blocklists

`BLOCKLIST_MAP` in `url_analysis.py` expects these files under
`blocklists/` (each a flat JSON array of domain/host strings) — all 13 are
present:

| Category | Files |
|---|---|
| ads | `ads.json` (200,543 entries) |
| malware | `malware.json`, `hijack.json` |
| spyware | `spyware.json` (551 entries) |
| phishing | `phishing.json` (920,545 entries) |
| spam | `spam.json` (2,833 entries) |
| tracking | `tracking-telemetry.json` |
| scams | `scams.json` (468,729 entries) |
| shocksites | `shocksites.json` (181 entries) |
| suspicious | `suspicious.json`, `fb_blacklist.json`, `mvps_hosts.json`, `neo_hosts.json` |

## Running it

```bash
python url_analysis.py \
  --workers 24 \
  --checkpoint-every 1000 \
  --blocklist-dir blocklists \
  --input-glob urls/urls_merged.json \
  --output-dir results_repro \
  --resume            # optional, to continue from a checkpoint
```

These are also the script's defaults (`--output-dir` defaults to
`results/` — use a different one as above if you don't want to overwrite
the included reference run, see below). The script prompts for
confirmation (`Proceed to scan... (y/n)`, and again for `--resume`) before
it starts — this is expected behavior, not an error.

At roughly 55-60 URLs/sec/worker, scanning the full 8.56M-URL corpus takes
about 6-8 hours with `--workers 24` on typical hardware. On Python 3.12+
you may see a `datetime.utcnow() is deprecated` warning; it doesn't affect
the output.

## Output

Written to `--output-dir` (default `results/`, created if missing):

- `results_checkpoint.jsonl` — per-URL results, appended incrementally (used for `--resume`)
- `results.json` / `results.csv` — final aggregated results
- `summary.json` / `summary.csv` — counts by category + top offending domains per category
- `scanner.log` — run log

### Reference run (included)

`results/` contains a full prior run to compare against:

- `results.csv` (via Git LFS) — the complete output this scanner produces
  (8,566,646 rows, one per URL in `urls_merged.json`).
- `results_summary_per_app.csv` — a per-app rollup (one row per app, with
  per-category match counts) derived from `results.csv`. This isn't
  produced by `url_analysis.py` itself (which only emits a global
  `summary.csv`, not a per-app one) — it's a downstream aggregation used
  later to join with permissions/CVE data elsewhere in the project. No
  script for it is included here, but it's a simple groupby (by `app`,
  counting matches per `category`) if you need to regenerate it.

There's no `results.json`, `results_checkpoint.jsonl`, or `summary.json`
included for this reference run — only the two CSVs above survived.

## `malicious-checks/` — supplementary checks

A separate, complementary set of checks against public sources other than
the Firebog-style lists above, all operating on the same
`urls/urls_merged.json`:

- **`check_oisd_blocklist.py`** — checks each app's domains against the
  [OISD](https://oisd.nl/) "big" blocklist. `oisd_basic.txt` and
  `oisd_domains.json` (a pre-parsed cache) are included, so no download is
  needed to rerun it, though the script will re-fetch from
  `https://big.oisd.nl/domainswild` if `oisd_domains.json` is deleted.
  Run from inside `malicious-checks/`; writes `results/blocked_domains.json`
  and `results/oisd_blocked_summary.csv`.
- **`url-haus-malicious-url-detector.py`** — checks domains/IPs against
  `data/urlhauze.txt`, a snapshot of the
  [URLhaus](https://urlhaus.abuse.ch/) malicious URL feed (included).
  Writes `results/apps_with_malicious_urls.json`.
- **`allchecks.py`** — combines an ad-network host list (fetched live from
  `pgl.yoyo.org`) with the local URLhaus list above. It also has
  (currently commented out in `main()`) Google Safe Browsing and
  VirusTotal lookups. Writes `results/vulnerability_checks.csv`.

All three read `../urls/urls_merged.json` and expect to be run with
`malicious-checks/` as the working directory, e.g.:

```bash
cd malicious-checks
python check_oisd_blocklist.py
python url-haus-malicious-url-detector.py
python allchecks.py
```

`check_oisd_blocklist.py` and `url-haus-malicious-url-detector.py` run
against purely local/cached data and complete in seconds. `allchecks.py`'s
ad-network + URLhaus checks (the only ones enabled by default) run in
roughly the same time; only the optional Google Safe Browsing / VirusTotal
lookups below are rate-limited.

### Using the optional Google Safe Browsing / VirusTotal lookups

`allchecks.py` has Google Safe Browsing and VirusTotal lookups built in,
commented out in `main()` by default. To enable them, get your own API
keys and set them as environment variables (never hardcode a key in the
script itself):

```bash
export GOOGLE_SAFE_BROWSING_API_KEY="..."
export VIRUSTOTAL_API_KEY="..."
```

then uncomment the relevant blocks in `allchecks.py`'s `main()`. To obtain
keys:

- **Google Safe Browsing API**: follow Google's setup guide at
  https://developers.google.com/safe-browsing/v4/get-started to create a
  project and generate an API key.
- **VirusTotal API**: create a free account at
  [virustotal.com](https://www.virustotal.com/) and find your API key at
  https://www.virustotal.com/gui/my-apikey (see
  https://docs.virustotal.com/ for full API documentation and rate limits).
