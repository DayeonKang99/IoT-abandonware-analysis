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
├── urls/                        # urls_merged.json goes here — NOT in git, see below
├── results/                    # small reference outputs only — results.csv NOT in git, see below
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

**Not checked in — download it separately.** At ~514MB it's well over
GitHub's per-file limit, and it's raw extracted data rather than something
derivable from anything else in this repo (regenerating it means
redecompiling and re-scanning all 61,500 APKs). Download it from this
repo's [Releases page](<RELEASE_URL>) and place it at `urls/urls_merged.json`.

`results/results.csv` (the full scan output, one row per URL) is likewise
excluded — at 1.6GB it's even larger, but unlike `urls_merged.json` it's
fully regenerable: just run `url_analysis.py` against `urls_merged.json`
and `blocklists/` (both free, no paid API), which takes roughly 6-8 hours
with `--workers 24`. `results/results_summary_per_app.csv` (a small
per-app rollup, see below) is kept in git as a lightweight reference.

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
`blocklist-analysis/` (`python url_domains_extractor.py`); it already
points at `urls/` and will re-merge/re-write `urls_merged.json` (a no-op
merge of the single file, harmless) and populate `results/unique_app_domains*.json`.
**Tested:** ran end-to-end against a 200-app slice — completed cleanly and
produced all four expected output files. If you're given the 5 batch files
again and want to reconstruct `urls_merged.json` from them instead, point
`apps_urls` at the directory containing them.

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
the reference run already there, see below). The script will interactively
prompt `Proceed to scan... (y/n)` (and again for `--resume`) before it
starts — that's a manual confirmation left in by the original author for
large runs, not a bug.

**Tested:** ran end-to-end against a 200-app slice of `urls_merged.json`
(16,805 URLs) with the real blocklists — completed cleanly and produced a
`results.csv` in the schema documented under Output below. At ~55-60
URLs/sec/worker, the full 8.56M-URL corpus should take roughly 6-8 hours
with `--workers 24` on typical hardware. You'll also see a harmless
`datetime.utcnow() is deprecated` warning on Python 3.12+; it doesn't
affect the output.

## Output

Written to `--output-dir` (default `results/`, created if missing):

- `results_checkpoint.jsonl` — per-URL results, appended incrementally (used for `--resume`)
- `results.json` / `results.csv` — final aggregated results
- `summary.json` / `summary.csv` — counts by category + top offending domains per category
- `scanner.log` — run log

### Reference run

A full prior run exists (8,566,646 rows, one per URL in `urls_merged.json`)
but its `results.csv` (1.6GB) is **not checked in** — see
[Input data](#input-data) above for why, and how to regenerate it yourself
(~6-8 hours, no paid API needed).

What *is* checked in from that run:

- `results/results_summary_per_app.csv` — a per-app rollup (one row per
  app, with per-category match counts) derived from `results.csv`. This
  isn't produced by `url_analysis.py` itself (which only emits a global
  `summary.csv`, not a per-app one) — it's a downstream aggregation used
  later to join with permissions/CVE data elsewhere in the project. No
  script for it is included here, but it's a simple groupby (by `app`,
  counting matches per `category`) if you need to regenerate it from your
  own `results.csv`.

There's no `results.json`, `results_checkpoint.jsonl`, or `summary.json`
included from that run — only `results_summary_per_app.csv` survived here.

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

**Tested:** ran all three end-to-end against a 200-app slice —
`check_oisd_blocklist.py` and `url-haus-malicious-url-detector.py`
completed in seconds. `allchecks.py` originally had a `time.sleep(1)`
after *every* URL's URLhaus check even though that check is a pure local
set lookup with nothing to rate-limit — at 1 URL/sec that made even this
200-app slice's ~7,260 unique URLs a ~2-hour run, and the full corpus would
have taken months. Removed that sleep (rate limiting still applies to the
commented-out VirusTotal/GSB calls, which are genuinely rate-limited APIs);
the slice now finishes in ~4 seconds.

### API keys — do not hardcode them

`allchecks.py` reads `GOOGLE_SAFE_BROWSING_API_KEY` and
`VIRUSTOTAL_API_KEY` from the environment (they default to empty, and the
GSB/VT lookups are commented out in `main()` regardless — only the
ad-network + URLhaus checks run by default). **A previous copy of this
file had two live keys hardcoded** (a Google Safe Browsing key and a
VirusTotal key) — they've been removed here, but if those keys were ever
committed or shared anywhere else, treat them as compromised and rotate
them in the Google Cloud / VirusTotal consoles. To use these lookups,
export your own keys instead:

```bash
export GOOGLE_SAFE_BROWSING_API_KEY="..."
export VIRUSTOTAL_API_KEY="..."
```

and uncomment the relevant blocks in `allchecks.py`'s `main()`.
