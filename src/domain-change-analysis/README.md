# Domain Ownership Change Analysis

Checks whether domains referenced by (abandoned) IoT companion apps appear
to have changed ownership since the app was published — a signal that an
app may be pointing at a domain that's since been re-registered, parked, or
seized. This corresponds to the **At-Risk Domain Analysis** section of the
top-level project README.

**Default path: use the curated results already in `results/` — no API key
needed.** `results/whois_history_cache_simplified.json` (the input to every
stage from `ownership_change_analysis.py` onward) is checked in, so you can
go straight there without fetching anything yourself. Only get your own
WhoisXMLAPI key (stage 1) if you want to fetch fresh WHOIS history or
extend the dataset to more domains.

**Not checked in:** `results/whois_history_cache.json` (raw WHOIS history,
~305MB) and `results/whois_history_results.json` (~81MB) are excluded from
git — both are far over GitHub's size limits, and neither is needed to
reproduce any reported result. `whois_history_cache.json` is read only by
`simplify_dataset.py` (stage 2), whose *output* — `whois_history_cache_simplified.json`
— is already here; `whois_history_results.json` isn't read by any script in
this pipeline at all. The only thing their absence costs you is the ability
to re-derive the simplified cache yourself instead of trusting the included
one — everything downstream of it (the actual ownership-change scoring/
validation) is unaffected and needs no WhoisXMLAPI credits.

**Verified:** stages 2-4 (`simplify_dataset.py` → `ownership_change_analysis.py`
→ `convert_results_to_csv.py`) were rerun from scratch, starting only from
`whois_history_cache.json` (before it was excluded here), in an isolated
copy of this directory, and produced byte-for-byte identical output to
every file checked into `results/`. `verifiable_domains.py` and
`diagnosis.py` were also run end-to-end without errors. `analysis_v2.py`
had a real bug — see below — which is now fixed and verified.

## Pipeline

1. `whois_api_client.py` — fetches historical WHOIS records for a set of
   hostnames via the WhoisXMLAPI *WHOIS History* API and caches them.
   → `results/whois_history_cache.json`
2. `simplify_dataset.py` — reduces each domain's full WHOIS history down to
   just its first and last record in a date window.
   → `results/whois_history_cache_simplified.json`
3. `ownership_change_analysis.py` — compares each domain's first vs. last
   record and scores the likelihood of an ownership change, validated
   against a ground-truth subset (domains with non-redacted registrant
   org/email/name).
   → `results/validation_results*.json`
4. `convert_results_to_csv.py` — converts the ground-truth results to CSV
   for spreadsheet review / the plotting script below.
   → `results/validation_results_ground_truth.csv`

Optional deeper analysis, all built on the outputs above:

- `verifiable_domains.py` — a stricter, PII-quality-aware re-derivation of
  ground truth (separate from step 3's simpler logic), with its own
  verifiable/non-verifiable breakdown.
- `diagnosis.py` — analyzes false negatives/positives and score
  distributions from `validation_results.json` to help pick a threshold.
- `analysis_v2.py` / `analysis.ipynb` — statistics and publication-ready
  plots from `results/validation_results_ground_truth.csv`.

## Contents

```
domain-change-analysis/
├── whois_api_client.py                          # stage 1: fetch + cache WHOIS history
├── simplify_dataset.py                          # stage 2: reduce to first/last record per domain
├── ownership_change_analysis.py                 # stage 3: score/validate ownership changes
├── convert_results_to_csv.py                    # stage 4: ground truth JSON -> CSV
├── verifiable_domains.py                        # optional: stricter ground-truth re-derivation
├── diagnosis.py                                 # optional: false negative/positive + threshold analysis
├── analysis_v2.py / analysis.ipynb              # optional: stats + plots
├── data/
│   ├── sampled_urls_4_domain_analysis.csv       # sampling iteration 1 (1000 hostnames)
│   ├── sampled_urls_4_domain_analysis-II.csv    # sampling iteration 2 (1000 hostnames)
│   ├── sampled_urls_4_domain_analysis-III.csv   # sampling iteration 3 (500 hostnames) — the one whois_api_client.py reads
│   └── sampled_urls_4_domain_analysis_stats.md  # log of how the samples were drawn
└── results/
    ├── whois_history_results.json               # stage 1 output (NOT in git, ~81MB — see note above)
    ├── whois_history_results_summary.csv        # stage 1 output
    ├── whois_history_cache.json                 # stage 1 output (NOT in git, ~305MB — see note above)
    ├── whois_history_cache_simplified.json      # stage 2 output / stage 3 input
    ├── validation_results.json                  # stage 3 output
    ├── validation_results_ground_truth.json     # stage 3 output
    ├── validation_results_ground_truth.csv      # stage 4 output
    ├── validation_results_predictions.json      # stage 3 output
    └── apps_with_changed_domain_ownership_contact.md  # final deliverable, see below
```

## Requirements

```bash
pip install pandas python-whois requests tldextract matplotlib seaborn numpy
```

(`pandas`/`matplotlib`/`seaborn`/`numpy` are only needed for `analysis_v2.py`
/ `analysis.ipynb`; the core pipeline needs `python-whois`, `requests`,
`tldextract`. `whois` import in `whois_api_client.py` comes from the
`python-whois` package, not `whois` on PyPI.)

## Stage 1 — `whois_api_client.py` (optional — curated cache already included)

**Note:** the CLI argument parsing at the bottom of `main()` is commented
out — all inputs are hardcoded in `main()` and must be edited directly:

```python
api_key = ""                                                  # see below
csv_file = "data/sampled_urls_4_domain_analysis-III.csv"      # present, see below
max_domains = 300
delay = 0.5
output_file = 'results/whois_history_results.json'
cache_file = 'results/whois_history_cache.json'
```

- **`data/sampled_urls_4_domain_analysis-III.csv`** is present (500
  hostnames, columns `rank, hostname, frequency, num_top_apps_using,
  sample_url, first_app`) — this is the file the script actually reads,
  and the only column it uses is `hostname` (`hostname_column='hostname'`);
  every other column (`frequency`, `num_top_apps_using`, `sample_url`,
  `first_app`, and the app risk score used to pick which apps to sample
  from in the first place) is just provenance metadata that no script in
  this pipeline reads or depends on. Per
  `data/sampled_urls_4_domain_analysis_stats.md`, this file (and the two
  earlier iterations `sampled_urls_4_domain_analysis.csv` / `-II.csv`) was
  produced by a separate sampling script not included in this repo, using a
  risk-scored-apps CSV and a benign-URL frequency table that also aren't
  included — but since neither of those actually feeds into any analysis
  script here (they only shaped *which* 500 hostnames got sampled), their
  absence has no effect on reproducing anything downstream of this CSV.
  Treat this file as the starting point: it's just a list of hostnames.
- **`api_key`** is blank on purpose — this is a paid API
  (`whois-history.whoisxmlapi.com`). **You don't need one to use this
  project**: `results/whois_history_cache_simplified.json` already contains
  the reduced fetched data for the included sample, so stages 2–4 and the
  optional analyses run as-is with no key at all. Only get your own key if
  you want to fetch WHOIS history for additional domains, refresh the
  existing ones, or regenerate the (git-excluded) raw
  `whois_history_cache.json` / `whois_history_results.json` yourself — see
  WhoisXMLAPI's docs for making requests:
  https://whois-history.whoisxmlapi.com/api/documentation/making-requests.
  Do not hardcode a real key in this file if you ever share/commit it —
  `whois_api_client.py` also skips any domain already in `cache_file`, so a
  fresh key only needs to cover new domains.

## Stage 2 — `simplify_dataset.py`

```python
input_file = "results/whois_history_cache.json"
output_file = "results/whois_history_cache_simplified.json"
start_date = "2024-01-01"
end_date = "2026-01-05"
```

For each domain, picks the first WHOIS record on/after `start_date` and the
last on/before `end_date`, and records the span between them in years. Both
input and output are already present in `results/`, so rerunning this is
only necessary if you've fetched new/updated WHOIS history in stage 1 or
want a different date window.

## Stage 3 — `ownership_change_analysis.py`

```python
input_file = "results/whois_history_cache_simplified.json"
output_file = "results/validation_results.json"
threshold = 0.5
```

Runs as-is against the included `whois_history_cache_simplified.json` (737
domains). Compares each domain's first vs. last record: ground truth comes
from non-redacted registrant org/email/name (when available), and the
GDPR-safe prediction score is built from reseller, registration service
provider, nameserver category/hash, registrar, state, DNSSEC, and country
changes.

Prints a validation summary to stdout (accuracy/precision/recall/F1,
overall and by ground-truth confidence level) and writes
`results/validation_results.json`,
`results/validation_results_ground_truth.json`, and
`results/validation_results_predictions.json` (all already present from a
prior run; rerunning overwrites them).

## Stage 4 — `convert_results_to_csv.py`

```python
json_input = "results/validation_results_ground_truth.json"
csv_output = "results/validation_results_ground_truth.csv"
```

Simple JSON→CSV conversion of the ground-truth records (for spreadsheet
review, and as the input to `analysis_v2.py`). Output already present;
rerun after a fresh stage 3 run to keep it in sync.

## Optional: `verifiable_domains.py`

A separate, stricter pass at ground truth: instead of `ownership_change_analysis.py`'s
simple org/email/name comparison, it scores each record's PII quality
(organization, email domain, name, address fields, phone) into
high/medium/low/insufficient confidence, keeps only domains with
comparable, sufficiently confident PII in both first and last records, and
determines ownership change from that filtered subset. Reads
`results/whois_history_cache_simplified.json`; writes
`results/verified_domains.json`, `results/verified_analysis.json`, and
`results/verified_verification_status.json`. This is a different
methodology from stage 3, not a dependency of it — useful for
cross-checking how sensitive the ownership-change conclusions are to how
strictly "verifiable" is defined.

## Optional: `diagnosis.py`

Reads `results/validation_results.json` and prints:
false-negative case-by-case detail (which GDPR features changed/didn't for
missed ownership changes), true-positive detail, score distributions for
changed vs. unchanged domains, and a sweep over thresholds (0.1–0.5) to
suggest the F1-optimal one. No file outputs — stdout only. Useful before
adjusting `threshold` in stage 3.

## Optional: `analysis_v2.py` / `analysis.ipynb`

```python
csv_file = "results/validation_results_ground_truth.csv"
output_dir = "results/analysis_output"
```

Loads the stage 4 CSV and produces summary statistics, TLD-level change
rates, temporal (years-span) breakdowns, and publication-quality plots
(saved under `results/analysis_output/`, created automatically), plus a
`summary_statistics.json`. `analysis.ipynb` is the notebook version of the
same analysis. Requires `pandas`, `matplotlib`, `seaborn`, `numpy`.

**Bug fixed:** the script generated all 8 plots correctly but crashed on
its very last step — writing `summary_statistics.json` — because some
values in the summary dict are numpy `int64`/`float64` (from pandas
`.value_counts()`/`.groupby()`) and one nested dict has tuple keys (from
`df.groupby(['confidence', 'changed'])`), neither of which `json.dump()`
can serialize. Added a recursive sanitizer (`json_safe()`) that converts
numpy scalars to native Python types and stringifies non-string dict keys
before dumping. Verified: reran end-to-end, all 8 plots plus a valid
`summary_statistics.json` are now produced.

## `results/apps_with_changed_domain_ownership_contact.md`

This is the final deliverable of the whole pipeline: a plain stdout dump
(`print()` output pasted into Markdown, not real Markdown) listing the
2,154 apps (3.50% of the 61,500-app corpus) whose domains were flagged as
having changed ownership. It cross-references stage 3's
predictions/ground truth against the app→domain mapping — but the script
that does that join isn't included, only its printed output. If you need
this regenerated after a rerun of stage 3, you'll need to write that join
yourself: for each app, look up whether any of its domains appear with
`changed: true` in `validation_results_ground_truth.json` /
`validation_results_predictions.json`.
