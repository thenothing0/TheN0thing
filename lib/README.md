# TheN0thing — Attack-Surface Platform (`lib/`)

This directory turns TheN0thing from a discovery tool into an
**external attack-surface assessment platform**:

```
Discovery ─▶ Analysis ─▶ Findings ─▶ Prioritization ─▶ Reporting
(TheN0thing.sh)         (lib/ modules + Findings Engine)   (lib/report)
```

The main `TheN0thing.sh` still owns **Discovery** (subdomains, DNS, httpx,
nuclei, buckets, …) exactly as before. `lib/` adds a new **Analysis phase**
(phase 7) that runs after discovery: every module inspects the discovery output
and emits **structured findings** into a central **Findings Engine**, which
deduplicates, scores, correlates and renders a severity-ranked report.

## Layout

```
lib/
├── findings/
│   ├── engine.sh        # Findings Engine: fe_emit / fe_ingest / fe_stats
│   └── SCHEMA.md        # the finding object contract
├── core/
│   └── probe.sh         # shared engines: probe_paths, fetch_scan, scan_body
├── data/                # rulesets & catalogs (space-delimited, regex = remainder)
│   ├── exposure_paths.txt
│   ├── api_paths.txt
│   ├── content_common.txt
│   ├── vendor_paths.txt  # edge devices / K8s / Docker / CI-CD
│   └── secrets.txt
├── modules/             # one file per capability; each defines mod_<name>(od,tgt,tt)
│   ├── normalize.sh     # existing outputs (buckets/takeover/axfr/vhosts) -> findings
│   │  ── Tier-1 ──
│   ├── exposure.sh      # .git/.env/actuator/jenkins/tomcat/elasticsearch/…
│   ├── secrets.sh       # HTML/JS credential scanning
│   ├── jsanalysis.sh    # sourcemaps, internal hosts, endpoints
│   ├── apidiscovery.sh  # swagger/openapi/graphql + field-suggestion probe
│   ├── contentbrute.sh  # curated paths (+ optional ffuf)
│   ├── identity.sh      # Entra/Okta/ADFS/Google/SAML/OIDC
│   ├── vulnprio.sh      # nuclei -> EPSS + CISA KEV -> prioritized queue
│   ├── origin.sh        # CDN/WAF origin discovery (DNS history + Host probe)
│   ├── tls.sh           # cert/protocol posture (openssl)
│   ├── wayback_intel.sh # historical URLs/params/JS + live sensitive files
│   ├── emailsec.sh      # SPF/DMARC/DKIM/MTA-STS/BIMI/DNSSEC posture
│   │  ── Tier-2 ──
│   ├── vendor.sh        # Exchange/Citrix/F5/Fortinet/Pulse/PaloAlto + K8s/Docker/CI-CD
│   ├── gfpatterns.sh    # applies ~/.gf (GF_PATH) templates over the URL corpus
│   ├── firebase.sh      # open Firebase Realtime Database detection
│   ├── netintel.sh      # reverse-DNS expansion + IPv6 discovery
│   ├── breach.sh        # HudsonRock infostealer/breach correlation (keyless)
│   ├── pkgintel.sh      # npm/PyPI dependency-confusion / typosquat
│   ├── githubdork.sh    # GitHub code-search dorks (needs GITHUB_TOKEN)
│   ├── postman.sh       # public Postman workspace intelligence
│   └── mobile.sh        # Play Store app discovery + APK scan (apkleaks/apktool)
├── analysis.sh          # run_analysis(): orchestrates modules + engine + report
└── report/
    └── render.sh        # severity-ranked HTML / Markdown / JSON reports
```

## The module contract

A module is a shell function `mod_<name> <output_dir> <target> <target_type>`
that reads discovery output and **only** emits findings — it never prints
findings to the console. It emits via the Findings Engine:

```bash
fe_emit <module> <category> <severity> <confidence> <asset> <title> \
        <description> [evidence_json] [remediation] [refs_csv] [tags_csv]
```

`severity ∈ {critical,high,medium,low,info}`,
`confidence ∈ {confirmed,firm,tentative}`.

To add a new capability: drop a `mod_<name>` into `lib/modules/`, add one line
to `run_analysis` in `lib/analysis.sh`, and (usually) a ruleset in `lib/data/`.
Most HTTP modules are just `probe_paths` over a data file; most content modules
are `fetch_scan`/`scan_body` over a regex catalog — so new modules stay tiny.

## Shared engines (why modules are small)

- **`probe_paths <module> <bases_file> <rules_file>`** — baseline-calibrated
  path probing with body confirmation (kills soft-404s). Powers exposure, API
  discovery, content brute, identity.
- **`fetch_scan` / `scan_body`** — fetch a body and run a regex catalog. Powers
  secrets and JS analysis.

Ruleset format (space-delimited so the regex — which contains `|`,`^`,… — is the
safe line remainder):

```
# probe_paths:  <severity> <category> <codes> <title_underscored> <path> [body_regex...]
critical exposure 200 Git_config_exposed /.git/config \[core\]|repositoryformatversion
# scan_body:    <name_underscored> <severity> <category> <ere_regex...>
AWS_Access_Key critical secret AKIA[0-9A-Z]{16}
```

## Findings Engine outputs

```
<output_dir>/findings/
├── raw/<module>.jsonl   # per-module emitted findings (append-only)
├── findings.json        # deduped, merged, severity-ranked array
├── findings.jsonl       # same, one per line
└── stats.json           # totals, by_severity/category/asset, risk_score, risk_rating
<output_dir>/reports/
├── findings.json        # composed machine report (meta+stats+findings)
├── findings.md          # Markdown report
└── findings.html        # professional dark-theme, severity-ranked report
```

Deduplication key: `sha1(asset | category | title)`. On collision the highest
severity/confidence wins; evidence, references, tags and detection methods are
merged and an `occurrences` count is kept.

Risk score = weighted sum (critical 40 / high 10 / medium 4 / low 1), capped at
100, mapped to a rating.

## Backward compatibility

`lib/` is sourced by `TheN0thing.sh` only if present; the analysis phase
self-guards on `run_analysis` being defined and on `DO_ANALYSIS` / scan mode.
Removing `lib/` returns the tool to pure-discovery behaviour. Existing CLI,
output files and reports are unchanged; the findings layer is additive.

Toggle: `--no-analysis`. Skipped automatically in `--fast` and `--profile
passive`. Env caps: `EXPOSURE_MAX_HOSTS`, `API_MAX_HOSTS`, `CONTENT_MAX_HOSTS`,
`VENDOR_MAX_HOSTS`, `TLS_MAX_HOSTS`, `SECRETS_MAX_URLS`, `ORIGIN_MAX_IPS`,
`FIREBASE_MAX`, `NETINTEL_MAX_IPS`, `NETINTEL_MAX_SUBS`, `WAYBACK_LIMIT`,
`ANALYSIS_SKIP_WAYBACK`, `CONTENT_WORDLIST` (enables ffuf),
`GF_PATH` (gf templates dir, default `~/.gf`), `BREACH_ENABLE`.

**Detection-aware probing:** `probe_paths` backs off on HTTP 429/503 and aborts
a host after `PROBE_MAX_BLOCKS` (default 6) rate-limit responses; set
`PROBE_DELAY` (seconds) for polite pacing between requests.
