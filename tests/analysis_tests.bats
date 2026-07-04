#!/usr/bin/env bats
# Tests for the v11 attack-surface platform: Findings Engine + analysis modules.
# Deterministic / offline (external commands stubbed). Run:
#   bats tests/analysis_tests.bats

setup() {
    load test_helper
    ten_setup_sandbox
    ten_load                         # sources TheN0thing.sh -> loads lib/*
    OD="$(make_output_dir "$HOME/scan")"
    mkdir -p "$OD/temp"
    declare -F fe_init >/dev/null || skip "lib not loaded"
    fe_init "$OD"
}

# ── Findings Engine ────────────────────────────────────────────────────────

@test "engine: fe_emit dedups by (asset,category,title) keeping highest severity" {
    fe_emit m exposure high firm a.com ".git exposed" d '{"x":1}'
    fe_emit m exposure critical confirmed a.com ".git exposed" d '{"y":2}'
    fe_emit m tls medium firm b.com "weak tls" d '{}'
    fe_ingest "$OD"
    [ "$(jq 'length' "$OD/findings/findings.json")" -eq 2 ]
    run jq -r '.[] | select(.title==".git exposed") | "\(.severity) \(.occurrences)"' "$OD/findings/findings.json"
    [ "$output" = "critical 2" ]
}

@test "engine: fe_stats computes weighted risk score + rating" {
    fe_emit m exposure critical confirmed a.com t1 d
    fe_emit m tls medium firm b.com t2 d
    fe_ingest "$OD"; fe_stats "$OD"
    [ "$(jq -r '.by_severity.critical' "$OD/findings/stats.json")" -eq 1 ]
    [ "$(jq -r '.risk_score' "$OD/findings/stats.json")" -eq 44 ]   # 40 + 4
    [ "$(jq -r '.risk_rating' "$OD/findings/stats.json")" = "critical" ]
}

@test "engine: evidence JSON is preserved verbatim (no stray-brace corruption)" {
    fe_emit m exposure info firm a.com t "desc" '{"url":"https://a.com/x","status":200}'
    fe_ingest "$OD"
    [ "$(jq -r '.[0].evidence.status' "$OD/findings/findings.json")" -eq 200 ]
}

# ── scan_body (secret catalog) ─────────────────────────────────────────────

@test "secrets: scan_body flags an AWS key and redacts it in evidence" {
    printf 'var k="AKIAIOSFODNN7EXAMPLE"; ok\n' > "$HOME/app.js"
    scan_body secrets "https://a.com/app.js" "$HOME/app.js" "$TN_LIB_DIR/data/secrets.txt"
    fe_ingest "$OD"
    run jq -r '.[] | select(.category=="secret") | .title' "$OD/findings/findings.json"
    [[ "$output" == *"AWS Access Key"* ]]
    # full secret must NOT be stored verbatim
    ! grep -q 'AKIAIOSFODNN7EXAMPLE' "$OD/findings/findings.json"
}

# ── normalize (existing outputs -> findings) ───────────────────────────────

@test "normalize: open bucket + AXFR become findings" {
    printf 'OPEN   s3    https://s3.amazonaws.com/acme-assets/\n' > "$OD/processed/cloud_buckets.txt"
    printf 'ns1.acme.com\nmail.acme.com\n' > "$OD/raw/axfr.txt"
    mod_normalize "$OD" acme.com domain
    fe_ingest "$OD"
    run jq -r '[.[].category] | sort | unique | join(",")' "$OD/findings/findings.json"
    [[ "$output" == *"cloud"* && "$output" == *"dns"* ]]
    [ "$(jq -r '.[] | select(.tags|index("axfr")) | .severity' "$OD/findings/findings.json")" = "high" ]
}

# ── emailsec (stubbed dig) ─────────────────────────────────────────────────

@test "emailsec: missing SPF/DMARC/DNSSEC produce findings" {
    make_stub dig <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    mod_emailsec "$OD" acme.com domain
    fe_ingest "$OD"
    run jq -r '[.[] | select(.detection_method=="emailsec") | .title] | join("|")' "$OD/findings/findings.json"
    [[ "$output" == *"SPF record missing"* ]]
    [[ "$output" == *"DMARC record missing"* ]]
    [[ "$output" == *"DNSSEC not enabled"* ]]
}

# ── vulnprio (stubbed KEV + EPSS) ──────────────────────────────────────────

@test "vulnprio: KEV CVE is escalated to critical and tagged exploited" {
    printf '[CVE-2021-44228] [http] [medium] https://a.com/api\n' > "$OD/processed/nuclei_results.txt"
    make_stub curl <<'EOF'
#!/usr/bin/env bash
out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; http*|https*) url="$1"; shift;; *) shift;; esac; done
[ -z "$url" ] && url="$out"
case "$url" in
  *known_exploited*) body='{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}';;
  *epss*)            body='{"data":[{"epss":"0.97","percentile":"0.99"}]}';;
  *)                 body='';;
esac
if [ -n "$out" ]; then printf '%s' "$body" > "$out"; else printf '%s' "$body"; fi
exit 0
EOF
    mod_vulnprio "$OD"
    fe_ingest "$OD"
    run jq -r '.[] | select(.category=="vuln") | "\(.severity) \(.tags|join(","))"' "$OD/findings/findings.json"
    [[ "$output" == critical* ]]
    [[ "$output" == *"kev"* ]]
}

# ── report renderer ────────────────────────────────────────────────────────

@test "report: render_findings_report emits html + md + json" {
    fe_emit m exposure critical confirmed a.com ".env exposed" "leak" '{"url":"https://a.com/.env"}'
    fe_ingest "$OD"; fe_stats "$OD"
    render_findings_report "$OD" acme.com domain
    [ -s "$OD/reports/findings.html" ]
    [ -s "$OD/reports/findings.md" ]
    [ -s "$OD/reports/findings.json" ]
    grep -q '.env exposed' "$OD/reports/findings.html"
    grep -q 'risk' "$OD/reports/findings.md"
    jq -e '.findings|length>=1' "$OD/reports/findings.json" >/dev/null
}

# ── Tier-2 modules ─────────────────────────────────────────────────────────

@test "gfpatterns: applies gf templates from GF_PATH to the URL corpus" {
    mkdir -p "$HOME/gf"
    printf '{"flags":"-iE","patterns":["id=","cmd="]}' > "$HOME/gf/sqli.json"
    printf '{"flags":"-iE","patterns":["cmd=","exec="]}' > "$HOME/gf/rce.json"
    export GF_PATH="$HOME/gf"
    printf 'https://x.com/p?id=1\nhttps://x.com/e?cmd=ls\nhttps://x.com/ok\n' > "$OD/processed/all_urls.txt"
    mod_gfpatterns "$OD"
    fe_ingest "$OD"
    run jq -r '[.[]|select(.category=="vuln-indicator")|.evidence.match]|sort|unique|join(",")' "$OD/findings/findings.json"
    [[ "$output" == *"id="* ]]
    [[ "$output" == *"cmd="* ]]
    [ "$(jq -r '.[0].confidence' "$OD/findings/findings.json")" = "tentative" ]
}

@test "vendor: Docker registry catalog is flagged critical" {
    make_stub curl <<'EOF'
#!/bin/sh
out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; -w) shift 2;; http*|https*) url="$1"; shift;; *) shift;; esac; done
case "$url" in
  *_catalog*) [ -n "$out" ] && printf '{"repositories":["app"]}' > "$out"; printf '200 24'; exit 0;;
  *)          [ -n "$out" ] && : > "$out"; printf '404 0'; exit 0;;
esac
EOF
    printf 'https://reg.acme.com/\n' > "$OD/processed/all_urls.txt"
    mod_vendor "$OD"
    fe_ingest "$OD"
    run jq -r '.[] | select(.tags|index("vendor")) | "\(.severity) \(.title)"' "$OD/findings/findings.json"
    [[ "$output" == *"critical"* ]]
    [[ "$output" == *"Docker registry"* ]]
}

@test "firebase: open Realtime Database is flagged critical" {
    make_stub curl <<'EOF'
#!/bin/sh
out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; -w) shift 2;; http*|https*) url="$1"; shift;; *) shift;; esac; done
case "$url" in
  *.json) [ -n "$out" ] && printf '{"users":{"1":{"email":"a@b.c"}}}' > "$out"; printf '200'; exit 0;;
  *)      [ -n "$out" ] && : > "$out"; printf '404'; exit 0;;
esac
EOF
    printf 'acme.firebaseio.com\n' > "$OD/assets/subdomains/all.txt"
    mod_firebase "$OD" acme.com domain
    fe_ingest "$OD"
    run jq -r '.[] | select(.category=="cloud" and (.tags|index("firebase"))) | .severity' "$OD/findings/findings.json"
    [ "$output" = "critical" ]
}

@test "breach: HudsonRock infected-employee count escalates to critical" {
    make_stub curl <<'EOF'
#!/bin/sh
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; *) shift;; esac; done
[ -n "$out" ] && printf '{"employees":3,"users":10,"total":13}' > "$out"
exit 0
EOF
    mod_breach "$OD" acme.com domain
    fe_ingest "$OD"
    run jq -r '.[] | select(.category=="breach") | "\(.severity) \(.evidence.employees)"' "$OD/findings/findings.json"
    [ "$output" = "critical 3" ]
}

@test "netintel: IPv6 discovery emits a finding (stubbed dig)" {
    make_stub dig <<'EOF'
#!/bin/sh
case " $* " in *" AAAA "*) echo "2606:2800:220:1:248:1893:25c8:1946";; *) : ;; esac
exit 0
EOF
    printf 'www.acme.com\n' > "$OD/assets/subdomains/all.txt"
    : > "$OD/assets/ips/all.txt"
    mod_netintel "$OD" acme.com domain
    fe_ingest "$OD"
    run jq -r '.[] | select(.tags|index("ipv6")) | .title' "$OD/findings/findings.json"
    [[ "$output" == *"IPv6"* ]]
}

@test "pkgintel: unclaimed scoped npm package is a dependency-confusion finding" {
    make_stub curl <<'EOF'
#!/bin/sh
case " $* " in *" -w "*) printf '404';; esac
exit 0
EOF
    mod_pkgintel "$OD" acme.com domain
    fe_ingest "$OD"
    run jq -r '.[] | select(.category=="supplychain") | "\(.severity) \(.asset)"' "$OD/findings/findings.json"
    [[ "$output" == *"npm:@acme/"* ]]
    [[ "$output" == medium* ]]
}

@test "githubdork: code-search hits produce a leak finding" {
    export GITHUB_TOKEN=ghp_dummy GHDORK_DELAY=0
    make_stub curl <<'EOF'
#!/bin/sh
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; *) shift;; esac; done
[ -n "$out" ] && printf '{"total_count":3,"items":[{"html_url":"https://github.com/x/y"}]}' > "$out"
exit 0
EOF
    mod_githubdork "$OD" acme.com domain
    fe_ingest "$OD"
    run jq -r '[.[] | select(.tags|index("github"))] | length' "$OD/findings/findings.json"
    [ "$output" -ge 1 ]
}

@test "postman: public workspace referencing target is flagged" {
    make_stub curl <<'EOF'
#!/bin/sh
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; *) shift;; esac; done
[ -n "$out" ] && printf '{"data":[{"name":"acme prod api","url":"https://api.acme.com"}]}' > "$out"
exit 0
EOF
    mod_postman "$OD" acme.com domain
    fe_ingest "$OD"
    run jq -r '.[] | select(.tags|index("postman")) | .title' "$OD/findings/findings.json"
    [[ "$output" == *"Postman"* ]]
}

@test "mobile: Play Store listing for the brand becomes app intel" {
    make_stub curl <<'EOF'
#!/bin/sh
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; *) shift;; esac; done
[ -n "$out" ] && printf 'x id=com.acme.app y id=com.other.thing z' > "$out"
exit 0
EOF
    mod_mobile "$OD" acme.com domain
    fe_ingest "$OD"
    run jq -r '[.[] | select(.category=="mobile") | .asset] | join(",")' "$OD/findings/findings.json"
    [[ "$output" == *"play:com.acme.app"* ]]
    [[ "$output" != *"com.other.thing"* ]]
}

# ── run_analysis smoke (stubbed network) ───────────────────────────────────

@test "run_analysis: full phase runs and produces a valid findings report" {
    make_stub dig <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    make_stub curl <<'EOF'
#!/usr/bin/env bash
out=""; for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
[ -n "$out" ] && : > "$out"
# emit an http code if -w was requested
case " $* " in *" -w "*) printf '000';; esac
exit 0
EOF
    printf 'https://acme.com/\n' > "$OD/processed/all_urls.txt"
    printf 'OPEN   s3    https://s3.amazonaws.com/acme-x/\n' > "$OD/processed/cloud_buckets.txt"
    run run_analysis "$OD" acme.com domain
    [ "$status" -eq 0 ]
    jq -e 'type=="array"' "$OD/findings/findings.json" >/dev/null
    [ -s "$OD/reports/findings.html" ]
    jq -e '.total>=1' "$OD/findings/stats.json" >/dev/null
}
