#!/usr/bin/env bats
# Unit + mocked-network tests for TheN0thing v10.0 — no real network access.
# Run:  bats tests/unit_tests.bats

setup() {
    load test_helper
    ten_setup_sandbox
    ten_load
    OD="$(make_output_dir "$HOME/scan")"
}

# ─────────────────────────────────────────────────────────────────────────
# gen_permutations  (smart permutation engine)
# ─────────────────────────────────────────────────────────────────────────

@test "gen_permutations: api-dev seeds api-staging / api-test / admin-dev" {
    export RESOLVERS=/nonexistent           # force dig path (no massdns)
    stub_dig_resolves '*'                    # every candidate "resolves"
    printf '%s\n' api-dev.example.com www.example.com admin.example.com \
        > "$OD/assets/subdomains/all.txt"

    gen_permutations example.com "$OD"

    run cat "$OD/temp/perms_resolved.txt"
    [ "$status" -eq 0 ]
    [[ "$output" == *"api-staging.example.com"* ]]
    [[ "$output" == *"api-test.example.com"* ]]
    [[ "$output" == *"admin-dev.example.com"* ]]
}

@test "gen_permutations: honours --perm-limit (PERM_MAX) cap" {
    export RESOLVERS=/nonexistent
    export PERM_MAX=50
    stub_dig_resolves '*'
    printf '%s\n' api-dev.example.com www.example.com admin.example.com \
        beta.example.com prod.example.com > "$OD/assets/subdomains/all.txt"

    gen_permutations example.com "$OD"

    local n; n=$(wc -l < "$OD/temp/perms_resolved.txt")
    [ "$n" -gt 0 ]
    [ "$n" -le 50 ]
}

# ─────────────────────────────────────────────────────────────────────────
# detect_wildcard
# ─────────────────────────────────────────────────────────────────────────

@test "detect_wildcard: returns 0 and records IPs when *.domain resolves" {
    stub_dig_resolves 'wildcardtest-*' '10.10.10.10'
    run detect_wildcard example.com "$OD"
    [ "$status" -eq 0 ]
    [ -s "$OD/temp/wildcard_ips.txt" ]
    grep -q '10.10.10.10' "$OD/temp/wildcard_ips.txt"
}

@test "detect_wildcard: returns 1 and empty file when no wildcard" {
    make_stub dig <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    run detect_wildcard example.com "$OD"
    [ "$status" -eq 1 ]
    [ ! -s "$OD/temp/wildcard_ips.txt" ]
}

# ─────────────────────────────────────────────────────────────────────────
# _safe_jq  (valid / invalid / empty / jq-unavailable)
# ─────────────────────────────────────────────────────────────────────────

@test "_safe_jq: parses valid JSON" {
    printf '{"name":"hello"}' > "$HOME/in.json"
    run _safe_jq "$HOME/out.txt" "$HOME/in.json" -r '.name'
    [ "$status" -eq 0 ]
    [ "$(cat "$HOME/out.txt")" = "hello" ]
}

@test "_safe_jq: invalid JSON fails without crashing" {
    printf 'this is not json {' > "$HOME/in.json"
    run _safe_jq "$HOME/out.txt" "$HOME/in.json" -r '.name'
    [ "$status" -ne 0 ]
    [ ! -s "$HOME/out.txt" ]          # no bogus output written
    echo "shell still alive"          # proves no crash/abort
}

@test "_safe_jq: empty input handled gracefully" {
    : > "$HOME/in.json"
    run _safe_jq "$HOME/out.txt" "$HOME/in.json" -r '.name'
    [ ! -s "$HOME/out.txt" ]
}

@test "_safe_jq: does not crash when jq is unavailable" {
    make_stub jq <<'EOF'
#!/usr/bin/env bash
exit 127
EOF
    printf '{"name":"x"}' > "$HOME/in.json"
    run _safe_jq "$HOME/out.txt" "$HOME/in.json" -r '.name'
    [ "$status" -ne 0 ]
    echo "survived missing jq"
}

# ─────────────────────────────────────────────────────────────────────────
# ENT-aware logic  (_ent_derive)
# ─────────────────────────────────────────────────────────────────────────

@test "_ent_derive: extracts intermediate nodes (blog.dev) from deep host" {
    run _ent_derive api.blog.dev.example.com example.com
    [ "$status" -eq 0 ]
    [[ "$output" == *"blog.dev.example.com"* ]]   # contains the 'blog.dev' ENT
    [[ "$output" == *"dev.example.com"* ]]
}

@test "_ent_derive: single-label host yields no ENTs" {
    run _ent_derive www.example.com example.com
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "_ent_derive: out-of-base host is ignored" {
    run _ent_derive host.other.org example.com
    [ -z "$output" ]
}

# ─────────────────────────────────────────────────────────────────────────
# Format validation
# ─────────────────────────────────────────────────────────────────────────

@test "validate_domain: accepts valid, rejects invalid" {
    run validate_domain example.com;        [ "$status" -eq 0 ]
    run validate_domain sub.example.co.uk;  [ "$status" -eq 0 ]
    run validate_domain "nodot";            [ "$status" -ne 0 ]
    run validate_domain "bad domain.com";   [ "$status" -ne 0 ]
    run validate_domain 'evil;rm.com';      [ "$status" -ne 0 ]
}

# ─────────────────────────────────────────────────────────────────────────
# MOCK: crt.sh response  (function that consumes crt.sh)
# ─────────────────────────────────────────────────────────────────────────

@test "mock crt.sh: _en_crt parses mocked JSON into subdomains" {
    stub_curl_mock
    export STUB_BODY_FILE="$MOCK_DATA/crtsh_response.json"

    _en_crt example.com "$OD/raw"

    [ -f "$OD/raw/crtsh.txt" ]
    grep -q '^www.example.com$'   "$OD/raw/crtsh.txt"
    grep -q '^api.example.com$'   "$OD/raw/crtsh.txt"
    grep -q '^dev.example.com$'   "$OD/raw/crtsh.txt"   # from *.dev.example.com
    ! grep -q '[*]' "$OD/raw/crtsh.txt"                 # wildcards stripped
}

# ─────────────────────────────────────────────────────────────────────────
# MOCK: AXFR  (deterministic zone-transfer parsing, no external NS needed)
# ─────────────────────────────────────────────────────────────────────────

@test "mock AXFR: _proto_axfr extracts hosts from a transferred zone" {
    make_stub dig <<'EOF'
#!/usr/bin/env bash
for a in "$@"; do
  case "$a" in
    NS)   printf 'ns1.example-test.\n'; exit 0 ;;
    AXFR) printf '%s\n' \
            "zonetransfer.me.	7200	IN	SOA	ns1. admin. 1 7200 900 1209600 3600" \
            "cmdexec.zonetransfer.me.	7200	IN	A	1.2.3.4" \
            "asfdbauthdns.zonetransfer.me.	7200	IN	A	1.2.3.5" \
            "www.zonetransfer.me.	7200	IN	CNAME	example.com." ; exit 0 ;;
  esac
done
exit 0
EOF
    _proto_axfr zonetransfer.me "$OD"

    [ -s "$OD/raw/axfr.txt" ]
    grep -q '^cmdexec.zonetransfer.me$'      "$OD/raw/axfr.txt"
    grep -q '^asfdbauthdns.zonetransfer.me$' "$OD/raw/axfr.txt"
}

# ─────────────────────────────────────────────────────────────────────────
# MOCK: ollama  (ai_predict filters unresolved predictions via dig)
# ─────────────────────────────────────────────────────────────────────────

@test "mock ollama: ai_predict keeps resolvable predictions, drops the rest" {
    export DO_AI=true
    export RESOLVERS=/nonexistent
    make_stub ollama <<'EOF'
#!/usr/bin/env bash
printf 'test1\ntest2\nadmin\n'
EOF
    stub_dig_resolves '*test1*' '93.184.216.34'   # only test1.* resolves
    printf '%s\n' www.example.com api.example.com > "$OD/assets/subdomains/all.txt"

    ai_predict example.com "$OD"

    [ -f "$OD/temp/ai_resolved.txt" ]
    grep -q '^test1.example.com$' "$OD/temp/ai_resolved.txt"
    ! grep -q '^test2.example.com$' "$OD/temp/ai_resolved.txt"   # false positive filtered
}

# ─────────────────────────────────────────────────────────────────────────
# Flag parsing  (new v10 flags propagate to globals)
# ─────────────────────────────────────────────────────────────────────────

@test "parse_args: --recursive and --perm-limit set globals" {
    parse_args --recursive --perm-limit 50 example.com
    [ "$DO_RECURSIVE" = true ]
    [ "$PERM_MAX" -eq 50 ]
    [ "$_PARSED_TGT" = example.com ]
}

@test "parse_args: --vhost / --ai / --no-permute / --no-buckets toggle features" {
    parse_args --vhost --ai mymodel --no-permute --no-buckets example.com
    [ "$DO_VHOST" = true ]
    [ "$DO_AI" = true ]
    [ "$AI_MODEL" = mymodel ]
    [ "$DO_PERMUTE" = false ]
    [ "$DO_BUCKETS" = false ]
}

@test "parse_args: --fast marks scan fast (active phase will be skipped)" {
    parse_args --fast example.com
    [ "$_PARSED_FAST" = true ]
}

@test "parse_args: rejects non-numeric --perm-limit" {
    run parse_args --perm-limit abc example.com
    [ "$status" -ne 0 ]
}

# ─────────────────────────────────────────────────────────────────────────
# Batch processing: --file must process EVERY domain
# Regression for the stdin-drain bug (httpx/puredns consumed the target list,
# so only the first domain was scanned).
# ─────────────────────────────────────────────────────────────────────────

@test "batch: --file processes all domains despite stdin-draining tools" {
    stub_all_recon_tools
    # Make httpx behave like the real binary: it drains stdin. Before the fix
    # this swallowed the rest of targets.txt after the first scan.
    make_stub httpx <<'EOF'
#!/bin/sh
cat >/dev/null 2>&1
exit 0
EOF
    printf '%s\n' aaa.com bbb.com ccc.com > "$HOME/targets.txt"

    cd "$HOME"   # contain any output under the sandbox
    run bash "$TARGET_SCRIPT" --file "$HOME/targets.txt" --profile bounty -f -o "$HOME/out"
    [ "$status" -eq 0 ]

    # one output sub-directory per domain == every target was processed
    local n; n=$(find "$HOME/out" -maxdepth 1 -type d -name '*.com' | wc -l)
    [ "$n" -eq 3 ]
}

@test "batch: --file honours -o output directory" {
    stub_all_recon_tools
    printf '%s\n' aaa.com bbb.com > "$HOME/targets.txt"

    cd "$HOME"   # contain any output under the sandbox
    run bash "$TARGET_SCRIPT" --file "$HOME/targets.txt" -f -o "$HOME/custom_out"
    [ "$status" -eq 0 ]
    [ -d "$HOME/custom_out" ]
    [ ! -d "$HOME/output" ]      # did NOT fall back to output/multi_*
}

# ─────────────────────────────────────────────────────────────────────────
# Screenshots
# ─────────────────────────────────────────────────────────────────────────

@test "screenshots: captures images for live URLs and reports count" {
    # fake gowitness that drops a jpeg into --screenshot-path
    make_stub gowitness <<'EOF'
#!/usr/bin/env bash
path="./screenshots"
while [ $# -gt 0 ]; do
  case "$1" in --screenshot-path) path="$2"; shift 2 ;; *) shift ;; esac
done
mkdir -p "$path"; printf 'JPEG' > "$path/https---example.com-443.jpeg"; exit 0
EOF
    printf 'https://example.com\n' > "$OD/processed/all_urls.txt"

    run screenshots "$OD"
    [ "$status" -eq 0 ]
    [[ "$output" == *"captured 1 image"* ]]
    [ -n "$(find "$OD/screenshots" -name '*.jpeg' 2>/dev/null)" ]
}

@test "screenshots: skips cleanly when there are no live URLs" {
    : > "$OD/processed/all_urls.txt"
    run screenshots "$OD"
    [ "$status" -eq 0 ]
    [[ "$output" == *"no live URLs"* ]]
}

# ─────────────────────────────────────────────────────────────────────────
# Engineering: _ptimeout
# ─────────────────────────────────────────────────────────────────────────

@test "_ptimeout: kills an overrunning command and returns 124" {
    run _ptimeout 1 sleep 8
    [ "$status" -eq 124 ]
}

@test "_ptimeout: passes through the child's exit code" {
    run _ptimeout 5 sh -c 'exit 3'
    [ "$status" -eq 3 ]
}
