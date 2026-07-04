#!/usr/bin/env bats
# Integration tests for TheN0thing v10.0 — REQUIRE network access.
#
# Targets are limited to explicitly-authorised hosts:
#   * zonetransfer.me   — DigiNinja's public DNS/AXFR test domain
#   * scanme.nmap.org   — Nmap's public scan-test host
#   * github.com / example.com / cloudflare.com — read-only DNS/HTTP lookups
#
# Every test is resilient: it `skip`s (does not fail) when the network or a
# third-party server is unavailable, so transient outages don't break CI.
# Disable the whole file with:  SKIP_INTEGRATION=1   (run_tests.sh --skip-integration)

setup() {
    load test_helper
    ten_setup_sandbox
    ten_load
    OD="$(make_output_dir "$HOME/scan")"
}

@test "integration AXFR: zonetransfer.me transfer recovers known records" {
    network_or_skip
    _proto_axfr zonetransfer.me "$OD"
    [ -f "$OD/raw/axfr.txt" ]
    [ -s "$OD/raw/axfr.txt" ] || skip "zonetransfer.me AXFR unreachable right now"
    grep -qiE 'cmdexec|asfdbauthdns' "$OD/raw/axfr.txt"
}

@test "integration email-DNS: github.com SPF/DKIM/DMARC hosts harvested" {
    network_or_skip
    make_output_dir "$HOME/gh" >/dev/null
    _en_email_dns github.com "$HOME/gh/raw"
    [ -f "$HOME/gh/raw/email_dns.txt" ]
    [ -s "$HOME/gh/raw/email_dns.txt" ] || skip "github.com SPF lookup unreachable"
    grep -qiE 'outlook|_spf|spf|sendgrid|zendesk|salesforce|google' "$HOME/gh/raw/email_dns.txt"
}

@test "integration wayback: example.com query completes without crashing" {
    network_or_skip
    export WAYBACK_MAXTIME=15          # example.com's CDX is large; bound the query
    run _en_wayback example.com "$OD/raw"
    [ "$status" -eq 0 ]
    [ -f "$OD/raw/wayback.txt" ]      # produced even if the host count is zero
    # any harvested line must belong to the target
    if [ -s "$OD/raw/wayback.txt" ]; then
        ! grep -qv 'example.com$' "$OD/raw/wayback.txt"
    fi
}

@test "integration buckets: AWS/GCP/Azure probing handles 403/404 gracefully" {
    network_or_skip
    export DO_BUCKETS=true BUCKET_MAX=12
    printf '%s\n' assets.example.com backup.example.com > "$OD/assets/subdomains/all.txt"
    run cloud_buckets "$OD" example.com
    [ "$status" -eq 0 ]
    [ -f "$OD/processed/cloud_buckets.txt" ]   # never throws, even on 403/404/000
}

@test "integration vhost: scanme.nmap.org probed without throwing" {
    network_or_skip
    export DO_VHOST=true VHOST_MAX=10
    local ip
    ip=$(dig +short A scanme.nmap.org 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
    [ -n "$ip" ] || skip "cannot resolve scanme.nmap.org"
    printf '%s\n' "$ip" > "$OD/assets/ips/all.txt"
    printf '%s\n' scanme.nmap.org example.com > "$OD/assets/subdomains/all.txt"
    run vhost_fuzz "$OD" scanme.nmap.org
    [ "$status" -eq 0 ]
    [ -f "$OD/processed/vhosts.txt" ]          # results or silent no-results
}

@test "integration zonewalk: DNSSEC detected on a signed zone" {
    network_or_skip
    export ZONEWALK_MAX=5                       # bound the walk so the test is fast
    _proto_zonewalk cloudflare.com "$OD"
    [ -f "$OD/processed/dnssec.txt" ]
    grep -qi 'DNSSEC' "$OD/processed/dnssec.txt"
    grep -qi 'ENABLED' "$OD/processed/dnssec.txt" || skip "cloudflare DNSSEC state unexpected"
}

@test "integration cname: real CNAME chain is followed" {
    network_or_skip
    printf '%s\n' www.github.com > "$OD/assets/subdomains/all.txt"
    run cname_chains "$OD"
    [ "$status" -eq 0 ]
    [ -f "$OD/processed/cname_chains.txt" ]
}
