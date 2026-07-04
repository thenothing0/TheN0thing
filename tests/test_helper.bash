#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# Shared helpers for the TheN0thing bats test-suite.
#
# Design notes
#  * The suite SOURCES TheN0thing.sh to test its functions in isolation. This
#    is only possible because the script guards execution with
#        if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then main "$@"; fi
#    so sourcing loads the functions without launching a scan.
#  * Every test runs in a hermetic sandbox: HOME, TMPDIR and a stub-bin dir all
#    live under the per-test BATS temp dir, so no config/log/cache/temp files
#    ever touch the real system or the repo root.
#  * External commands (curl, dig, ollama, …) are mocked with PATH-based stub
#    executables — NOT shell functions — because several functions spawn
#    `xargs sh -c '…'` subprocesses that do not inherit shell functions.
# ──────────────────────────────────────────────────────────────────────────

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
TARGET_SCRIPT="$PROJECT_ROOT/TheN0thing.sh"
MOCK_DATA="$TESTS_DIR/mock_data"

# Per-test sandbox: isolated HOME + TMPDIR + stub bin, all under BATS temp.
ten_setup_sandbox() {
    local box="${BATS_TEST_TMPDIR:-$TESTS_DIR/tmp/$$.$RANDOM}"
    mkdir -p "$box"
    export HOME="$box/home";    mkdir -p "$HOME"
    export TMPDIR="$box/tmp";   mkdir -p "$TMPDIR"
    export STUB_BIN="$box/bin"; mkdir -p "$STUB_BIN"
    export PATH="$STUB_BIN:$PATH"
    # Empty/dummy API keys so key-gated sources never burn real quota.
    export VT_API_KEY="" SHODAN_KEY="" CENSYS_API_ID="" CENSYS_API_SECRET=""
    export SECURITYTRAILS_KEY="" GITHUB_TOKEN="" CHAOS_KEY=""
}

# Source TheN0thing.sh (functions only). The script installs its EXIT/INT/TERM
# traps only when executed directly, so sourcing leaves the bats traps intact
# (which `skip` relies on). Relax the strict shell options the script enables so
# the bats harness stays stable.
ten_load() {
    # shellcheck disable=SC1090
    source "$TARGET_SCRIPT"
    set +e +u +o pipefail
}

# Create an executable stub on PATH; its body is read from stdin.
#   make_stub dig <<'EOF'
#   #!/usr/bin/env bash
#   echo 1.2.3.4
#   EOF
make_stub() {
    local name="$1"
    cat > "$STUB_BIN/$name"
    chmod +x "$STUB_BIN/$name"
}

# A dig stub that prints an A record only for names matching $1 (ERE), nothing
# otherwise. Used to simulate selective resolution / wildcard presence.
stub_dig_resolves() {
    local pattern="$1" ip="${2:-93.184.216.34}"
    make_stub dig <<EOF
#!/usr/bin/env bash
# crude dig stub — resolves names matching: $pattern
args="\$*"
case "\$args" in
    *" A "*|*" A"|"A "*)
        for a in "\$@"; do
            case "\$a" in
                $pattern) printf '%s\n' "$ip"; exit 0 ;;
            esac
        done ;;
esac
exit 0
EOF
}

# A curl stub: emits \$STUB_HTTP_CODE when -w is requested (bucket/vhost probes),
# otherwise the contents of \$STUB_BODY_FILE (API/CDX responses).
stub_curl_mock() {
    make_stub curl <<'EOF'
#!/usr/bin/env bash
want_code=0
for a in "$@"; do [ "$a" = "-w" ] && want_code=1; done
if [ "$want_code" = 1 ]; then printf '%s' "${STUB_HTTP_CODE:-000}"; exit 0; fi
if [ -n "${STUB_BODY_FILE:-}" ] && [ -f "$STUB_BODY_FILE" ]; then cat "$STUB_BODY_FILE"; fi
exit 0
EOF
}

# Minimal output-dir skeleton expected by the active/cloud/protocol functions.
make_output_dir() {
    local od="$1"
    mkdir -p "$od"/{raw,processed,temp,reports} \
             "$od"/assets/{subdomains,ips,asns,cidrs}
    : > "$od/assets/subdomains/all.txt"
    : > "$od/assets/ips/all.txt"
    printf '%s' "$od"
}

# Write empty-output stubs for the whole external recon toolchain so a full
# `TheN0thing.sh` run completes offline in seconds (used by flag tests).
stub_all_recon_tools() {
    local t
    for t in subfinder amass assetfinder findomain chaos github-subdomains \
             rapiddns-cli puredns massdns naabu nuclei gospider subjack dnsx \
             mapcidr asnmap webanalyze whatweb wafw00f gowitness aquatone \
             httpx curl dig whois sqlite3; do
        printf '#!/bin/sh\nexit 0\n' > "$STUB_BIN/$t"
        chmod +x "$STUB_BIN/$t"
    done
}

# Skip the calling test when there is no outbound network (keeps integration
# tests from failing in air-gapped CI).
network_or_skip() {
    if [ -n "${SKIP_INTEGRATION:-}" ]; then skip "integration disabled (SKIP_INTEGRATION)"; fi
    if ! command -v dig >/dev/null 2>&1; then skip "dig not available"; fi
    if ! timeout 8 dig +short +time=3 +tries=1 a.root-servers.net >/dev/null 2>&1; then
        skip "no network connectivity"
    fi
}
