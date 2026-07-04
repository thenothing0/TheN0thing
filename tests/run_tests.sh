#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# TheN0thing v10.0 — unified test runner
#
#   ./tests/run_tests.sh                     # unit + integration
#   ./tests/run_tests.sh --skip-integration  # unit (mocked) only — offline/CI-fast
#   ./tests/run_tests.sh --unit-only         # alias for --skip-integration
#   ./tests/run_tests.sh --help
#
# Produces:  tests/reports/report.xml        (JUnit, for CI)
#            tests/reports/test_report.log
# ──────────────────────────────────────────────────────────────────────────
set -u

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="$TESTS_DIR/reports"
TMP_DIR="$TESTS_DIR/tmp"

C_G=$'\033[0;32m'; C_R=$'\033[0;31m'; C_Y=$'\033[1;33m'; C_0=$'\033[0m'
[[ -t 1 ]] || { C_G=""; C_R=""; C_Y=""; C_0=""; }

RUN_INTEGRATION=true
for arg in "$@"; do
    case "$arg" in
        --skip-integration|--unit-only) RUN_INTEGRATION=false ;;
        -h|--help) grep -E '^#( |$)' "$0" | sed -E 's/^# ?//'; exit 0 ;;
        *) printf '%sUnknown option: %s%s\n' "$C_R" "$arg" "$C_0" >&2; exit 2 ;;
    esac
done

# 1. bats present?
if ! command -v bats >/dev/null 2>&1; then
    cat >&2 <<EOF
${C_R}bats (Bash Automated Testing System) is not installed.${C_0}

Install it with ONE of:
  sudo apt-get update && sudo apt-get install -y bats        # Debian/Ubuntu
  brew install bats-core                                      # macOS
  npm install -g bats                                         # any platform
  git clone https://github.com/bats-core/bats-core && \\
      sudo ./bats-core/install.sh /usr/local                 # from source

Also required:  jq, dig (dnsutils / bind-utils), curl
EOF
    exit 127
fi

# 2. Dummy/empty API keys — never spend real quota during tests.
export VT_API_KEY="" SHODAN_KEY="" CENSYS_API_ID="" CENSYS_API_SECRET="" \
       SECURITYTRAILS_KEY="" GITHUB_TOKEN="" CHAOS_KEY="" GITLAB_TOKEN=""
[[ "$RUN_INTEGRATION" == true ]] || export SKIP_INTEGRATION=1

# 3. Fresh report/temp dirs.
rm -rf "$TMP_DIR" "$REPORT_DIR"
mkdir -p "$TMP_DIR" "$REPORT_DIR"

# Offline suites first (unit + attack-surface analysis), then integration.
FILES=("$TESTS_DIR/unit_tests.bats" "$TESTS_DIR/analysis_tests.bats")
[[ "$RUN_INTEGRATION" == true ]] && FILES+=("$TESTS_DIR/integration_tests.bats")

printf '%s== TheN0thing test-suite ==%s\n' "$C_Y" "$C_0"
printf 'bats        : %s (%s)\n' "$(command -v bats)" "$(bats --version 2>/dev/null)"
printf 'integration : %s\n\n' "$RUN_INTEGRATION"

# 4. Run: JUnit report for CI + a plain log; pretty output to the console.
rc=0
if bats --report-formatter junit --output "$REPORT_DIR" "${FILES[@]}" \
        2>&1 | tee "$REPORT_DIR/test_report.log"; then
    rc=0
else
    rc=${PIPESTATUS[0]}
fi

# 5. Clean up scratch space (no temp files left behind).
rm -rf "$TMP_DIR"

echo
if [[ "$rc" -eq 0 ]]; then
    printf '%sALL TESTS PASSED%s — report: %s\n' "$C_G" "$C_0" "$REPORT_DIR/report.xml"
else
    printf '%sTESTS FAILED (rc=%s)%s — see %s\n' "$C_R" "$rc" "$C_0" "$REPORT_DIR/test_report.log"
fi
exit "$rc"
