#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════
# TheN0thing — Shared Probe Engine  (sourced by TheN0thing.sh)
#
# Two reusable engines that most analysis modules are built on, so the modules
# themselves stay small (data + a few module-specific rules):
#
#   probe_paths  — baseline-calibrated path probing with body confirmation.
#                  Powers: exposure, api-discovery, identity, content-brute.
#   fetch_scan   — fetch a body and run a regex catalog over it.
#                  Powers: secrets, js-analysis.
#
# Both emit into the Findings Engine (fe_emit); they never print findings.
# Reuses core helpers when present: _ptimeout, _mktmp, _url_encode, log,
# MAX_RESPONSE_SIZE, RATE_LIMIT. Degrades gracefully standalone (tests).
# ══════════════════════════════════════════════════════════════════════════

_PR_UA="${_PR_UA:-Mozilla/5.0 (X11; Linux x86_64) TheN0thing/10.x}"
: "${MAX_RESPONSE_SIZE:=10485760}"

# Fallbacks when sourced without the main script (unit tests may still load it).
declare -F _mktmp     >/dev/null 2>&1 || _mktmp() { mktemp "${TMPDIR:-/tmp}/${1:-t}.XXXXXX" 2>/dev/null; }
declare -F _ptimeout  >/dev/null 2>&1 || _ptimeout() { local s="$1"; shift; timeout "$s" "$@" 2>/dev/null; }
declare -F log        >/dev/null 2>&1 || log() { printf '%s [%s] %s\n' "$(date +%H:%M:%S)" "$1" "$2" >&2; }

# _pr_fetch <url> <body_out> [max_time]  -> prints "<status> <size>" (or "000 0")
# One capped, insecure-tolerant GET. Body written to body_out (truncated to cap).
_pr_fetch() {
    local url="$1" body_out="$2" mt="${3:-12}"
    curl -sk -L --max-redirs 3 -A "$_PR_UA" \
        --max-time "$mt" --max-filesize "$MAX_RESPONSE_SIZE" \
        -o "$body_out" -w '%{http_code} %{size_download}' "$url" 2>/dev/null || printf '000 0'
}

# _pr_snippet <body_file> [n]  -> first n printable chars on one line (evidence)
_pr_snippet() {
    head -c "${2:-200}" "$1" 2>/dev/null | tr -d '\000' | tr '\n\r\t' '   ' | \
        LC_ALL=C tr -cd '[:print:]' | cut -c1-"${2:-200}"
}

# _probe_paths_worker <module> <base> <rules_file>
# One worker per base URL. Calibrates a soft-404 baseline, then evaluates each
# rule (TSV: path<TAB>severity<TAB>category<TAB>title<TAB>status_set<TAB>body_regex).
_probe_paths_worker() {
    local module="$1" base="$2" rules="$3"
    base="${base%/}"
    [[ "$base" =~ ^https?:// ]] || base="https://$base"
    local bl bbody; bbody=$(_mktmp prbl) || return 0
    local rand="zzz-notexist-$$-${RANDOM}"
    bl=$(_pr_fetch "$base/$rand" "$bbody" 10)
    local bstatus="${bl%% *}" bsize="${bl##* }"
    rm -f "$bbody"
    # Catch-all detection: server 200s (or 3xx) on a random path.
    local catchall=false
    case "$bstatus" in 200|301|302|401) catchall=true ;; esac

    local body; body=$(_mktmp prbody) || return 0
    # Rule line format (space-delimited; regex is the remainder so it may contain
    # spaces / | / ^ safely):  <severity> <category> <codes> <title_> <path> [regex...]
    # title_ uses underscores for spaces. codes is a comma-set e.g. 200 or 200,403.
    local sev cat codes title path rx blocks=0
    while read -r sev cat codes title path rx; do
        [[ -z "$sev" || "$sev" == \#* ]] && continue
        title="${title//_/ }"
        local r; r=$(_pr_fetch "${base}${path}" "$body" 12)
        local status="${r%% *}" size="${r##* }"
        # detection-aware back-off: slow down on rate-limit/WAF, abort if persistent
        case "$status" in
            429|503)
                ((blocks++))
                if (( blocks >= ${PROBE_MAX_BLOCKS:-6} )); then
                    log "WARNING" "[$module] $base rate-limiting/WAF (HTTP $status) — backing off"
                    break
                fi
                sleep "$blocks" 2>/dev/null || true; : > "$body"; continue ;;
        esac
        [[ "${PROBE_DELAY:-0}" != 0 ]] && sleep "$PROBE_DELAY" 2>/dev/null || true
        # status must be in the rule's accepted set
        [[ ",$codes," == *",$status,"* ]] || { : > "$body"; continue; }
        local confidence="firm" ok=true
        if [[ -n "$rx" ]]; then
            # body confirmation required — strongest signal, kills soft-404s
            if grep -qiE -- "$rx" "$body" 2>/dev/null; then confidence="confirmed"
            else ok=false; fi
        elif [[ "$catchall" == true && "$size" == "$bsize" ]]; then
            # 200 with identical size to the soft-404 baseline => almost certainly noise
            ok=false
        else
            confidence="tentative"
        fi
        [[ "$ok" == true ]] || { : > "$body"; continue; }
        local snip; snip=$(_pr_snippet "$body" 180)
        [[ "$status" =~ ^[0-9]+$ ]] || status=0
        [[ "$size" =~ ^[0-9]+$ ]] || size=0
        local ev; ev=$(jq -nc --arg u "${base}${path}" --argjson s "$status" \
            --argjson z "$size" --arg snip "$snip" \
            '{url:$u,status:$s,size:$z,snippet:$snip}')
        fe_emit "$module" "$cat" "$sev" "$confidence" "${base}${path}" \
            "$title" "$title at ${base}${path} (HTTP $status)" "$ev" \
            "" "" "$cat"
        : > "$body"
    done < "$rules"
    rm -f "$body"
}

# probe_paths <module> <bases_file> <rules_file> [max_bases]
# Probe every rule against every base URL (capped), in parallel across bases.
probe_paths() {
    local module="$1" bases="$2" rules="$3" maxb="${4:-200}"
    [[ -s "$bases" && -s "$rules" ]] || return 0
    command -v curl >/dev/null 2>&1 || { log "WARNING" "[$module] curl missing"; return 0; }
    local list; list=$(_mktmp prlist) || return 0
    grep -E '^[a-zA-Z0-9]' "$bases" | sort -u | head -n "$maxb" > "$list"
    local n; n=$(wc -l < "$list" 2>/dev/null); n="${n//[[:space:]]/}"
    log "INFO" "[$module] probing $n host(s)"
    if declare -F run_par >/dev/null 2>&1; then
        local -a jobs=(); local b
        while IFS= read -r b; do
            [[ -z "$b" ]] && continue
            jobs+=(_probe_paths_worker "$module" "$b" "$rules" "${_SEP:-__PSEP__}")
        done < "$list"
        (( ${#jobs[@]} )) && run_par "${jobs[@]}"
    else
        local b; while IFS= read -r b; do
            [[ -z "$b" ]] && continue
            _probe_paths_worker "$module" "$b" "$rules"
        done < "$list"
    fi
    rm -f "$list"
}

# ──────────────────────────────────────────────────────────────────────────
# fetch_scan — download bodies and run a regex catalog over them.
# Catalog format (TSV): name<TAB>severity<TAB>category<TAB>pcre_regex
# ──────────────────────────────────────────────────────────────────────────

# scan_body <module> <asset> <body_file> <catalog_file>
# Run every regex in the catalog over one body; emit a finding per match.
scan_body() {
    local module="$1" asset="$2" body="$3" catalog="$4"
    [[ -s "$body" && -s "$catalog" ]] || return 0
    # Catalog line format (space-delimited; regex is remainder):
    #   <name_underscored> <severity> <category> <pcre_regex...>
    local name sev cat rx m
    while read -r name sev cat rx; do
        [[ -z "$name" || "$name" == \#* ]] && continue
        name="${name//_/ }"
        m=$(grep -aoE -- "$rx" "$body" 2>/dev/null | head -1)
        [[ -z "$m" ]] && continue
        # redact the middle of the match in evidence (don't store full secrets)
        local red="${m:0:6}…${m: -4}"; (( ${#m} <= 12 )) && red="$m"
        local ev; ev=$(jq -nc --arg a "$asset" --arg n "$name" --arg m "$red" \
            '{asset:$a,pattern:$n,match:$m}')
        fe_emit "$module" "$cat" "$sev" "firm" "$asset" \
            "$name exposed" "Pattern '$name' matched in $asset" "$ev" \
            "Rotate/revoke the credential and remove it from client-served content" \
            "" "$cat"
    done < "$catalog"
    return 0
}

# fetch_scan <module> <urls_file> <catalog_file> [max_urls]
# Fetch each URL and scan its body with the regex catalog.
fetch_scan() {
    local module="$1" urls="$2" catalog="$3" maxu="${4:-300}"
    [[ -s "$urls" && -s "$catalog" ]] || return 0
    command -v curl >/dev/null 2>&1 || return 0
    local list; list=$(_mktmp fslist) || return 0
    grep -E '^https?://' "$urls" | sort -u | head -n "$maxu" > "$list"
    local u body
    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        body=$(_mktmp fsbody) || continue
        _pr_fetch "$u" "$body" 12 >/dev/null
        [[ -s "$body" ]] && scan_body "$module" "$u" "$body" "$catalog"
        rm -f "$body"
    done < "$list"
    rm -f "$list"
}
