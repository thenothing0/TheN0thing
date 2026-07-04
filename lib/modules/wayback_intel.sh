#!/usr/bin/env bash
# Module: wayback_intel — mine the Wayback CDX for historical URLs, parameters,
# archived JS and legacy files; feed the crawl pipeline and flag archived
# sensitive files that are STILL live today.
mod_wayback_intel() {
    local od="$1" tgt="$2" tt="$3"
    [[ "$tt" == domain ]] || return 0
    command -v curl >/dev/null 2>&1 || return 0
    local dom="$tgt" t; t=$(_mktmp wbi) || return 0
    local enc; enc=$(_url_encode "*.$dom/*")
    _ptimeout $(( ${WAYBACK_MAXTIME:-60} + 20 )) curl -fsS --max-time "${WAYBACK_MAXTIME:-60}" \
        --max-filesize "$MAX_RESPONSE_SIZE" \
        "http://web.archive.org/cdx/search/cdx?url=${enc}&output=text&fl=original&collapse=urlkey&limit=${WAYBACK_LIMIT:-30000}" \
        > "$t" 2>/dev/null || true
    [[ -s "$t" ]] || { rm -f "$t"; log "INFO" "[wayback] no archived URLs (skipped)"; return 0; }

    grep -oiE 'https?://[^ ]+' "$t" | sort -u > "$od/processed/wayback_urls.txt"
    grep -E '\?[a-zA-Z0-9_]+=' "$od/processed/wayback_urls.txt" 2>/dev/null | sort -u > "$od/processed/wayback_params.txt"
    # archived JS joins the JS-analysis input
    grep -iE '\.js([?#]|$)' "$od/processed/wayback_urls.txt" 2>/dev/null >> "$od/processed/js_urls.txt"
    sort -u "$od/processed/js_urls.txt" -o "$od/processed/js_urls.txt" 2>/dev/null || true
    log "SUCCESS" "[wayback] $(wc -l < "$od/processed/wayback_urls.txt") URLs, $(_safe_count "$od/processed/wayback_params.txt" 2>/dev/null || echo 0) parameterised"

    # historical sensitive files — probe whether they are still served
    local interesting; interesting=$(_mktmp wbint) || { rm -f "$t"; return 0; }
    grep -iE '\.(sql|bak|old|backup|conf|config|ini|env|log|zip|tgz|gz|tar|yml|yaml|json|xml|pem|key|p12|pfx|swp|git)([?#]|$)' \
        "$od/processed/wayback_urls.txt" 2>/dev/null | \
        grep -iE "(^|[/.])$(_escape_ere "$dom")" | sort -u | head -n "${WAYBACK_PROBE:-60}" > "$interesting"
    local u code sev
    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        code=$(curl -sk -A "$_PR_UA" --max-time 8 -o /dev/null -w '%{http_code}' "$u" 2>/dev/null)
        if [[ "$code" == 200 ]]; then
            sev=medium
            grep -iqE '\.(sql|env|key|pem|p12|pfx|bak|backup|conf|config)([?#]|$)' <<<"$u" && sev=high
            fe_emit wayback wayback "$sev" firm "$u" "Archived sensitive file still live" \
                "A historically-archived sensitive file is still accessible today (HTTP 200)" \
                "$(jq -nc --arg u "$u" '{url:$u,source:"wayback"}')" \
                "Remove the file from the web root / restrict access" "" "wayback,legacy,exposure"
        fi
    done < "$interesting"
    rm -f "$t" "$interesting"
    return 0
}
