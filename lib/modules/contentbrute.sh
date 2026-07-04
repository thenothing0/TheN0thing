#!/usr/bin/env bash
# Module: contentbrute — directory/file discovery. Uses the curated ruleset via
# the shared probe engine, and accelerates with ffuf when the operator supplies
# a wordlist (CONTENT_WORDLIST=/path). Discovered URLs feed the pipeline.
mod_contentbrute() {
    local od="$1"
    local urls="$od/processed/all_urls.txt"
    [[ -s "$urls" ]] || { log "INFO" "[content] no live URLs (skipped)"; return 0; }
    if [[ -n "${CONTENT_WORDLIST:-}" && -f "$CONTENT_WORDLIST" ]] && command -v ffuf >/dev/null 2>&1; then
        _content_ffuf "$od" "$urls" "$CONTENT_WORDLIST"
    fi
    local rules="$TN_LIB_DIR/data/content_common.txt"
    [[ -f "$rules" ]] && probe_paths content "$urls" "$rules" "${CONTENT_MAX_HOSTS:-80}"
}

_content_ffuf() {
    local od="$1" urls="$2" wl="$3"
    local host out code u
    log "INFO" "[content] ffuf with $(basename "$wl")"
    head -n "${CONTENT_FFUF_HOSTS:-15}" "$urls" | while IFS= read -r host; do
        host="${host%/}"
        out=$(_mktmp ffuf) || continue
        _ptimeout 300 ffuf -u "${host}/FUZZ" -w "$wl" \
            -mc 200,204,301,302,307,401,403 -ac -t 40 -of json -o "$out" -s 2>/dev/null || true
        if [[ -s "$out" ]]; then
            jq -r '.results[]? | "\(.status) \(.url)"' "$out" 2>/dev/null | while read -r code u; do
                [[ -z "$u" ]] && continue
                printf '%s\n' "$u" >> "$od/processed/content_found.txt"
                fe_emit content content low firm "$u" "Content discovered (ffuf)" \
                    "Path resolved via content brute-force (HTTP $code)" \
                    "$(jq -nc --arg u "$u" --arg c "$code" '{url:$u,status:($c|tonumber? // 0)}')" \
                    "" "" "content,ffuf"
            done
        fi
        rm -f "$out"
    done
}
