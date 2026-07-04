#!/usr/bin/env bash
# Module: secrets — scan HTML pages + crawled JavaScript for exposed credentials.
# Reads processed/all_urls.txt (pages) and processed/spider_urls.txt (crawled),
# fetches each and runs the regex catalog (lib/data/secrets.txt) via fetch_scan.
mod_secrets() {
    local od="$1"
    local catalog="$TN_LIB_DIR/data/secrets.txt"
    [[ -f "$catalog" ]] || { log "WARNING" "[secrets] catalog missing"; return 0; }
    local tgt; tgt=$(_mktmp sectgt) || return 0
    [[ -s "$od/processed/all_urls.txt" ]] && \
        head -n "${SECRETS_MAX_URLS:-150}" "$od/processed/all_urls.txt" >> "$tgt"
    # JavaScript discovered by the crawler is the highest-signal source
    for f in "$od/processed/spider_urls.txt" "$od/processed/js_urls.txt"; do
        [[ -s "$f" ]] && grep -iE '\.js([?#]|$)' "$f" >> "$tgt"
    done
    sort -u "$tgt" -o "$tgt" 2>/dev/null
    local n; n=$(_safe_count "$tgt" 2>/dev/null || wc -l < "$tgt")
    [[ -s "$tgt" ]] || { rm -f "$tgt"; log "INFO" "[secrets] no content to scan (skipped)"; return 0; }
    log "INFO" "[secrets] scanning $n resource(s)"
    fetch_scan secrets "$tgt" "$catalog" "${SECRETS_MAX_SCAN:-400}"
    rm -f "$tgt"
}
