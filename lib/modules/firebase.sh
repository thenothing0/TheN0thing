#!/usr/bin/env bash
# Module: firebase (Tier-2) — discover Firebase Realtime Databases and test the
# canonical open-database condition (/.json returns data without auth).
mod_firebase() {
    local od="$1" tgt="$2" tt="$3"
    command -v curl >/dev/null 2>&1 || return 0
    local cand; cand=$(_mktmp fbc) || return 0
    # 1) firebase hosts referenced anywhere we've collected
    cat "$od/processed/js_endpoints.txt" "$od/processed/wayback_urls.txt" \
        "$od/processed/all_urls.txt" "$od/assets/subdomains/all.txt" 2>/dev/null | \
        grep -oiE '[a-z0-9-]+(-default-rtdb)?\.(firebaseio\.com|firebasedatabase\.app)' >> "$cand"
    # 2) slug guesses from the target
    if [[ "$tt" == domain ]]; then
        local slug="${tgt%%.*}"
        printf '%s.firebaseio.com\n%s-default-rtdb.firebaseio.com\n%s-default-rtdb.firebasedatabase.app\n' \
            "$slug" "$slug" "$slug" >> "$cand"
    fi
    sort -u "$cand" -o "$cand" 2>/dev/null
    [[ -s "$cand" ]] || { rm -f "$cand"; log "INFO" "[firebase] no candidates (skipped)"; return 0; }

    local host body code
    head -n "${FIREBASE_MAX:-40}" "$cand" | while IFS= read -r host; do
        [[ "$host" =~ ^[a-z0-9.-]+$ ]] || continue
        body=$(_mktmp fbb) || continue
        code=$(curl -sk -A "$_PR_UA" --max-time 10 -o "$body" -w '%{http_code}' "https://${host}/.json" 2>/dev/null)
        if [[ "$code" == 200 ]]; then
            local content; content=$(head -c 200 "$body" 2>/dev/null | tr -d '\n')
            if [[ "$content" != "null" && -n "$content" ]] && ! grep -qi 'Permission denied\|error' "$body"; then
                fe_emit firebase cloud critical confirmed "https://${host}/.json" \
                    "Open Firebase Realtime Database" \
                    "Firebase database at $host is world-readable without authentication" \
                    "$(jq -nc --arg h "$host" --arg s "${content:0:120}" '{host:$h,sample:$s}')" \
                    "Set Firebase security rules to deny unauthenticated reads/writes" \
                    "https://firebase.google.com/docs/database/security" "firebase,cloud,data-exposure"
            fi
        fi
        rm -f "$body"
    done
    rm -f "$cand"
    return 0
}
