#!/usr/bin/env bash
# Module: mobile (Tier-2) — mobile attack-surface discovery.
# Finds the target's Google Play listings, and (when tooling is present) pulls
# the APK and scans it for backend hostnames + secrets. Without APK tooling it
# still records app presence as intel. Read-only; downloads only public APKs.
mod_mobile() {
    local od="$1" tgt="$2" tt="$3"
    [[ "$tt" == domain ]] || return 0
    [[ "${MOBILE_ENABLE:-true}" == true ]] || return 0
    command -v curl >/dev/null 2>&1 || return 0
    local brand="${tgt%%.*}"

    # ── 1) Discover Play Store listings via a store search ──
    local s; s=$(_mktmp mob) || return 0
    _ptimeout 25 curl -fsS -A "$_PR_UA" --max-time 20 --max-filesize "$MAX_RESPONSE_SIZE" \
        "https://play.google.com/store/search?q=$(_url_encode "$brand")&c=apps" -o "$s" 2>/dev/null || true
    local pkgs; pkgs=$(_mktmp mobp) || { rm -f "$s"; return 0; }
    grep -oE 'id=[a-zA-Z][a-zA-Z0-9._]+' "$s" 2>/dev/null | sed 's/^id=//' | \
        grep -iE "(^|\.)$(_escape_ere "$brand")" | sort -u | head -n "${MOBILE_MAX:-5}" > "$pkgs"
    rm -f "$s"
    if [[ ! -s "$pkgs" ]]; then rm -f "$pkgs"; log "INFO" "[mobile] no Play listings for $brand (skipped)"; return 0; fi

    local pkg
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        fe_emit mobile mobile info firm "play:$pkg" "Android app identified" \
            "Google Play app '$pkg' appears associated with the target" \
            "$(jq -nc --arg p "$pkg" '{package:$p,store:"google-play",url:("https://play.google.com/store/apps/details?id="+$p)}')" \
            "" "" "mobile,android"
        _mobile_apk_scan "$od" "$pkg"
    done < "$pkgs"
    rm -f "$pkgs"
    return 0
}

# Pull the APK from a public mirror and scan it, if the tooling exists.
_mobile_apk_scan() {
    local od="$1" pkg="$2"
    [[ "${MOBILE_APK_FETCH:-false}" == true ]] || return 0
    command -v apkleaks >/dev/null 2>&1 || command -v apktool >/dev/null 2>&1 || return 0
    local apk="$od/temp/${pkg}.apk"
    # APKPure download endpoint (public APK mirror)
    _ptimeout 120 curl -fsSL -A "$_PR_UA" --max-time 100 --max-filesize 104857600 \
        "https://d.apkpure.com/b/APK/${pkg}?version=latest" -o "$apk" 2>/dev/null || true
    [[ -s "$apk" ]] || { log "INFO" "[mobile] APK fetch failed for $pkg"; return 0; }

    if command -v apkleaks >/dev/null 2>&1; then
        local out="$od/temp/${pkg}_apkleaks.txt"
        _ptimeout 300 apkleaks -f "$apk" -o "$out" 2>/dev/null || true
        if [[ -s "$out" ]]; then
            # backend hosts referenced in the APK
            local hosts; hosts=$(grep -oiE 'https?://[a-z0-9.-]+' "$out" 2>/dev/null | sed -E 's#https?://##' | sort -u | head -10)
            [[ -n "$hosts" ]] && fe_emit mobile mobile low firm "apk:$pkg" \
                "Backend hosts extracted from APK" \
                "apkleaks extracted backend hostnames from $pkg" \
                "$(jq -nc --arg p "$pkg" --arg h "$(head -3 <<<"$hosts" | paste -sd, -)" '{package:$p,hosts:$h}')" \
                "Review whether these backends require authentication" "" "mobile,android,apk"
            # secrets in the APK (reuse the secret catalog)
            scan_body mobile "apk:$pkg" "$out" "$TN_LIB_DIR/data/secrets.txt"
        fi
    fi
    rm -f "$apk"
}
