#!/usr/bin/env bash
# Module: origin — find likely origin servers hidden behind a CDN/WAF via
# historical DNS and direct-IP Host-header probing.
mod_origin() {
    local od="$1" tgt="$2" tt="$3"
    command -v curl >/dev/null 2>&1 || return 0

    # ── 1) Historical IPs (SecurityTrails) as candidate origins ──
    if [[ -s "$od/raw/securitytrails_ips.txt" ]]; then
        local ip
        head -n 20 "$od/raw/securitytrails_ips.txt" | while IFS= read -r ip; do
            [[ "$ip" =~ ^[0-9.]+$ ]] || continue
            fe_emit origin origin info tentative "$ip" "Historical IP (candidate origin)" \
                "IP historically resolved for $tgt; may host the origin behind a CDN" \
                "$(jq -nc --arg i "$ip" --arg d "$tgt" '{ip:$i,domain:$d,source:"dns-history"}')" \
                "Verify whether the IP still serves the application directly" "" "origin,dns-history"
        done
    fi

    # ── 2) Direct-IP Host-header probe (CDN/WAF origin exposure) ──
    [[ "$tt" == domain ]] || return 0
    [[ -s "$od/assets/ips/all.txt" ]] || return 0
    local domain="$tgt"
    # baseline: the site's <title> when fetched normally
    local base; base=$(_mktmp orgb) || return 0
    _pr_fetch "https://$domain/" "$base" 12 >/dev/null
    local btitle; btitle=$(grep -oiE '<title>[^<]*' "$base" 2>/dev/null | head -1 | sed 's/<title>//I')
    rm -f "$base"
    [[ -z "$btitle" ]] && return 0

    local ip body code title
    head -n "${ORIGIN_MAX_IPS:-40}" "$od/assets/ips/all.txt" | while IFS= read -r ip; do
        [[ "$ip" =~ ^[0-9.]+$ ]] || continue
        body=$(_mktmp orgp) || continue
        code=$(curl -sk -A "$_PR_UA" --max-time 10 -H "Host: $domain" -o "$body" -w '%{http_code}' "https://$ip/" 2>/dev/null)
        title=$(grep -oiE '<title>[^<]*' "$body" 2>/dev/null | head -1 | sed 's/<title>//I')
        rm -f "$body"
        if [[ "$code" =~ ^(200|301|302|401|403)$ && -n "$title" && "$title" == "$btitle" ]]; then
            fe_emit origin origin medium firm "$ip" "Possible origin IP behind CDN/WAF" \
                "Direct request to $ip with Host: $domain returned the application (title matches)" \
                "$(jq -nc --arg i "$ip" --arg d "$domain" --arg t "$title" --arg c "$code" \
                    '{ip:$i,domain:$d,matched_title:$t,status:$c}')" \
                "Firewall the origin to accept traffic only from the CDN" "" "origin,cdn-bypass"
        fi
    done
    return 0
}
