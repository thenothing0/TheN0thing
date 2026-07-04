#!/usr/bin/env bash
# Module: netintel (Tier-2) — reverse-DNS expansion + IPv6 discovery.
# Collects PTR / AAAA records into assets, and emits info findings for PTRs that
# reveal off-scope / related infrastructure and for IPv6 exposure.
mod_netintel() {
    local od="$1" tgt="$2" tt="$3"
    command -v dig >/dev/null 2>&1 || { log "WARNING" "[netintel] dig missing"; return 0; }

    # ── Reverse DNS ──
    if [[ -s "$od/assets/ips/all.txt" ]]; then
        local rev="$od/processed/reverse_dns.txt"; : > "$rev"
        local ip ptr
        head -n "${NETINTEL_MAX_IPS:-100}" "$od/assets/ips/all.txt" | while IFS= read -r ip; do
            [[ "$ip" =~ ^[0-9.]+$ ]] || continue
            ptr=$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//' | head -1)
            [[ -z "$ptr" ]] && continue
            printf '%s\t%s\n' "$ip" "$ptr" >> "$rev"
            # off-scope PTR (different registrable domain) = related infra worth noting
            if [[ "$tt" == domain && "$ptr" != *"$tgt" && "$ptr" =~ [a-z]\.[a-z]{2,} ]]; then
                fe_emit netintel dns info tentative "$ip" "Reverse DNS reveals related host" \
                    "PTR for $ip resolves to $ptr (outside $tgt)" \
                    "$(jq -nc --arg i "$ip" --arg p "$ptr" '{ip:$i,ptr:$p}')" \
                    "Review whether the pointed-to host is in scope" "" "dns,reverse-dns"
            fi
        done
    fi

    # ── IPv6 (AAAA) discovery ──
    if [[ -s "$od/assets/subdomains/all.txt" ]]; then
        local v6="$od/processed/ipv6.txt"; : > "$v6"
        local host a
        head -n "${NETINTEL_MAX_SUBS:-200}" "$od/assets/subdomains/all.txt" | while IFS= read -r host; do
            [[ "$host" =~ ^[a-zA-Z0-9.-]+$ ]] || continue
            dig +short AAAA "$host" 2>/dev/null | grep -E ':' | while IFS= read -r a; do
                printf '%s\t%s\n' "$host" "$a" >> "$v6"
            done
        done
        if [[ -s "$v6" ]]; then
            local n6; n6=$(wc -l < "$v6" 2>/dev/null); n6="${n6//[^0-9]/}"; [[ -z "$n6" ]] && n6=0
            fe_emit netintel dns info firm "$tgt" "IPv6 attack surface present" \
                "$n6 IPv6 (AAAA) address(es) discovered across hosts" \
                "$(jq -nc --arg d "$tgt" --argjson n "$n6" '{domain:$d,ipv6_records:$n}')" \
                "Ensure IPv6 endpoints are covered by the same controls as IPv4" "" "dns,ipv6"
        fi
    fi
    return 0
}
