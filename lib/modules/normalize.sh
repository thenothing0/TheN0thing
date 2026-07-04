#!/usr/bin/env bash
# Module: normalize — refactor EXISTING discovery outputs into findings so the
# whole tool feeds one pipeline (nuclei is owned by vulnprio; DNSSEC by emailsec).
mod_normalize() {
    local od="$1" tgt="$2"

    # ── Public / existing cloud buckets ──
    if [[ -s "$od/processed/cloud_buckets.txt" ]]; then
        local st prov url rest
        while read -r st prov url rest; do
            case "$st" in
                OPEN)   fe_emit normalize cloud high firm "$url" \
                            "Publicly readable cloud bucket ($prov)" \
                            "Bucket is world-readable" \
                            "$(jq -nc --arg u "$url" --arg p "$prov" '{url:$u,provider:$p}')" \
                            "Restrict the bucket ACL/policy" "" "cloud,bucket,$prov" ;;
                EXISTS) fe_emit normalize cloud info tentative "$url" \
                            "Cloud bucket exists ($prov)" "Bucket exists (access denied)" \
                            "$(jq -nc --arg u "$url" --arg p "$prov" '{url:$u,provider:$p}')" \
                            "" "" "cloud,bucket" ;;
            esac
        done < "$od/processed/cloud_buckets.txt"
    fi

    # ── Subdomain takeover (subjack) ──
    if [[ -s "$od/processed/subjack.txt" ]]; then
        local l host
        grep -ivE 'not vulnerable|^[[:space:]]*$' "$od/processed/subjack.txt" | while IFS= read -r l; do
            host=$(grep -oE '[a-z0-9._-]+\.[a-z]{2,}' <<<"$l" | head -1)
            fe_emit normalize takeover high firm "${host:-$l}" "Potential subdomain takeover" \
                "$l" "$(jq -nc --arg l "$l" '{detail:$l}')" \
                "Remove the dangling DNS record or reclaim the backing resource" "" "takeover,dns"
        done
    fi

    # ── Third-party / dangling CNAMEs ──
    if [[ -s "$od/processed/cname_thirdparty.txt" ]]; then
        local l host
        head -n 100 "$od/processed/cname_thirdparty.txt" | while IFS= read -r l; do
            [[ -z "$l" ]] && continue
            host="${l%% *}"
            fe_emit normalize takeover medium tentative "$host" \
                "Third-party CNAME (takeover candidate)" "$l" \
                "$(jq -nc --arg l "$l" '{chain:$l}')" \
                "Verify the pointed-to service is claimed by you" "" "takeover,cname"
        done
    fi

    # ── Zone transfer (AXFR) ──
    if [[ -s "$od/raw/axfr.txt" ]]; then
        local n; n=$(wc -l < "$od/raw/axfr.txt" 2>/dev/null); n="${n//[^0-9]/}"; [[ -z "$n" ]] && n=0
        fe_emit normalize dns high confirmed "$tgt" "DNS zone transfer (AXFR) allowed" \
            "A nameserver returned the full zone ($n records)" \
            "$(jq -nc --arg d "$tgt" --argjson n "$n" '{domain:$d,records:$n}')" \
            "Restrict AXFR to authorized secondary nameservers" "" "dns,axfr"
    fi

    # ── Virtual hosts ──
    if [[ -s "$od/processed/vhosts.txt" ]]; then
        local ip host code size
        head -n 50 "$od/processed/vhosts.txt" | while IFS=$'\t' read -r ip host code size; do
            [[ -z "$host" ]] && continue
            fe_emit normalize misc info tentative "$host" "Virtual host on $ip" \
                "Host header '$host' served distinct content on $ip (HTTP $code)" \
                "$(jq -nc --arg i "$ip" --arg h "$host" --arg c "${code:-}" '{ip:$i,vhost:$h,status:$c}')" \
                "" "" "vhost"
        done
    fi
    return 0
}
