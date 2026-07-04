#!/usr/bin/env bash
# Module: emailsec — email-security posture findings from DNS.
# SPF / DMARC / DKIM / MTA-STS / BIMI / DNSSEC. Domain targets only.
_es_ev() { jq -nc --arg d "$1" --arg v "$2" '{domain:$d,record:$v}'; }

mod_emailsec() {
    local od="$1" tgt="$2" tt="$3"
    [[ "$tt" == domain ]] || return 0
    command -v dig >/dev/null 2>&1 || { log "WARNING" "[emailsec] dig missing"; return 0; }
    local dom="$tgt"
    _ev() { _es_ev "$dom" "$1"; }

    # ── SPF ──
    local spf; spf=$(dig +short TXT "$dom" 2>/dev/null | tr -d '"' | grep -i 'v=spf1' | head -1)
    if [[ -z "$spf" ]]; then
        fe_emit emailsec email medium firm "$dom" "SPF record missing" \
            "No SPF record published; sender spoofing is easier" "$(_ev none)" \
            "Publish an SPF record that ends in -all" \
            "https://datatracker.ietf.org/doc/html/rfc7208" "email,spf,spoofing"
    elif grep -qiE '\+all' <<<"$spf"; then
        fe_emit emailsec email high firm "$dom" "SPF +all (any sender allowed)" \
            "SPF uses +all, authorizing any host to send as this domain" "$(_ev "$spf")" \
            "Replace +all with -all" "" "email,spf,spoofing"
    elif grep -qiE '[?]all|~all' <<<"$spf"; then
        fe_emit emailsec email low firm "$dom" "SPF not hard-fail" \
            "SPF ends in ~all/?all rather than -all; spoofed mail may still pass" "$(_ev "$spf")" \
            "Use -all once senders are enumerated" "" "email,spf"
    fi

    # ── DMARC ──
    local dmarc; dmarc=$(dig +short TXT "_dmarc.$dom" 2>/dev/null | tr -d '"' | grep -i 'v=DMARC1' | head -1)
    if [[ -z "$dmarc" ]]; then
        fe_emit emailsec email high firm "$dom" "DMARC record missing" \
            "No DMARC policy; spoofed mail is neither quarantined nor rejected" "$(_ev none)" \
            "Publish _dmarc.$dom with p=quarantine or p=reject" \
            "https://datatracker.ietf.org/doc/html/rfc7489" "email,dmarc,spoofing"
    else
        local p; p=$(grep -oiE 'p=[a-z]+' <<<"$dmarc" | head -1 | cut -d= -f2 | tr 'A-Z' 'a-z')
        case "$p" in
            none) fe_emit emailsec email medium firm "$dom" "DMARC policy is p=none" \
                    "DMARC is monitor-only; spoofed mail is still delivered" "$(_ev "$dmarc")" \
                    "Progress to p=quarantine then p=reject" "" "email,dmarc,spoofing" ;;
            reject|quarantine) : ;;  # good posture, no finding
            *) fe_emit emailsec email medium firm "$dom" "DMARC missing policy tag" \
                    "DMARC record present but has no valid p= tag" "$(_ev "$dmarc")" \
                    "Add p=reject or p=quarantine" "" "email,dmarc" ;;
        esac
    fi

    # ── DKIM (probe common selectors; absence of any is informational) ──
    local sel found_dkim=false
    for sel in default google selector1 selector2 k1 dkim mail smtp s1 s2; do
        if dig +short TXT "${sel}._domainkey.$dom" 2>/dev/null | grep -qiE 'v=DKIM1|k=rsa|p='; then
            found_dkim=true; break
        fi
    done
    [[ "$found_dkim" == false ]] && fe_emit emailsec email low tentative "$dom" \
        "No DKIM selector found" \
        "No DKIM key found at common selectors; outbound mail may be unsigned" "$(_ev none)" \
        "Publish a DKIM key and sign outbound mail" "" "email,dkim"

    # ── MTA-STS ──
    if ! dig +short TXT "_mta-sts.$dom" 2>/dev/null | grep -qi 'v=STSv1'; then
        fe_emit emailsec email low firm "$dom" "MTA-STS not deployed" \
            "No MTA-STS policy; inbound-mail TLS can be stripped (downgrade)" "$(_ev none)" \
            "Publish an MTA-STS policy and _mta-sts TXT record" \
            "https://datatracker.ietf.org/doc/html/rfc8461" "email,tls,mta-sts"
    fi

    # ── BIMI (informational) ──
    if dig +short TXT "default._bimi.$dom" 2>/dev/null | grep -qi 'v=BIMI1'; then
        fe_emit emailsec email info firm "$dom" "BIMI record present" \
            "Domain publishes a BIMI record (brand indicator)" "$(_ev bimi)" \
            "" "" "email,bimi"
    fi

    # ── DNSSEC ──
    if [[ -z "$(dig +short DNSKEY "$dom" 2>/dev/null)" ]]; then
        fe_emit emailsec dns low firm "$dom" "DNSSEC not enabled" \
            "Zone is not DNSSEC-signed; DNS answers can be spoofed/tampered" "$(_ev none)" \
            "Enable DNSSEC signing at the registrar/DNS provider" \
            "https://www.cloudflare.com/dns/dnssec/" "dns,dnssec"
    fi
    return 0
}
