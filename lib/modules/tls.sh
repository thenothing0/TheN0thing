#!/usr/bin/env bash
# Module: tls — certificate + protocol posture per HTTPS host (portable openssl).
mod_tls() {
    local od="$1"
    command -v openssl >/dev/null 2>&1 || { log "WARNING" "[tls] openssl missing"; return 0; }
    local hosts; hosts=$(_mktmp tlsh) || return 0
    { grep -E '^https://' "$od/processed/all_urls.txt" 2>/dev/null | sed -E 's#^https://##; s#/.*##'
      # fall back to bare subdomains if no live-URL list
      [[ ! -s "$od/processed/all_urls.txt" ]] && head -n 40 "$od/assets/subdomains/all.txt" 2>/dev/null
    } | sed '/^$/d' | sort -u | head -n "${TLS_MAX_HOSTS:-40}" > "$hosts"
    [[ -s "$hosts" ]] || { rm -f "$hosts"; log "INFO" "[tls] no HTTPS hosts (skipped)"; return 0; }
    log "INFO" "[tls] assessing $(wc -l < "$hosts") host(s)"
    local h; while IFS= read -r h; do
        [[ -z "$h" ]] && continue
        local port=443; case "$h" in *:*) port="${h##*:}"; h="${h%%:*}";; esac
        _tls_check_host "$h" "$port"
    done < "$hosts"
    rm -f "$hosts"
}

_tls_check_host() {
    local host="$1" port="$2" asset="$1:$2"
    local cert; cert=$(_mktmp tlsc) || return 0
    _ptimeout 15 openssl s_client -connect "$host:$port" -servername "$host" </dev/null 2>/dev/null \
        | openssl x509 2>/dev/null > "$cert"
    [[ -s "$cert" ]] || { rm -f "$cert"; return 0; }

    # Expiry
    if ! openssl x509 -in "$cert" -checkend 0 -noout >/dev/null 2>&1; then
        local end; end=$(openssl x509 -in "$cert" -enddate -noout 2>/dev/null | cut -d= -f2)
        fe_emit tls tls high confirmed "$asset" "TLS certificate expired" \
            "Certificate for $host expired ($end)" \
            "$(jq -nc --arg h "$asset" --arg e "$end" '{host:$h,not_after:$e}')" \
            "Renew the certificate immediately" "" "tls,cert"
    elif ! openssl x509 -in "$cert" -checkend 1209600 -noout >/dev/null 2>&1; then
        local end; end=$(openssl x509 -in "$cert" -enddate -noout 2>/dev/null | cut -d= -f2)
        fe_emit tls tls medium confirmed "$asset" "TLS certificate expiring soon" \
            "Certificate for $host expires within 14 days ($end)" \
            "$(jq -nc --arg h "$asset" --arg e "$end" '{host:$h,not_after:$e}')" \
            "Renew before expiry" "" "tls,cert"
    fi

    # Self-signed
    local subj iss
    subj=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/^subject= *//')
    iss=$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null | sed 's/^issuer= *//')
    if [[ -n "$subj" && "$subj" == "$iss" ]]; then
        fe_emit tls tls medium firm "$asset" "Self-signed certificate" \
            "Certificate subject equals issuer ($subj)" \
            "$(jq -nc --arg h "$asset" --arg s "$subj" '{host:$h,subject:$s}')" \
            "Use a CA-issued certificate" "" "tls,cert"
    fi

    # Weak key size — algorithm-aware (ECDSA 256-bit is strong; only RSA/DSA
    # under 2048 bits, or EC under 224 bits, is weak).
    local text bits alg weak=false
    text=$(openssl x509 -in "$cert" -noout -text 2>/dev/null)
    bits=$(grep -oiE 'Public-Key: \([0-9]+ bit\)' <<<"$text" | grep -oE '[0-9]+' | head -1)
    alg=$(grep -oiE 'Public Key Algorithm: [a-zA-Z0-9-]+' <<<"$text" | head -1)
    if [[ "$bits" =~ ^[0-9]+$ ]]; then
        if grep -qiE 'rsa|dsa' <<<"$alg" && (( bits < 2048 )); then weak=true
        elif grep -qiE 'ecPublicKey|id-ec' <<<"$alg" && (( bits < 224 )); then weak=true; fi
    fi
    if [[ "$weak" == true ]]; then
        fe_emit tls tls high firm "$asset" "Weak certificate key" \
            "Public key is only ${bits} bits (${alg#Public Key Algorithm: })" \
            "$(jq -nc --arg h "$asset" --argjson b "$bits" --arg a "$alg" '{host:$h,key_bits:$b,algorithm:$a}')" \
            "Reissue with >=2048-bit RSA or >=256-bit ECDSA" "" "tls,cert,crypto"
    fi
    rm -f "$cert"

    # Legacy protocol negotiation (only flags what our client can actually speak)
    local proto pn
    for proto in tls1 tls1_1; do
        [[ "$proto" == tls1 ]] && pn="TLSv1.0" || pn="TLSv1.1"
        if _ptimeout 12 openssl s_client -"$proto" -connect "$host:$port" -servername "$host" </dev/null >/dev/null 2>&1; then
            fe_emit tls tls medium confirmed "$asset" "Legacy $pn supported" \
                "Server negotiates deprecated $pn" \
                "$(jq -nc --arg h "$asset" --arg p "$pn" '{host:$h,protocol:$p}')" \
                "Disable TLS 1.0 and TLS 1.1" \
                "https://datatracker.ietf.org/doc/html/rfc8996" "tls,protocol"
        fi
    done
}
