#!/usr/bin/env bash
# Module: vulnprio — turn raw nuclei output into a prioritized vuln queue.
# Each nuclei result becomes a finding; CVEs are enriched with EPSS + CISA KEV
# and severity is escalated (KEV -> critical, high EPSS -> >=high).
mod_vulnprio() {
    local od="$1"
    local nf="$od/processed/nuclei_results.txt"
    [[ -s "$nf" ]] || { log "INFO" "[vulnprio] no nuclei results (skipped)"; return 0; }
    command -v curl >/dev/null 2>&1 || true
    local kev="$od/temp/kev_cves.txt"
    _vp_load_kev "$kev"

    local line sev tid url cve
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        sev=$(grep -oiE '\[(critical|high|medium|low|info|unknown)\]' <<<"$line" | head -1 | tr -d '[]' | tr 'A-Z' 'a-z')
        [[ -z "$sev" || "$sev" == unknown ]] && sev=info
        tid=$(grep -oE '^\[[^]]+\]' <<<"$line" | head -1 | tr -d '[]')
        url=$(grep -oE 'https?://[^ ]+' <<<"$line" | head -1)
        [[ -z "$url" ]] && url="$tid"
        cve=$(grep -oiE 'CVE-[0-9]{4}-[0-9]{4,7}' <<<"$line" | head -1 | tr 'a-z' 'A-Z')

        local epss="" percentile="" in_kev=false
        if [[ -n "$cve" ]]; then
            grep -qxF "$cve" "$kev" 2>/dev/null && in_kev=true
            local e; e=$(_vp_epss "$cve")
            epss="${e%% *}"; percentile="${e##* }"
            # Escalation rules
            [[ "$in_kev" == true ]] && sev=critical
            if [[ "$epss" =~ ^0?\.[0-9]+$ ]]; then
                awk "BEGIN{exit !($epss>=0.5)}" && { [[ "$sev" =~ ^(info|low|medium)$ ]] && sev=high; }
            fi
        fi
        local ev; ev=$(jq -nc --arg u "$url" --arg t "$tid" --arg c "${cve:-}" \
            --arg epss "${epss:-}" --arg pct "${percentile:-}" --argjson kev "$in_kev" \
            '{url:$u,template:$t,cve:$c,epss:$epss,epss_percentile:$pct,cisa_kev:$kev}')
        local title="$tid"; [[ -n "$cve" ]] && title="$cve ($tid)"
        local tags="nuclei,vuln"; [[ "$in_kev" == true ]] && tags="$tags,kev,exploited"
        fe_emit vulnprio vuln "$sev" firm "$url" "$title" \
            "Nuclei match $tid${cve:+ — $cve}${in_kev:+ [CISA KEV: actively exploited]}${epss:+ (EPSS $epss)}" \
            "$ev" "Patch/upgrade the affected component" \
            "${cve:+https://nvd.nist.gov/vuln/detail/$cve}" "$tags"
    done < "$nf"
    return 0
}

# Download the CISA KEV catalog once, extract CVE ids to a flat list (cached).
_vp_load_kev() {
    local out="$1"
    [[ -s "$out" ]] && return 0
    command -v curl >/dev/null 2>&1 || { : > "$out"; return 0; }
    local t; t=$(_mktmp kev) || { : > "$out"; return 0; }
    _ptimeout 40 curl -fsS --max-time 30 --max-filesize "$MAX_RESPONSE_SIZE" \
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
        -o "$t" 2>/dev/null || true
    if [[ -s "$t" ]]; then
        _safe_jq "$out" "$t" -r '.vulnerabilities[]?.cveID // empty' 2>/dev/null || \
            jq -r '.vulnerabilities[]?.cveID // empty' "$t" 2>/dev/null > "$out" || : > "$out"
        log "INFO" "[vulnprio] CISA KEV: $(wc -l < "$out" 2>/dev/null) CVEs"
    else : > "$out"; fi
    rm -f "$t"
}

# EPSS score for a CVE -> "<score> <percentile>" (empty if unavailable).
_vp_epss() {
    local cve="$1" t; t=$(_mktmp epss) || { printf ' '; return 0; }
    _ptimeout 20 curl -fsS --max-time 15 "https://api.first.org/data/v1/epss?cve=$cve" -o "$t" 2>/dev/null || true
    local score pct
    score=$(jq -r '.data[0].epss // empty' "$t" 2>/dev/null)
    pct=$(jq -r '.data[0].percentile // empty' "$t" 2>/dev/null)
    rm -f "$t"
    printf '%s %s' "${score:-}" "${pct:-}"
}
