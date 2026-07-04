#!/usr/bin/env bash
# Module: gfpatterns (Tier-2) — apply the operator's gf pattern templates
# (~/.gf/*.json, or $GF_PATH) across the whole discovered URL corpus to surface
# parameters/URLs worth manual testing (sqli/ssrf/lfi/rce/redirect/…).
# Reads the JSON templates directly (pattern/patterns + flags) — no dependency
# on the gf binary or its config discovery, so it is portable and testable.
mod_gfpatterns() {
    local od="$1"
    command -v jq >/dev/null 2>&1 || return 0
    local gfd="${GF_PATH:-$HOME/.gf}"
    [[ -d "$gfd" ]] || { log "INFO" "[gf] no gf templates at $gfd (skipped)"; return 0; }

    local corpus; corpus=$(_mktmp gfcorp) || return 0
    cat "$od/processed/all_urls.txt" "$od/processed/spider_urls.txt" \
        "$od/processed/wayback_urls.txt" "$od/processed/wayback_params.txt" \
        "$od/processed/js_endpoints.txt" "$od/processed/content_found.txt" 2>/dev/null | \
        grep -E '^https?://' 2>/dev/null | sort -u > "$corpus"
    if [[ ! -s "$corpus" ]]; then rm -f "$corpus"; log "INFO" "[gf] empty URL corpus (skipped)"; return 0; fi
    log "INFO" "[gf] applying patterns to $(wc -l < "$corpus") URLs"

    # curated <template>:<severity>:<tag> — indicators are tentative candidates
    local specs="rce:medium:rce ssti:medium:ssti sqli:low:sqli ssrf:low:ssrf lfi:low:lfi \
img-traversal:low:lfi redirect:low:open-redirect idor:low:idor xss:low:xss \
interestingparams:info:params interestingEXT:info:ext debug-pages:info:debug"
    local spec name sev tag
    for spec in $specs; do
        IFS=: read -r name sev tag <<<"$spec"
        [[ -f "$gfd/$name.json" ]] && _gf_apply "$gfd/$name.json" "$corpus" "$name" "$sev" "$tag"
    done
    rm -f "$corpus"
}

_gf_apply() {
    local tpl="$1" corpus="$2" name="$3" sev="$4" tag="$5"
    local pf; pf=$(_mktmp gfpat) || return 0
    jq -r '(.pattern // empty), (.patterns[]? // empty)' "$tpl" 2>/dev/null > "$pf"
    [[ -s "$pf" ]] || { rm -f "$pf"; return 0; }
    local hits; hits=$(grep -iEf "$pf" "$corpus" 2>/dev/null | sort -u | head -n "${GF_MAX_PER_PATTERN:-15}")
    if [[ -n "$hits" ]]; then
        local u m
        while IFS= read -r u; do
            [[ -z "$u" ]] && continue
            m=$(grep -oiEf "$pf" <<<"$u" 2>/dev/null | head -1)
            fe_emit gfpatterns vuln-indicator "$sev" tentative "$u" \
                "Candidate: $name pattern in URL" \
                "URL matches the '$name' gf pattern — manual verification candidate" \
                "$(jq -nc --arg u "$u" --arg n "$name" --arg m "${m:-}" '{url:$u,pattern:$n,match:$m}')" \
                "Manually test for $name on the highlighted parameter" "" "gf,$tag"
        done <<<"$hits"
    fi
    rm -f "$pf"
}
