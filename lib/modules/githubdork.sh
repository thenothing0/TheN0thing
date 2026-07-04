#!/usr/bin/env bash
# Module: githubdork (Tier-2) — automated GitHub code-search dorks for the target.
# Uses the authenticated Code Search API (needs GITHUB_TOKEN). Self-skips without
# a token. Flags public code that mentions the target domain alongside secret /
# config indicators. Read-only; never clones or writes.
mod_githubdork() {
    local od="$1" tgt="$2" tt="$3"
    [[ "$tt" == domain ]] || return 0
    [[ -n "${GITHUB_TOKEN:-}" ]] || { log "INFO" "[githubdork] no GITHUB_TOKEN (skipped)"; return 0; }
    command -v curl >/dev/null 2>&1 || return 0
    local dom="$tgt"

    local tf; tf=$(_write_token_file "ghdork" "$GITHUB_TOKEN") || return 0
    local _tok; _tok=$(_read_token_file "$tf") || { rm -f "$tf"; return 0; }

    # dork:severity pairs — the qualifier is combined with the target domain
    local dorks='password:high api_key:high secret:high aws_access_key_id:critical \
BEGIN_RSA_PRIVATE_KEY:critical mysql_password:high JDBC:medium .env:high \
authorization_bearer:high client_secret:high connectionstring:medium'
    local spec q sev
    for spec in $dorks; do
        IFS=: read -r q sev <<<"$spec"
        q="${q//_/ }"
        local query; query=$(_url_encode "\"$dom\" $q")
        local t; t=$(_mktmp ghd) || continue
        _ptimeout 25 curl -fsS --max-time 20 --max-filesize "$MAX_RESPONSE_SIZE" \
            -H "Authorization: Bearer ${_tok}" \
            -H "Accept: application/vnd.github.text-match+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "https://api.github.com/search/code?q=${query}&per_page=5" -o "$t" 2>/dev/null || true
        if [[ -s "$t" && "$(head -c1 "$t")" == "{" ]]; then
            local total; total=$(jq -r '.total_count // 0' "$t" 2>/dev/null); total="${total//[^0-9]/}"
            if [[ "$total" =~ ^[0-9]+$ ]] && (( total > 0 )); then
                local top; top=$(jq -r '[.items[]?.html_url] | .[0:3] | join(" , ")' "$t" 2>/dev/null)
                fe_emit githubdork exposure "$sev" tentative "github:$dom" \
                    "GitHub code mentions '$dom' near '$q' ($total hits)" \
                    "Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials" \
                    "$(jq -nc --arg d "$dom" --arg q "$q" --argjson n "$total" --arg u "${top:-}" \
                        '{domain:$d,dork:$q,hits:$n,examples:$u}')" \
                    "Review and rotate any leaked secrets; request GitHub takedown if applicable" \
                    "https://docs.github.com/search-github/searching-on-github/searching-code" \
                    "github,dork,secret-leak"
            fi
        fi
        rm -f "$t"
        local d="${GHDORK_DELAY:-$(( RANDOM % 3 + 2 ))}"   # respect code-search rate limit
        _safe_sleep "$d" 2>/dev/null || sleep "$d" 2>/dev/null || true
    done
    rm -f "$tf"
    return 0
}
