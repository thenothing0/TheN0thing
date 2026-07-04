#!/usr/bin/env bash
# Module: postman (Tier-2) — Postman public-workspace intelligence.
# Searches Postman's public API network for the target and flags public
# workspaces/collections/requests that reference it (these routinely leak
# internal API endpoints and environment credentials). Read-only.
mod_postman() {
    local od="$1" tgt="$2" tt="$3"
    [[ "$tt" == domain ]] || return 0
    [[ "${POSTMAN_ENABLE:-true}" == true ]] || return 0
    command -v curl >/dev/null 2>&1 || return 0
    local dom="$tgt" brand="${tgt%%.*}"

    local t; t=$(_mktmp pm) || return 0
    # Public search endpoint used by the Postman web UI (no key required).
    _ptimeout 30 curl -fsS -A "$_PR_UA" --max-time 25 --max-filesize "$MAX_RESPONSE_SIZE" \
        -H 'Content-Type: application/json' \
        --data "$(jq -nc --arg q "$dom" '{service:"search",method:"POST",path:"/search-all",body:{queryIndices:["runtime.collection","adp.api","runtime.workspace"],queryText:$q,size:15,from:0}}')" \
        "https://www.postman.com/_api/ws/proxy" -o "$t" 2>/dev/null || true
    if [[ ! -s "$t" || "$(head -c1 "$t")" != "{" ]]; then rm -f "$t"; log "INFO" "[postman] no data (skipped)"; return 0; fi

    # Count hits whose name/URL references the brand or domain (defensive jq).
    local hits; hits=$(jq -r --arg d "$dom" --arg b "$brand" '
        [ .. | objects | select((.name? // "" | ascii_downcase | test($b))
              or (.url? // "" | ascii_downcase | test($d))) ] | length' "$t" 2>/dev/null)
    hits="${hits//[^0-9]/}"; [[ "$hits" =~ ^[0-9]+$ ]] || hits=0
    local sample; sample=$(jq -r --arg d "$dom" --arg b "$brand" '
        [ .. | objects | select((.name? // "" | ascii_downcase | test($b))
              or (.url? // "" | ascii_downcase | test($d)))
          | (.name? // .url? // empty) ] | .[0:3] | join(" | ")' "$t" 2>/dev/null)
    rm -f "$t"

    if (( hits > 0 )); then
        fe_emit postman exposure medium tentative "postman:$dom" \
            "Public Postman workspace references target ($hits hits)" \
            "Public Postman collections/workspaces mention the target — often leak internal API endpoints and environment secrets" \
            "$(jq -nc --arg d "$dom" --argjson n "$hits" --arg s "${sample:-}" \
                '{domain:$d,hits:$n,examples:$s,source:"postman-public"}')" \
            "Review the public workspaces; make internal collections private and rotate any exposed secrets" \
            "https://www.postman.com/explore" "postman,api,info-leak"
    fi
    return 0
}
