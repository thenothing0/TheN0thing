#!/usr/bin/env bash
# Module: apidiscovery — Swagger/OpenAPI/GraphQL/docs paths + GraphQL field
# suggestion probing (schema leak even when introspection is disabled).
mod_apidiscovery() {
    local od="$1"
    local urls="$od/processed/all_urls.txt"
    [[ -s "$urls" ]] || { log "INFO" "[api] no live URLs (skipped)"; return 0; }
    local rules="$TN_LIB_DIR/data/api_paths.txt"
    [[ -f "$rules" ]] && probe_paths api "$urls" "$rules" "${API_MAX_HOSTS:-120}"
    _api_graphql_suggest "$od" "$urls"
}

# Send a query with a deliberately-misspelled field; GraphQL servers that keep
# "Did you mean …" suggestions on leak their schema even with introspection off.
_api_graphql_suggest() {
    local od="$1" urls="$2"
    command -v curl >/dev/null 2>&1 || return 0
    local base gp body code sugg ev
    grep -E '^https?://' "$urls" | sort -u | head -n "${API_GQL_HOSTS:-30}" | while IFS= read -r base; do
        base="${base%/}"
        for gp in /graphql /api/graphql /v1/graphql; do
            body=$(_mktmp gql) || continue
            code=$(curl -sk -A "$_PR_UA" --max-time 10 -X POST \
                -H 'Content-Type: application/json' \
                --data '{"query":"{ __typename thisFieldDoesNotExist_zzz }"}' \
                -o "$body" -w '%{http_code}' "${base}${gp}" 2>/dev/null)
            if [[ "$code" =~ ^(200|400)$ ]] && grep -qiE 'Did you mean|Cannot query field' "$body" 2>/dev/null; then
                sugg=$(grep -oiE 'Did you mean [^"}.]*' "$body" 2>/dev/null | head -1)
                ev=$(jq -nc --arg u "${base}${gp}" --arg s "${sugg:-suggestions present}" \
                    '{url:$u,suggestion:$s}')
                fe_emit api api medium firm "${base}${gp}" \
                    "GraphQL field-suggestions enabled" \
                    "GraphQL returns field-name suggestions, leaking schema names even if introspection is disabled" \
                    "$ev" "Disable field suggestions / didYouMean in production" \
                    "https://graphql.org/learn/" "graphql,api"
            fi
            rm -f "$body"
        done
    done
}
