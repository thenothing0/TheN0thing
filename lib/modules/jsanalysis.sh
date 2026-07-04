#!/usr/bin/env bash
# Module: jsanalysis — analyse JavaScript for sourcemaps, internal-host leakage
# and high-interest endpoints. Extracted endpoints are written back into the
# crawl pipeline (processed/js_endpoints.txt).
mod_jsanalysis() {
    local od="$1"
    command -v curl >/dev/null 2>&1 || return 0
    local jsurls; jsurls=$(_mktmp jsu) || return 0
    # 1) JS the crawler already found
    [[ -s "$od/processed/spider_urls.txt" ]] && \
        grep -iE '\.js([?#]|$)' "$od/processed/spider_urls.txt" >> "$jsurls"
    # 2) <script src> from a sample of live pages
    if [[ ! -s "$jsurls" && -s "$od/processed/all_urls.txt" ]]; then
        local p pb
        head -n 20 "$od/processed/all_urls.txt" | while IFS= read -r p; do
            pb=$(_mktmp jshtml) || continue
            _pr_fetch "$p" "$pb" 10 >/dev/null
            grep -oiE 'src="[^"]+\.js[^"]*"' "$pb" 2>/dev/null | sed -E 's/^src="//; s/"$//' | \
                while IFS= read -r s; do
                    case "$s" in http*) printf '%s\n' "$s";; /*) printf '%s%s\n' "${p%/*}" "$s";; esac
                done
            rm -f "$pb"
        done >> "$jsurls"
    fi
    sort -u "$jsurls" -o "$jsurls" 2>/dev/null
    [[ -s "$jsurls" ]] || { rm -f "$jsurls"; log "INFO" "[jsanalysis] no JavaScript found (skipped)"; return 0; }
    head -n "${JS_MAX:-150}" "$jsurls" > "${jsurls}.c" && mv "${jsurls}.c" "$jsurls"
    log "INFO" "[jsanalysis] analysing $(wc -l < "$jsurls") script(s)"

    local endpoints="$od/processed/js_endpoints.txt"; : > "$endpoints"
    local ju body
    while IFS= read -r ju; do
        [[ -z "$ju" ]] && continue
        body=$(_mktmp jsb) || continue
        _pr_fetch "$ju" "$body" 12 >/dev/null
        [[ -s "$body" ]] || { rm -f "$body"; continue; }
        _js_sourcemap "$ju" "$body"
        _js_internal_hosts "$ju" "$body"
        _js_endpoints "$ju" "$body" "$endpoints"
        rm -f "$body"
    done < "$jsurls"
    rm -f "$jsurls"
    _sort_inplace "$endpoints" 2>/dev/null || sort -u "$endpoints" -o "$endpoints" 2>/dev/null
    return 0
}

_js_sourcemap() {
    local ju="$1" body="$2"
    local sm; sm=$(grep -oiE 'sourceMappingURL=[^ */]+\.map' "$body" 2>/dev/null | head -1)
    local mapurl="${ju}.map"; [[ -n "$sm" ]] && mapurl="${ju%/*}/${sm#sourceMappingURL=}"
    local code; code=$(curl -sk -A "$_PR_UA" --max-time 8 -o /dev/null -w '%{http_code}' "$mapurl" 2>/dev/null)
    if [[ "$code" == 200 ]]; then
        fe_emit jsanalysis js medium confirmed "$mapurl" "JavaScript source map exposed" \
            "Source map is publicly served, disclosing original source" \
            "$(jq -nc --arg u "$mapurl" '{sourcemap:$u}')" \
            "Do not deploy .map files to production" "" "js,sourcemap,info-leak"
    fi
}

_js_internal_hosts() {
    local ju="$1" body="$2" m
    m=$(grep -aoiE '(https?://)?((10|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9.]+|[a-z0-9-]+\.(internal|corp|intranet|local|svc\.cluster\.local))(:[0-9]+)?' "$body" 2>/dev/null | sort -u | head -5)
    [[ -z "$m" ]] && return 0
    local first; first=$(head -1 <<<"$m")
    fe_emit jsanalysis js medium firm "$ju" "Internal hostname/IP leaked in JavaScript" \
        "Client-served JS references internal infrastructure" \
        "$(jq -nc --arg u "$ju" --arg m "$first" '{script:$u,example:$m}')" \
        "Remove internal references from client bundles" "" "js,internal,info-leak"
}

_js_endpoints() {
    local ju="$1" body="$2" out="$3"
    # collect endpoints for the crawl pipeline
    grep -aoiE '"(/[a-zA-Z0-9_./?=&-]{2,})"' "$body" 2>/dev/null | tr -d '"' >> "$out"
    grep -aoiE 'https?://[a-zA-Z0-9_./?=&%-]+' "$body" 2>/dev/null >> "$out"
    # emit a finding for genuinely interesting endpoints
    local hi; hi=$(grep -aoiE '"/(admin|internal|api/(admin|internal|v[0-9]+/(users|accounts|token)))|/actuator|/graphql|/debug|/\.env)[a-zA-Z0-9_./-]*"' "$body" 2>/dev/null | tr -d '"' | sort -u | head -5)
    [[ -z "$hi" ]] && return 0
    local first; first=$(head -1 <<<"$hi")
    fe_emit jsanalysis js low firm "$ju" "Sensitive endpoint referenced in JavaScript" \
        "Client JS references a high-interest endpoint ($first)" \
        "$(jq -nc --arg u "$ju" --arg e "$first" '{script:$u,endpoint:$e}')" \
        "Confirm the endpoint enforces authorization" "" "js,endpoint,api"
}
