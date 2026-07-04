#!/usr/bin/env bash
# Module: pkgintel (Tier-2) — package-registry intelligence.
# Extracts package names referenced by the target's JS/manifests, checks the
# public npm / PyPI registries, and flags dependency-confusion risk (a private-
# looking package name that is UNCLAIMED on the public registry) plus obvious
# typosquat neighbours that already exist.
mod_pkgintel() {
    local od="$1" tgt="$2"
    command -v curl >/dev/null 2>&1 || return 0
    local names; names=$(_mktmp pkgn) || return 0

    # ── npm: scoped names + package.json deps found during discovery ──
    { grep -rhoiE '@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]+' \
        "$od/processed/js_endpoints.txt" "$od/processed/spider_urls.txt" 2>/dev/null
      # package.json / composer.json bodies the crawler saved
      for f in "$od"/processed/*package*.json "$od"/processed/*composer*.json; do
          [[ -f "$f" ]] && jq -r '(.dependencies//{}),(.devDependencies//{}) | keys[]?' "$f" 2>/dev/null
      done
    } 2>/dev/null | tr 'A-Z' 'a-z' | sort -u | grep -E '^@?[a-z0-9]' | head -n "${PKG_MAX:-60}" > "$names"

    # brand-scoped guesses from the target (dependency-confusion bait names)
    local brand="${tgt%%.*}"
    [[ "$brand" =~ ^[a-z0-9-]+$ ]] && printf '@%s/app\n@%s/core\n@%s/utils\n@%s/ui\n%s-utils\n%s-core\n' \
        "$brand" "$brand" "$brand" "$brand" "$brand" "$brand" >> "$names"
    sort -u "$names" -o "$names" 2>/dev/null
    [[ -s "$names" ]] || { rm -f "$names"; log "INFO" "[pkgintel] no package names (skipped)"; return 0; }
    log "INFO" "[pkgintel] checking $(wc -l < "$names") npm package name(s)"

    local pkg code
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        [[ "$pkg" =~ ^@?[a-z0-9][a-z0-9._/-]*$ ]] || continue
        local enc; enc=$(_url_encode "$pkg")
        code=$(curl -sk -A "$_PR_UA" --max-time 8 -o /dev/null -w '%{http_code}' \
            "https://registry.npmjs.org/${enc}" 2>/dev/null)
        # A scoped @brand/* name that is UNCLAIMED (404) is a dependency-confusion risk.
        if [[ "$pkg" == @* && "$code" == 404 ]]; then
            fe_emit pkgintel supplychain medium tentative "npm:$pkg" \
                "Unclaimed scoped npm package (dependency-confusion risk)" \
                "Scoped package '$pkg' is referenced but not published to public npm — an attacker could publish it" \
                "$(jq -nc --arg p "$pkg" '{registry:"npm",package:$p,status:"unclaimed"}')" \
                "Publish/claim the scope, or pin an internal registry + scope config" \
                "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610" \
                "supplychain,npm,dependency-confusion"
        fi
    done < "$names"
    rm -f "$names"
    return 0
}
