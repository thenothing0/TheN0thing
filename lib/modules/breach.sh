#!/usr/bin/env bash
# Module: breach (Tier-2) — infostealer / breach exposure via HudsonRock's free
# Cavalier OSINT API (keyless). Flags credentials exposed by info-stealer logs.
mod_breach() {
    local od="$1" tgt="$2" tt="$3"
    [[ "$tt" == domain ]] || return 0
    [[ "${BREACH_ENABLE:-true}" == true ]] || return 0
    command -v curl >/dev/null 2>&1 || return 0
    local dom="$tgt" t; t=$(_mktmp brc) || return 0
    _ptimeout 40 curl -fsS -A "$_PR_UA" --max-time 30 --max-filesize "$MAX_RESPONSE_SIZE" \
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=${dom}" \
        -o "$t" 2>/dev/null || true
    [[ -s "$t" && "$(head -c1 "$t")" == "{" ]] || { rm -f "$t"; log "INFO" "[breach] no data"; return 0; }

    # schema is defensive: pull the first numeric value for each known key
    local emp usr total
    emp=$(jq -r 'first(.. | .employees? // empty | select(type=="number")) // 0' "$t" 2>/dev/null); emp="${emp//[^0-9]/}"
    usr=$(jq -r 'first(.. | .users? // empty | select(type=="number")) // 0' "$t" 2>/dev/null); usr="${usr//[^0-9]/}"
    total=$(jq -r 'first(.. | .total? // empty | select(type=="number")) // 0' "$t" 2>/dev/null); total="${total//[^0-9]/}"
    [[ "$emp" =~ ^[0-9]+$ ]] || emp=0; [[ "$usr" =~ ^[0-9]+$ ]] || usr=0; [[ "$total" =~ ^[0-9]+$ ]] || total=0
    rm -f "$t"

    if (( emp > 0 || usr > 0 || total > 0 )); then
        local sev=high; (( emp > 0 )) && sev=critical   # infected employees = internal compromise risk
        fe_emit breach breach "$sev" firm "$dom" "Infostealer-exposed credentials" \
            "HudsonRock reports credentials from info-stealer logs (employees: $emp, users: $usr, total: $total)" \
            "$(jq -nc --arg d "$dom" --argjson e "$emp" --argjson u "$usr" --argjson t "$total" \
                '{domain:$d,employees:$e,users:$u,total:$t,source:"hudsonrock-cavalier"}')" \
            "Force password resets; investigate infected endpoints; enforce MFA" \
            "https://www.hudsonrock.com/threat-intelligence-cybercrime-tools" \
            "breach,credentials,infostealer"
    fi
    return 0
}
