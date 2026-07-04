#!/usr/bin/env bash
# Module: identity — external identity-fabric mapping (Entra/Okta/ADFS/Google/
# SAML/OIDC) correlated to the target domain and discovered hosts.
mod_identity() {
    local od="$1" tgt="$2" tt="$3"
    [[ "$tt" == domain ]] || return 0
    command -v curl >/dev/null 2>&1 || { log "WARNING" "[identity] curl missing"; return 0; }
    local dom="$tgt"

    # ── Microsoft Entra ID / Microsoft 365 (getuserrealm) ──
    local realm; realm=$(curl -sk -A "$_PR_UA" --max-time 12 \
        "https://login.microsoftonline.com/getuserrealm.srf?login=user@${dom}&xml=1" 2>/dev/null)
    local nst; nst=$(grep -oiE 'NameSpaceType="[A-Za-z]+"' <<<"$realm" | head -1 | cut -d'"' -f2)
    case "$nst" in
        Managed)
            local brand; brand=$(grep -oiE 'FederationBrandName>[^<]*' <<<"$realm" | head -1 | cut -d'>' -f2)
            fe_emit identity identity info firm "$dom" "Microsoft 365 / Entra ID (Managed)" \
                "Domain is a Managed Microsoft 365 / Entra ID tenant${brand:+ — $brand}" \
                "$(jq -nc --arg d "$dom" --arg b "${brand:-}" '{domain:$d,idp:"entra",type:"managed",brand:$b}')" \
                "" "https://learn.microsoft.com/entra/" "identity,entra,m365" ;;
        Federated)
            local authurl; authurl=$(grep -oiE 'AuthURL>[^<]*' <<<"$realm" | head -1 | cut -d'>' -f2)
            fe_emit identity identity low firm "$dom" "Microsoft 365 (Federated)" \
                "Domain federates authentication to an external IdP${authurl:+ ($authurl)}" \
                "$(jq -nc --arg d "$dom" --arg a "${authurl:-}" '{domain:$d,idp:"entra",type:"federated",auth_url:$a}')" \
                "" "" "identity,entra,federation" ;;
    esac

    # ── Google Workspace (MX → google) ──
    if command -v dig >/dev/null 2>&1 && dig +short MX "$dom" 2>/dev/null | grep -qiE 'aspmx.*google|googlemail'; then
        fe_emit identity identity info firm "$dom" "Google Workspace in use" \
            "MX records point to Google Workspace" \
            "$(jq -nc --arg d "$dom" '{domain:$d,idp:"google"}')" "" "" "identity,google"
    fi

    # ── Okta (subdomain patterns + tenant probe) ──
    local okta_host
    okta_host=$(grep -oiE '[a-z0-9-]+\.(okta|oktapreview)\.com' "$od/assets/subdomains/all.txt" 2>/dev/null | head -1)
    if [[ -z "$okta_host" ]]; then
        local slug="${dom%%.*}"
        if curl -sk -A "$_PR_UA" --max-time 10 "https://${slug}.okta.com/.well-known/openid-configuration" 2>/dev/null | grep -qi 'issuer'; then
            okta_host="${slug}.okta.com"
        fi
    fi
    [[ -n "$okta_host" ]] && fe_emit identity identity info firm "$okta_host" "Okta tenant identified" \
        "Okta identity tenant associated with the target" \
        "$(jq -nc --arg h "$okta_host" '{tenant:$h,idp:"okta"}')" "" "" "identity,okta"

    # ── ADFS / SAML metadata on discovered hosts ──
    local hosts; hosts=$(_mktmp idh) || return 0
    { printf 'adfs.%s\nsts.%s\nfs.%s\n' "$dom" "$dom" "$dom"
      grep -iE '^(adfs|sts|fs|login|sso|auth|idp)\.' "$od/assets/subdomains/all.txt" 2>/dev/null
    } | sort -u | head -n "${IDENTITY_MAX_HOSTS:-20}" > "$hosts"
    local h path
    while IFS= read -r h; do
        [[ -z "$h" ]] && continue
        for path in /FederationMetadata/2007-06/FederationMetadata.xml /adfs/ls/idpinitiatedsignon /saml/metadata /simplesaml/saml2/idp/metadata.php; do
            local body code
            body=$(_mktmp idm) || continue
            code=$(curl -sk -A "$_PR_UA" --max-time 8 -o "$body" -w '%{http_code}' "https://${h}${path}" 2>/dev/null)
            if [[ "$code" == 200 ]] && grep -qiE 'EntityDescriptor|federationmetadata|idpinitiatedsignon|SingleSignOnService' "$body" 2>/dev/null; then
                local kind="SAML metadata"; grep -qi idpinitiatedsignon <<<"$path" && kind="ADFS sign-on"
                fe_emit identity identity low firm "https://${h}${path}" "$kind exposed" \
                    "Identity provider metadata/endpoint reachable at ${h}${path}" \
                    "$(jq -nc --arg u "https://${h}${path}" '{url:$u,idp:"saml/adfs"}')" \
                    "Restrict metadata exposure if not required" "" "identity,saml,adfs"
                rm -f "$body"; break
            fi
            rm -f "$body"
        done
    done < "$hosts"
    rm -f "$hosts"
    return 0
}
