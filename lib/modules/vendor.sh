#!/usr/bin/env bash
# Module: vendor (Tier-2) — fingerprint exposed edge devices / appliances
# (Exchange/Citrix/F5/Fortinet/Pulse/PaloAlto/Cisco/VMware) and container / CI-CD
# infrastructure (Kubernetes, Docker registry, Vault, Consul, Grafana, …).
mod_vendor() {
    local od="$1"
    local urls="$od/processed/all_urls.txt"
    [[ -s "$urls" ]] || { log "INFO" "[vendor] no live URLs (skipped)"; return 0; }
    local rules="$TN_LIB_DIR/data/vendor_paths.txt"
    [[ -f "$rules" ]] || { log "WARNING" "[vendor] ruleset missing"; return 0; }
    probe_paths vendor "$urls" "$rules" "${VENDOR_MAX_HOSTS:-120}"
}
