#!/usr/bin/env bash
# Module: exposure — always-on high-value path checks (.git/.env/actuator/…).
# Reads live URLs; emits findings via probe_paths. See lib/data/exposure_paths.txt.
mod_exposure() {
    local od="$1"
    local urls="$od/processed/all_urls.txt"
    [[ -s "$urls" ]] || { log "INFO" "[exposure] no live URLs (skipped)"; return 0; }
    local rules="$TN_LIB_DIR/data/exposure_paths.txt"
    [[ -f "$rules" ]] || { log "WARNING" "[exposure] ruleset missing"; return 0; }
    probe_paths exposure "$urls" "$rules" "${EXPOSURE_MAX_HOSTS:-150}"
}
