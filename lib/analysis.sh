#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════
# TheN0thing — Analysis phase orchestrator.
# Runs every analysis module (each emits into the Findings Engine), then
# ingests + scores + renders. This is the single entry point the main pipeline
# calls for the Discovery→Analysis→Findings→Prioritization→Reporting flow.
# ══════════════════════════════════════════════════════════════════════════

# Guard wrapper: a failing module must never abort the analysis phase.
_analysis_run_one() {
    local label="$1"; shift
    local t0=$SECONDS
    "$@" || log "WARNING" "[analysis] module '$label' errored (continuing)"
    log "DEBUG" "[analysis] $label done in $(( SECONDS - t0 ))s"
}

# run_analysis <output_dir> <target> <target_type>
run_analysis() {
    local od="$1" tgt="$2" tt="$3"
    declare -F fe_init >/dev/null 2>&1 || { log "ERROR" "[analysis] Findings Engine not loaded"; return 1; }
    fe_init "$od" || { log "ERROR" "[analysis] fe_init failed"; return 1; }
    log "INFO" "[analysis] running Findings Engine modules"

    # Cheap / DNS-based first, then HTTP-heavy, then enrichment.
    _analysis_run_one normalize     mod_normalize     "$od" "$tgt" "$tt"
    _analysis_run_one emailsec      mod_emailsec      "$od" "$tgt" "$tt"
    _analysis_run_one identity      mod_identity      "$od" "$tgt" "$tt"
    [[ "${ANALYSIS_SKIP_WAYBACK:-false}" == true ]] || \
        _analysis_run_one wayback   mod_wayback_intel "$od" "$tgt" "$tt"
    _analysis_run_one exposure      mod_exposure      "$od" "$tgt" "$tt"
    _analysis_run_one vendor        mod_vendor        "$od" "$tgt" "$tt"   # Tier-2
    _analysis_run_one apidiscovery  mod_apidiscovery  "$od" "$tgt" "$tt"
    _analysis_run_one jsanalysis    mod_jsanalysis    "$od" "$tgt" "$tt"
    _analysis_run_one secrets       mod_secrets       "$od" "$tgt" "$tt"
    _analysis_run_one contentbrute  mod_contentbrute  "$od" "$tgt" "$tt"
    _analysis_run_one firebase      mod_firebase      "$od" "$tgt" "$tt"   # Tier-2
    _analysis_run_one gfpatterns    mod_gfpatterns    "$od" "$tgt" "$tt"   # Tier-2 (uses ~/.gf)
    _analysis_run_one tls           mod_tls           "$od" "$tgt" "$tt"
    _analysis_run_one origin        mod_origin        "$od" "$tgt" "$tt"
    _analysis_run_one netintel      mod_netintel      "$od" "$tgt" "$tt"   # Tier-2
    _analysis_run_one breach        mod_breach        "$od" "$tgt" "$tt"   # Tier-2
    _analysis_run_one pkgintel      mod_pkgintel      "$od" "$tgt" "$tt"   # Tier-2
    _analysis_run_one githubdork    mod_githubdork    "$od" "$tgt" "$tt"   # Tier-2 (needs GITHUB_TOKEN)
    _analysis_run_one postman       mod_postman       "$od" "$tgt" "$tt"   # Tier-2
    _analysis_run_one mobile        mod_mobile        "$od" "$tgt" "$tt"   # Tier-2
    _analysis_run_one vulnprio      mod_vulnprio      "$od" "$tgt" "$tt"

    declare -F run_plugins >/dev/null 2>&1 && run_plugins "post_analysis" "$od"

    fe_ingest "$od"
    fe_stats  "$od"
    declare -F render_findings_report >/dev/null 2>&1 && render_findings_report "$od" "$tgt" "$tt"

    local n risk rating
    n=$(jq 'length' "$od/findings/findings.json" 2>/dev/null || echo 0)
    risk=$(jq -r '.risk_score // 0' "$od/findings/stats.json" 2>/dev/null || echo 0)
    rating=$(jq -r '.risk_rating // "clean"' "$od/findings/stats.json" 2>/dev/null || echo clean)
    log "SUCCESS" "[analysis] $n finding(s) — risk $risk ($rating)"
    declare -F notify_finding >/dev/null 2>&1 && (( n > 0 )) && \
        notify_finding "INFO" "$n findings, risk $risk ($rating) for $tgt"
    return 0
}
