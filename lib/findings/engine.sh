#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════
# TheN0thing — Findings Engine  (pure bash + jq)
#
# The single pipeline every analysis module feeds into:
#   module  ──fe_emit──▶  findings/raw/<module>.jsonl   (one JSON finding/line)
#   fe_ingest  ─────────▶ findings/findings.json        (dedup, merge, rank)
#   fe_stats   ─────────▶ findings/stats.json           (counts + risk score)
#
# Contract: modules NEVER print findings to the console. They only call
# fe_emit / fe_emit_json. See lib/findings/SCHEMA.md for the finding schema.
#
# This file only DEFINES functions; it is sourced by TheN0thing.sh. It reuses
# the core helpers (log, _mktmp, _safe_jq) from the main script when available
# and degrades gracefully when sourced standalone (tests).
# ══════════════════════════════════════════════════════════════════════════

# Ordered severity + confidence vocabularies (higher = worse / stronger).
_fe_sevrank() { case "$1" in critical) echo 5;; high) echo 4;; medium) echo 3;; low) echo 2;; info) echo 1;; *) echo 0;; esac; }
_fe_confrank() { case "$1" in confirmed) echo 3;; firm) echo 2;; tentative) echo 1;; *) echo 0;; esac; }

# Fallback logger if the main script's log() is not loaded (standalone tests).
if ! declare -F log >/dev/null 2>&1; then
    log() { printf '%s [%s] %s\n' "$(date +%H:%M:%S 2>/dev/null)" "$1" "$2" >&2; }
fi

# fe_init <output_dir>
# Prepare the findings tree and export FINDINGS_DIR for the module run.
fe_init() {
    local od="$1"
    [[ -n "$od" ]] || return 1
    FINDINGS_DIR="$od/findings"
    export FINDINGS_DIR
    mkdir -p "$FINDINGS_DIR/raw" "$FINDINGS_DIR/evidence" 2>/dev/null || return 1
    # A stable per-run timestamp so re-emitted findings keep first_seen stable.
    FE_TS="${FE_TS:-$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date +%Y-%m-%dT%H:%M:%S)}"
    export FE_TS
    return 0
}

# _fe_id <asset> <category> <title>  ->  12-hex stable dedup id
_fe_id() {
    local key; key=$(printf '%s|%s|%s' "$1" "$2" "$3")
    if command -v sha1sum >/dev/null 2>&1; then
        printf '%s' "$key" | sha1sum 2>/dev/null | cut -c1-12
    elif command -v shasum >/dev/null 2>&1; then
        printf '%s' "$key" | shasum 2>/dev/null | cut -c1-12
    else
        printf '%s' "$key" | cksum | tr -d ' ' | cut -c1-12
    fi
}

# fe_emit  <module> <category> <severity> <confidence> <asset> <title> \
#          <description> [evidence_json] [remediation] [refs_csv] [tags_csv]
#
# Appends one canonical finding to findings/raw/<module>.jsonl.
# Severity: critical|high|medium|low|info   Confidence: confirmed|firm|tentative
fe_emit() {
    local module="$1" category="$2" severity="$3" confidence="$4" asset="$5" \
          title="$6" desc="${7:-}" remediation="${9:-}" refs="${10:-}" tags="${11:-}"
    # NB: do NOT write ${8:-{}} — bash closes the ${...} at the first '}' and
    # appends a stray '}', corrupting valid JSON evidence. Default explicitly.
    local evidence="${8:-}"; [[ -n "$evidence" ]] || evidence='{}'
    [[ -n "${FINDINGS_DIR:-}" ]] || { log "ERROR" "[findings] FINDINGS_DIR unset (fe_init not called)"; return 1; }
    [[ -n "$module" && -n "$category" && -n "$severity" && -n "$asset" && -n "$title" ]] || {
        log "WARNING" "[findings] fe_emit missing required field"; return 1; }
    case "$severity"   in critical|high|medium|low|info) ;; *) severity=info ;; esac
    case "$confidence" in confirmed|firm|tentative) ;; *) confidence=tentative ;; esac
    # evidence must be valid JSON; otherwise coerce to a string field.
    printf '%s' "$evidence" | jq -e . >/dev/null 2>&1 || \
        evidence=$(jq -nc --arg v "$evidence" '{note:$v}')
    local id; id=$(_fe_id "$asset" "$category" "$title")
    local safe_mod="${module//[^a-zA-Z0-9_-]/_}"
    jq -nc \
        --arg id "$id" --arg asset "$asset" --arg category "$category" \
        --arg title "$title" --arg description "$desc" --arg severity "$severity" \
        --arg confidence "$confidence" --argjson evidence "$evidence" \
        --arg remediation "$remediation" --arg method "$module" \
        --arg ts "${FE_TS:-}" --arg refs "$refs" --arg tags "$tags" \
        '{
           id:$id, asset:$asset, category:$category, title:$title,
           description:$description, severity:$severity, confidence:$confidence,
           evidence:$evidence, remediation:$remediation,
           references:($refs|split(",")|map(select(length>0))),
           tags:($tags|split(",")|map(select(length>0))),
           detection_method:$method, first_seen:$ts, last_seen:$ts
         }' >> "$FINDINGS_DIR/raw/${safe_mod}.jsonl" 2>/dev/null || {
        log "WARNING" "[findings] fe_emit failed for $module/$title"; return 1; }
    return 0
}

# fe_emit_json <module> <finding_json>
# For modules that assemble their own object; missing fields are filled in.
fe_emit_json() {
    local module="$1" obj="$2"
    [[ -n "${FINDINGS_DIR:-}" ]] || return 1
    printf '%s' "$obj" | jq -e . >/dev/null 2>&1 || { log "WARNING" "[findings] fe_emit_json: bad JSON from $module"; return 1; }
    local safe_mod="${module//[^a-zA-Z0-9_-]/_}"
    printf '%s' "$obj" | jq -c \
        --arg method "$module" --arg ts "${FE_TS:-}" '
        {
          asset: (.asset // "unknown"),
          category: (.category // "misc"),
          title: (.title // "untitled"),
          description: (.description // ""),
          severity: (.severity // "info"),
          confidence: (.confidence // "tentative"),
          evidence: (.evidence // {}),
          remediation: (.remediation // ""),
          references: (.references // []),
          tags: (.tags // []),
          detection_method: (.detection_method // $method),
          first_seen: (.first_seen // $ts),
          last_seen: (.last_seen // $ts)
        }
        | . + {id: (.asset + "|" + .category + "|" + .title)}' 2>/dev/null | \
    while IFS= read -r line; do
        # recompute a short id hash from the composite key
        local key id
        key=$(printf '%s' "$line" | jq -r '.id')
        id=$(_fe_id "${key%%|*}" "$(printf '%s' "$key" | cut -d'|' -f2)" "${key##*|}")
        printf '%s' "$line" | jq -c --arg id "$id" '.id=$id' >> "$FINDINGS_DIR/raw/${safe_mod}.jsonl"
    done
    return 0
}

# fe_ingest <output_dir>
# Merge every raw/*.jsonl into a single deduplicated, severity-ranked array.
# Duplicates (same id) collapse: highest severity/confidence wins, evidence and
# references/tags/detection_methods union, occurrence count recorded.
fe_ingest() {
    local od="${1:?}"; local raw="$od/findings/raw"
    mkdir -p "$od/findings"
    local out="$od/findings/findings.json" outl="$od/findings/findings.jsonl"
    if ! compgen -G "$raw/*.jsonl" >/dev/null 2>&1; then
        printf '[]\n' > "$out"; : > "$outl"; return 0
    fi
    cat "$raw"/*.jsonl 2>/dev/null | jq -s '
      def sevrank(s): {critical:5,high:4,medium:3,low:2,info:1}[s] // 0;
      def confrank(c): {confirmed:3,firm:2,tentative:1}[c] // 0;
      map(select(type=="object" and .id))
      | group_by(.id)
      | map(
          (sort_by(sevrank(.severity), confrank(.confidence)) | last) as $rep
          | $rep + {
              evidence: ([.[].evidence] | add // $rep.evidence),
              references: ([.[].references[]?] | unique),
              tags: ([.[].tags[]?] | unique),
              detection_method: ([.[].detection_method] | unique | join(",")),
              first_seen: ([.[].first_seen] | min),
              last_seen: ([.[].last_seen] | max),
              occurrences: length
            }
        )
      | sort_by(-sevrank(.severity), -confrank(.confidence), .asset, .title)
    ' > "$out" 2>/dev/null || { printf '[]\n' > "$out"; }
    jq -c '.[]' "$out" 2>/dev/null > "$outl" || : > "$outl"
    local n; n=$(jq 'length' "$out" 2>/dev/null || echo 0)
    log "SUCCESS" "[findings] $n unique finding(s) -> $out"
    return 0
}

# fe_stats <output_dir>
# Produce findings/stats.json: totals, per-severity, per-category, per-asset,
# and a 0-100 risk score (weighted, capped).
fe_stats() {
    local od="${1:?}"; local f="$od/findings/findings.json"
    [[ -f "$f" ]] || return 1
    jq '
      def w(s): {critical:40,high:10,medium:4,low:1,info:0}[s] // 0;
      {
        total: length,
        by_severity: (reduce .[] as $x ({critical:0,high:0,medium:0,low:0,info:0};
                        .[$x.severity] += 1)),
        by_category: (reduce .[] as $x ({}; .[$x.category] += 1)),
        by_asset:    (reduce .[] as $x ({}; .[$x.asset] += 1)),
        risk_score:  ([.[] | w(.severity)] | add // 0 | if . > 100 then 100 else . end),
        risk_rating: ( ([.[] | w(.severity)] | add // 0) as $s
                       | if   $s >= 40 then "critical"
                         elif $s >= 15 then "high"
                         elif $s >= 5  then "medium"
                         elif $s >  0  then "low"
                         else "clean" end )
      }' "$f" > "$od/findings/stats.json" 2>/dev/null || return 1
    return 0
}
