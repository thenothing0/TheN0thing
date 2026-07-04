#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════
# TheN0thing — Findings report renderer.
# Consumes findings/findings.json + findings/stats.json and produces:
#   reports/findings.json   (composed machine report)
#   reports/findings.md     (Markdown)
#   reports/findings.html   (professional dark-theme, severity-ranked)
# ══════════════════════════════════════════════════════════════════════════

render_findings_report() {
    local od="$1" tgt="$2" tt="$3"
    local ff="$od/findings/findings.json" sf="$od/findings/stats.json"
    [[ -f "$ff" ]] || return 0
    [[ -f "$sf" ]] || printf '{}' > "$sf"
    mkdir -p "$od/reports"
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date +%Y-%m-%dT%H:%M:%S)

    # ── composed machine report ──
    jq -n --slurpfile f "$ff" --slurpfile s "$sf" \
        --arg tool TheN0thing --arg ver "${VERSION:-10.x}" --arg tgt "$tgt" \
        --arg tt "$tt" --arg ts "$ts" \
        '{meta:{tool:$tool,version:$ver,target:$tgt,type:$tt,generated:$ts},
          stats:($s[0] // {}), findings:($f[0] // [])}' \
        > "$od/reports/findings.json" 2>/dev/null || true

    _render_md   "$od" "$tgt" "$tt" "$ts"
    _render_html "$od" "$tgt" "$tt" "$ts"
    log "SUCCESS" "[report] findings.{json,md,html} -> $od/reports"
}

_render_md() {
    local od="$1" tgt="$2" tt="$3" ts="$4"
    local ff="$od/findings/findings.json" sf="$od/findings/stats.json"
    local md="$od/reports/findings.md"
    local total risk rating
    total=$(jq -r '.total // 0' "$sf"); risk=$(jq -r '.risk_score // 0' "$sf")
    rating=$(jq -r '.risk_rating // "clean"' "$sf")
    {
        printf '# Attack-Surface Findings — `%s` (%s)\n\n' "$tgt" "$tt"
        printf '_Generated %s by TheN0thing v%s_\n\n' "$ts" "${VERSION:-10.x}"
        printf '## Executive Summary\n\n'
        printf '**Risk score:** %s / 100 (**%s**)  ·  **Total findings:** %s\n\n' "$risk" "$rating" "$total"
        printf '| Severity | Count |\n|----------|------:|\n'
        local s
        for s in critical high medium low info; do
            printf '| %s | %s |\n' "$s" "$(jq -r --arg s "$s" '.by_severity[$s] // 0' "$sf")"
        done
        printf '\n## Findings by Severity\n\n'
        jq -r '.[] |
            "### [" + (.severity|ascii_upcase) + "] " + .title + "\n" +
            "- **Asset:** `" + .asset + "`\n" +
            "- **Category:** " + .category + "  ·  **Confidence:** " + .confidence +
            "  ·  **Detection:** " + .detection_method +
            (if .occurrences and .occurrences>1 then "  ·  **Occurrences:** " + (.occurrences|tostring) else "" end) + "\n" +
            (if .description!="" then "\n" + .description + "\n" else "" end) +
            (if (.references|length)>0 then "\n_References:_ " + (.references|join(", ")) + "\n" else "" end) +
            (if .remediation!="" then "\n**Remediation:** " + .remediation + "\n" else "" end) + "\n"' "$ff" 2>/dev/null
        printf '## Prioritized Recommendations\n\n'
        jq -r '[.[]|select(.remediation!="")|{s:.severity,r:.remediation}]
               | unique_by(.r)
               | sort_by({critical:0,high:1,medium:2,low:3,info:4}[.s])
               | .[] | "- [" + (.s|ascii_upcase) + "] " + .r' "$ff" 2>/dev/null
    } > "$md"
}

_render_html() {
    local od="$1" tgt="$2" tt="$3" ts="$4"
    local ff="$od/findings/findings.json" sf="$od/findings/stats.json"
    local html="$od/reports/findings.html"
    local total risk rating
    total=$(jq -r '.total // 0' "$sf"); risk=$(jq -r '.risk_score // 0' "$sf")
    rating=$(jq -r '.risk_rating // "clean"' "$sf")
    local c_crit c_high c_med c_low c_info
    c_crit=$(jq -r '.by_severity.critical // 0' "$sf"); c_high=$(jq -r '.by_severity.high // 0' "$sf")
    c_med=$(jq -r '.by_severity.medium // 0' "$sf"); c_low=$(jq -r '.by_severity.low // 0' "$sf")
    c_info=$(jq -r '.by_severity.info // 0' "$sf")

    # finding cards (jq builds escaped HTML)
    local cards; cards=$(jq -r '
        def esc: (. // "") | tostring | gsub("&";"&amp;")|gsub("<";"&lt;")|gsub(">";"&gt;");
        .[] |
        "<div class=\"card sev-" + .severity + "\">" +
        "<div class=\"chead\"><span class=\"badge " + .severity + "\">" + (.severity|ascii_upcase) + "</span>" +
        "<span class=\"title\">" + (.title|esc) + "</span>" +
        "<span class=\"conf\">" + (.confidence|esc) + "</span></div>" +
        "<div class=\"asset\">" + (.asset|esc) + "</div>" +
        "<div class=\"desc\">" + (.description|esc) + "</div>" +
        "<div class=\"meta\">category: " + (.category|esc) + " · detection: " + (.detection_method|esc) +
        (if .occurrences and .occurrences>1 then " · seen " + (.occurrences|tostring) + "×" else "" end) +
        (if (.tags|length)>0 then " · tags: " + ((.tags|join(", "))|esc) else "" end) + "</div>" +
        (if (.evidence|length)>0 then "<pre class=\"ev\">" + ((.evidence|tojson)|esc) + "</pre>" else "" end) +
        (if .remediation!="" then "<div class=\"rem\"><b>Remediation:</b> " + (.remediation|esc) + "</div>" else "" end) +
        (if (.references|length)>0 then "<div class=\"refs\">" + ([.references[]|"<a href=\""+.+"\">"+.+"</a>"]|join(" ")) + "</div>" else "" end) +
        "</div>"' "$ff" 2>/dev/null)

    cat > "$html" <<HTMLHEAD
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TheN0thing — Findings: ${tgt}</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--bd:#30363d;--fg:#c9d1d9;--mut:#8b949e;
--crit:#f85149;--high:#ff7b00;--med:#d29922;--low:#3fb950;--info:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 4px}.sub{color:var(--mut);margin:0 0 20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin:16px 0}
.stat{background:var(--panel);border:1px solid var(--bd);border-radius:8px;padding:14px;text-align:center}
.stat .n{font-size:26px;font-weight:700}.stat .l{color:var(--mut);font-size:12px;text-transform:uppercase}
.risk{font-size:40px;font-weight:800}
.rating-critical{color:var(--crit)}.rating-high{color:var(--high)}.rating-medium{color:var(--med)}
.rating-low{color:var(--low)}.rating-clean{color:var(--low)}
.n.critical{color:var(--crit)}.n.high{color:var(--high)}.n.medium{color:var(--med)}
.n.low{color:var(--low)}.n.info{color:var(--info)}
.card{background:var(--panel);border:1px solid var(--bd);border-left-width:4px;border-radius:8px;padding:14px;margin:10px 0}
.sev-critical{border-left-color:var(--crit)}.sev-high{border-left-color:var(--high)}
.sev-medium{border-left-color:var(--med)}.sev-low{border-left-color:var(--low)}.sev-info{border-left-color:var(--info)}
.chead{display:flex;align-items:center;gap:10px}.title{font-weight:600;flex:1}
.conf{color:var(--mut);font-size:12px}
.badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;color:#0d1117}
.badge.critical{background:var(--crit)}.badge.high{background:var(--high)}.badge.medium{background:var(--med)}
.badge.low{background:var(--low)}.badge.info{background:var(--info)}
.asset{color:var(--info);font-family:ui-monospace,Menlo,monospace;font-size:12px;margin:6px 0;word-break:break-all}
.desc{margin:6px 0}.meta{color:var(--mut);font-size:12px;margin:6px 0}
pre.ev{background:#0d1117;border:1px solid var(--bd);border-radius:6px;padding:8px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-all}
.rem{margin-top:8px}.refs a{color:var(--info);font-size:12px;margin-right:8px}
h2{border-bottom:1px solid var(--bd);padding-bottom:6px;margin-top:28px}
footer{color:var(--mut);text-align:center;margin:30px 0;font-size:12px}
</style></head><body><div class="wrap">
<h1>Attack-Surface Findings — ${tgt}</h1>
<p class="sub">${tt} · generated ${ts} · TheN0thing v${VERSION:-10.x}</p>
<div class="grid">
<div class="stat"><div class="risk rating-${rating}">${risk}</div><div class="l">risk / 100 (${rating})</div></div>
<div class="stat"><div class="n critical">${c_crit}</div><div class="l">critical</div></div>
<div class="stat"><div class="n high">${c_high}</div><div class="l">high</div></div>
<div class="stat"><div class="n medium">${c_med}</div><div class="l">medium</div></div>
<div class="stat"><div class="n low">${c_low}</div><div class="l">low</div></div>
<div class="stat"><div class="n info">${c_info}</div><div class="l">info</div></div>
</div>
<h2>Findings (${total})</h2>
HTMLHEAD
    printf '%s\n' "$cards" >> "$html"
    printf '<footer>TheN0thing v%s · %s findings · risk %s/100</footer>\n</div></body></html>\n' \
        "${VERSION:-10.x}" "$total" "$risk" >> "$html"
}
