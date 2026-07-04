# Finding Schema

Every finding emitted into the Findings Engine is a JSON object with these
fields. Modules produce them via `fe_emit` (or `fe_emit_json`); the engine fills
defaults and computes `id` / `occurrences`.

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | `sha1(asset\|category\|title)[:12]` — dedup key |
| `asset` | string | host, URL, `host:port`, IP, or domain the finding is about |
| `category` | string | `exposure`,`secret`,`js`,`api`,`content`,`identity`,`vuln`,`origin`,`tls`,`wayback`,`email`,`dns`,`cloud`,`takeover`,`misc` |
| `title` | string | short, stable finding name (part of the dedup key) |
| `description` | string | human-readable detail |
| `severity` | enum | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `confidence` | enum | `confirmed` \| `firm` \| `tentative` |
| `evidence` | object | free-form JSON (url, status, snippet, match, …) |
| `remediation` | string | recommended fix (feeds the report's recommendations) |
| `references` | string[] | URLs (RFCs, advisories, docs) |
| `tags` | string[] | filterable labels |
| `detection_method` | string | module name(s) that produced it |
| `first_seen` / `last_seen` | ISO-8601 | run timestamps |
| `occurrences` | int | how many raw findings collapsed into this one (added at ingest) |

## Example

```json
{
  "id": "63115ab8b328",
  "asset": "https://api.example.com/.git/config",
  "category": "exposure",
  "title": "Git config exposed",
  "description": "Git config exposed at https://api.example.com/.git/config (HTTP 200)",
  "severity": "critical",
  "confidence": "confirmed",
  "evidence": {"url": "https://api.example.com/.git/config", "status": 200, "size": 380, "snippet": "[core] repositoryformatversion = 0 …"},
  "remediation": "Block web access to the .git directory",
  "references": [],
  "tags": ["exposure"],
  "detection_method": "exposure",
  "first_seen": "2026-07-04T10:00:00Z",
  "last_seen": "2026-07-04T10:00:00Z",
  "occurrences": 1
}
```

## Severity guidance

- **critical** — direct compromise / secret / RCE / world-readable data (`.env`, exposed `.git`, KEV CVE, open bucket with data, live private key).
- **high** — strong exposure or likely-exploitable (actuator env, zone transfer, subdomain takeover, expired cert on prod, DMARC missing).
- **medium** — meaningful weakness needing a specific condition (legacy TLS, GraphQL suggestions, third-party CNAME, sourcemap).
- **low** — hardening gap (MTA-STS absent, DKIM absent, DNSSEC off, admin panel reachable).
- **info** — intel/context, not itself a weakness (IdP in use, historical IP, tech fingerprint).

## Confidence guidance

- **confirmed** — body/behaviour proves it (regex matched the file, cert parsed, tool executed the finding).
- **firm** — strong signal, not byte-proven (status code + heuristic).
- **tentative** — candidate needing manual verification (soft-404 risk, takeover candidate).
