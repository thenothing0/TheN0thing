
### Advanced Reconnaissance Framework v8.8

[![Bash](https://img.shields.io/badge/Bash-4.4%2B-green?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey)](/)
[![Version](https://img.shields.io/badge/Version-8.8-red)](/)

**Automated reconnaissance pipeline — from target to report in one command.**

[Installation](#installation) •
[Quick Start](#quick-start) •
[Features](#features) •
[Usage](#usage) •
[Profiles](#profiles) •
[Plugins](#plugins) •
[Database](#database) •
[API Tokens](#api-tokens)

</div>

---

## Features

| Category | Capabilities |
|----------|-------------|
| **Subdomain Enumeration** | subfinder, amass, assetfinder, findomain, crt.sh, chaos, github-subdomains, rapiddns |
| **DNS Resolution** | massdns, dnsx, puredns bruteforce |
| **Port Scanning** | naabu, httpx fingerprinting |
| **Web Analysis** | gospider crawling, WAF detection, technology fingerprinting |
| **Vulnerability Scanning** | nuclei, subdomain takeover (subjack) |
| **Cloud Detection** | AWS S3, Azure Blob, GCP Storage, CloudFront, Heroku, Netlify, Vercel |
| **Reporting** | Markdown, JSON, HTML with dark theme |
| **Extras** | SQLite database, plugin system, scheduled scans, scan diffing, interactive mode |

---

## Installation

### Prerequisites

```bash
sudo apt update && sudo apt install -y bash curl jq
```
### Required Tools
```
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```
### Optional Tools (more = better results)
```
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest``
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/jaeles-project/gospider@latest
go install -v github.com/haccer/subjack@latest
go install -v github.com/gwen001/github-subdomains@latest
go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest

https://github.com/rapiddns/rapiddns-cli

sudo apt install -y amass findomain massdns whois wafw00f whatweb
```
### Setup
```
git clone https://github.com/yourusername/TheN0thing.git
cd TheN0thing
chmod +x TheN0thing.sh
./TheN0thing.sh --help
```
### Quick Start
### Single Domain
```
./TheN0thing.sh example.com
```
### Fast Scan
```
./TheN0thing.sh -f example.com
```
### Full Scan with Screenshots
```
./TheN0thing.sh -s -a example.com
```
### IP Address
```
./TheN0thing.sh --type ip 192.168.1.1
```
### ASN
```
./TheN0thing.sh --type asn AS13335
```
### Multiple Targets
```
cat targets.txt
# example.com
# test.com
# 192.168.1.1

./TheN0thing.sh --file targets.txt
```
### Usage
```
USAGE  TheN0thing.sh [OPTIONS] <target>

TARGET OPTIONS:
  <target>                  Domain, IP, or ASN (auto-detected)
  --type domain|ip|asn      Force target type
  --file FILE               Scan multiple targets from file

SCAN OPTIONS:
  -f, --fast                Skip active enumeration and deep scanning
  -s, --screenshot          Take screenshots of live URLs
  -a, --all-ports           Scan extended port list
  -p, --ports PORTS         Custom port list (e.g., 80,443,8080)
  -t, --threads NUM         Thread count (default: 100, max: 500)
  --rate-limit NUM          Requests per second (default: 150, max: 5000)
  --all-options             Extended ports + screenshots + debug logging

OUTPUT OPTIONS:
  -o, --output DIR          Output directory
  -v, --verbose             Debug logging
  --no-color                Disable colored output
  --log-level LEVEL         DEBUG|INFO|WARNING|ERROR|CRITICAL

PROFILE OPTIONS:
  --profile NAME            Use scan profile

SCOPE OPTIONS:
  --scope FILE              Include only in-scope targets
  --out-of-scope FILE       Exclude out-of-scope targets

NOTIFICATION OPTIONS:
  --notify slack|discord|telegram
  --webhook-url URL         Slack/Discord webhook
  --bot-token TOKEN         Telegram bot token
  --chat-id ID              Telegram chat ID

DATABASE OPTIONS:
  --db                      Enable SQLite tracking
  --db-history              Show scan history
  --db-assets [type]        Show discovered assets
  --db-query SQL            Run read-only SQL query

PLUGIN OPTIONS:
  --create-plugin NAME      Create plugin template
  --list-plugins            List installed plugins

SCHEDULE OPTIONS:
  --schedule 'CRON' TARGET  Schedule recurring scan
  --list-schedules          List scheduled scans
  --remove-schedule ID      Remove scheduled scan

OTHER OPTIONS:
  --resume DIR              Resume interrupted scan
  --diff OLD NEW            Compare two scan results
  --no-cache                Disable result caching
  --config FILE             Custom config file
  --interactive             Interactive mode
  --check-update            Check for updates
  --self-update             Update to latest version
  -h, --help                Show help
```
## Profiles

| Profile | Threads | Rate | Timeout | Use Case |
|---------|---------|------|---------|----------|
| `stealth` | 10 | 10 | 15s | Avoid detection |
| `passive` | 50 | 50 | 10s | No active probing |
| `default` | 100 | 150 | 5s | Balanced |
| `bounty` | 200 | 300 | 5s | Bug bounty |
| `aggressive` | 300 | 500 | 3s | Maximum speed |
| `ci` | 50 | 100 | 5s | CI/CD pipeline |

### Examples
```
./TheN0thing.sh --profile stealth example.com

./TheN0thing.sh --profile aggressive example.com

./TheN0thing.sh --profile bounty -s --db example.com

./TheN0thing.sh --profile passive example.com
```
### Scan Phases
```
Phase 1: Passive Enumeration
    ├── subfinder, amass, assetfinder, findomain
    ├── crt.sh certificate transparency
    ├── github-subdomains, chaos
    ├── rapiddns
    └── DNS resolution (massdns/dig)

Phase 2: Active Enumeration (skipped with -f)
    └── puredns bruteforce

Phase 3: Service Discovery
    ├── httpx fingerprinting
    └── IP/ASN enrichment

Phase 4: Deep Scanning (skipped with -f)
    ├── subjack takeover detection
    ├── dnsx DNS records
    ├── mapcidr CIDR aggregation
    ├── naabu port scanning
    └── gospider web crawling

Phase 5: Extended Analysis (skipped with -f)
    ├── WAF detection (wafw00f)
    ├── Technology detection (webanalyze/whatweb)
    ├── nuclei vulnerability scanning
    └── Cloud asset detection

Phase 6: Screenshots (with -s)
    └── gowitness/aquatone

Phase 7: Reporting
    ├── Markdown summary
    ├── JSON report
    └── HTML report (dark theme)
```
### Output Structure
```
output/example.com/
├── raw/
│   ├── subfinder.txt
│   ├── amass.txt
│   ├── assetfinder.txt
│   ├── crtsh.txt
│   ├── massdns.txt
│   └── ...
├── assets/
│   ├── subdomains/all.txt
│   ├── ips/all.txt
│   ├── asns/all.txt
│   └── cidrs/all.txt
├── processed/
│   ├── fingerprint.txt
│   ├── all_urls.txt
│   ├── open_ports.txt
│   ├── nuclei_results.txt
│   ├── subjack.txt
│   ├── cloud_assets.txt
│   ├── waf_results.txt
│   └── dnsx.json
├── screenshots/
├── reports/
│   ├── summary.md
│   ├── summary.json
│   └── report.html
└── .checkpoint
```
### API Tokens
Create ~/.config/user/api_tokens.conf:
```
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
CHAOS_KEY=xxxxxxxxxxxxxxxxxxxxxxxx
SHODAN_KEY=xxxxxxxxxxxxxxxxxxxxxxxx
CENSYS_API_ID=xxxxxxxx-xxxx-xxxx-xxxx
CENSYS_API_SECRET=xxxxxxxxxxxxxxxx
```
## Scope Files
### scope.txt
```
example.com
*.example.com
*.dev.example.com
```
### out-of-scope.txt
```
staging.example.com
*.internal.example.com
```
### Usage
```
./TheN0thing.sh --scope scope.txt --out-of-scope out-of-scope.txt example.com
```
## Notifications
### Slack
```
./TheN0thing.sh --notify slack \
    --webhook-url "https://hooks.slack.com/services/XXX/YYY/ZZZ" \
    example.com
```
### Discord
```
./TheN0thing.sh --notify discord \
    --webhook-url "https://discord.com/api/webhooks/XXX/YYY" \
    example.com
```
### Telegram
```
./TheN0thing.sh --notify telegram \
    --bot-token "123456:ABC-DEF" \
    --chat-id "-1001234567890" \
    example.com
```
## Database
### Enable
```
./TheN0thing.sh --db example.com
```
### View History
```
./TheN0thing.sh --db-history
```
### View Assets
```
./TheN0thing.sh --db-assets subdomain
./TheN0thing.sh --db-assets ip
./TheN0thing.sh --db-assets asn
./TheN0thing.sh --db-assets cidr
```
### Custom Query
```
./TheN0thing.sh --db-query "SELECT target,subdomains,live_urls FROM scans ORDER BY id DESC LIMIT 5"
```
## Plugins
### Create Plugin
```
./TheN0thing.sh --create-plugin my_plugin
```
### Plugin Template
```
# ~/.config/then0thing/plugins/my_plugin.sh

plugin_init() {
    log "INFO" "My plugin loaded"
}

plugin_post_passive() {
    local od="$1"
    # runs after passive enumeration
}

plugin_post_active() {
    local od="$1"
    # runs after active enumeration
}

plugin_post_scan() {
    local od="$1"
    # runs after all scanning
}

plugin_report() {
    local od="$1"
    # runs during report generation
}
```
### List Plugins
```
./TheN0thing.sh --list-plugins
```
## Scheduled Scans
### Create Schedule
```
# Daily at 2 AM
./TheN0thing.sh --schedule "0 2 * * *" example.com

# Weekly Monday at midnight with fast scan
./TheN0thing.sh --schedule "0 0 * * 1" example.com "-f --db"

# Every 6 hours
./TheN0thing.sh --schedule "0 */6 * * *" example.com "--profile bounty"
```
### Manage Schedules
```
./TheN0thing.sh --list-schedules
./TheN0thing.sh --remove-schedule abc12345
```
### Scan Diffing
```
# First scan
./TheN0thing.sh -o output/scan1 example.com

# Later scan
./TheN0thing.sh -o output/scan2 example.com

# Compare
./TheN0thing.sh --diff output/scan1 output/scan2
```
### Resume Interrupted Scan
```
./TheN0thing.sh --resume output/example.com example.com
```
## Interactive Mode
```
./TheN0thing.sh --interactive
```
```
N0> scan example.com
N0> scan-fast test.com
N0> scan-full target.com
N0> history
N0> assets subdomain
N0> plugins
N0> schedules
N0> config
N0> status
N0> exit
```
## Configuration
### Config File
~/.config/user/config.conf:
```
THREADS=100
TIMEOUT=5
MAX_RETRIES=3
RATE_LIMIT=150
WEB_PORTS=80,443,8080,8443,3000,8000,8081
LOG_LEVEL=INFO
```
### Custom Config
```
./TheN0thing.sh --config /path/to/custom.conf example.com
```
### Environment Variables
```
THREADS=200 RATE_LIMIT=300 ./TheN0thing.sh example.com
```
## Real-World Examples
### Bug Bounty — Full Recon
```
./TheN0thing.sh \
    --profile bounty \
    --scope scope.txt \
    --out-of-scope oos.txt \
    --notify slack --webhook-url "$SLACK_WEBHOOK" \
    --db \
    -s \
    -o output/bounty_$(date +%Y%m%d) \
    target.com
```
### CI/CD Pipeline
```
./TheN0thing.sh \
    --profile ci \
    --no-color \
    --file targets.txt \
    --db \
    -o output/ci_run
```
### Stealth Passive Only
```
./TheN0thing.sh \
    --profile passive \
    --no-cache \
    target.com
```
### Monitor for Changes
```
# Schedule daily diff
./TheN0thing.sh --schedule "0 3 * * *" target.com "-f --db"

# Manual diff
./TheN0thing.sh --diff output/yesterday output/today
```
### Multi-Target Corporate Recon
```
cat << 'EOF' > corps.txt
company.com
company.io
company.dev
company.cloud
EOF

./TheN0thing.sh \
    --file corps.txt \
    --profile aggressive \
    --db \
    --notify telegram --bot-token "$BOT" --chat-id "$CHAT" \
    -s -a
```
## Troubleshooting
env: 'bash\r': No such file or directory
```
sed -i 's/\r$//' TheN0thing.sh
```
### Permission Denied
```
chmod +x TheN0thing.sh
```
### Missing Tools
```
./TheN0thing.sh --help
# Shows which required tools are missing
# Only httpx, jq, and curl are required
# Everything else is optional
```
### Logs
```
ls ~/.config/then0thing/logs/
cat ~/.config/then0thing/logs/TheN0thing_*.log
```
### Cache Issues
```
./TheN0thing.sh --no-cache example.com
# Or clear cache manually
rm -rf ~/.config/then0thing/cache/
```
## Security Notes
API tokens stored with 600 permissions <p>
Tokens redacted from log files <p>
Plugin sandbox blocks dangerous operations <p>
Database queries are read-only for user input <p>
Webhook URLs must be HTTPS <p>
All notifications sanitized before sending <p>
Path traversal protection on all file operations <p>
No eval with user-controlled input <p>
## Project Structure
```
TheN0thing/
├── TheN0thing.sh          # Main script
├── README.md              # This file
├── LICENSE                 # MIT License
└── wordlist/
    ├── subdomains-top1million-5000.txt
    └── resolvers.txt
```
### Runtime Files
```
~/.config/then0thing/
├── config.conf            # Configuration
├── api_tokens.conf        # API keys
├── cache/                 # Result cache
├── db/                    # SQLite database
├── logs/                  # Log files
├── plugins/               # Plugin scripts
├── schedules/             # Scheduled scan configs
└── locks/                 # Scan locks
```
### MIT License

<div align="center">
Built for bug bounty hunters and security researchers.

</div> ```
