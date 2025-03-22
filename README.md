# TheN0thing - Enhanced Enumeration Tool

An advanced reconnaissance and asset discovery tool that helps security professionals identify and categorize network assets including domains, IPs, ASNs, and CIDR ranges.

## Features

- **Multi-target support**: Enumerate domains, IP addresses, IP ranges (CIDR), and ASNs
- **Asset categorization**: Automatically separate and organize findings into subdomains, IPs, ASNs, and CIDR ranges
- **Passive reconnaissance**: Utilize multiple tools to gather information without directly interacting with the target
- **Active reconnaissance**: Perform DNS bruteforcing, web service discovery, and content discovery
- **Service fingerprinting**: Identify and fingerprint web services with detailed metadata
- **Reporting**: Generate comprehensive reports in both Markdown and HTML formats

## Installation

### Prerequisites

TheN0thing requires the following tools to be installed:

- subfinder
- amass
- assetfinder
- findomain
- httpx
- anew
- jq
- curl
- puredns
- shuffledns
- gospider
- sublist3r
- whois
- ipinfo
- asnmap
- dig

You can install most of these tools using Go:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/jaeles-project/gospider@latest
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
```bash



For other tools like findomain, sublist3r, and ipinfo, follow their respective installation instructions.
Installation

Clone the repository:
git clone https://github.com/yourusername/thenothing.git
cd thenothing

Make the script executable:
chmod +x thenothing.sh

(Optional) Create a configuration file for API keys:
cat > ~/.subenum_config << EOF
GITHUB_TOKEN="your_github_token"
CHAOS_KEY="your_chaos_key"
GITLAB_TOKEN="your_gitlab_token"
SHODAN_KEY="your_shodan_key"
CENSYS_API_ID="your_censys_id"
CENSYS_API_SECRET="your_censys_secret"
VIRUSTOTAL_API_KEY="your_virustotal_key"
SPYSE_API_TOKEN="your_spyse_token"
EOF


Usage
Basic Usage
./thenothing.sh [options] <target>
Where <target> can be:

A domain name (e.g., example.com)
An IP address (e.g., 192.168.1.1)
An IP range in CIDR notation (e.g., 192.168.1.0/24)
An ASN (e.g., AS15169)

Options
Options:
  -o, --output DIR     Output directory (default: output/<target>)
  -w, --wordlist FILE  Custom wordlist for bruteforce
  -r, --resolvers FILE Custom resolvers file
  -t, --threads NUM    Number of threads (default: 50)
  -p, --ports PORTS    Ports to scan (default: common web ports)
  -a, --all-ports      Use extended port list
  -s, --screenshot     Take screenshots of discovered web services
  -f, --fast           Fast mode - skip intensive operations
  -v, --verbose        Verbose output
  -h, --help           Show this help message and exit
  --type TYPE          Specify target type (domain, ip, asn) - auto-detect if not specified
Examples

Basic domain enumeration:
./thenothing.sh example.com

IP enumeration with screenshots:
./thenothing.sh -s 192.168.1.1

ASN enumeration with custom output directory:
./thenothing.sh -o custom_output AS15169

Fast domain enumeration with custom wordlist:
./thenothing.sh -f -w path/to/wordlist.txt example.com

Domain scan with extended port list:
./thenothing.sh -a example.com

IP range scan with more threads:
./thenothing.sh -t 100 192.168.1.0/24


Output Structure
The tool organizes results in the following directory structure:
output/target/
├── assets/
│   ├── asns/
│   │   └── all.txt
│   ├── cidrs/
│   │   └── all.txt
│   ├── ips/
│   │   └── all.txt
│   └── subdomains/
│       └── all.txt
├── processed/
│   ├── all_urls.txt
│   ├── ip_fingerprint.txt
│   ├── ip_urls.txt
│   ├── subdomain_fingerprint.txt
│   ├── subdomain_urls.txt
│   └── spider/
├── raw/
│   ├── amass.txt
│   ├── asn_details.txt
│   ├── asn_info.txt
│   ├── assetfinder.txt
│   ├── findomain.txt
│   ├── ip_metadata.txt
│   ├── puredns.txt
│   ├── reverse_dns.txt
│   ├── shuffledns.txt
│   └── subfinder.txt
├── reports/
│   ├── summary_report.html
│   └── summary_report.md
└── screenshots/
Reports
TheN0thing generates two types of reports:

Markdown Report (reports/summary_report.md): A simple text-based report with summary information.
HTML Report (reports/summary_report.html): A more visually appealing report that can be opened in any web browser.

Both reports include:

Summary statistics
List of discovered assets
Live web services
Suggested next steps

API Integration
TheN0thing can integrate with various security and reconnaissance APIs to enhance its capabilities. Configure your API keys in the ~/.subenum_config file to enable these integrations.
Supported APIs:

GitHub
CHAOS
GitLab
Shodan
Censys
VirusTotal
Spyse

Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
License
This project is licensed under the MIT License - see the LICENSE file for details.
Disclaimer
TheN0thing is designed for legitimate security testing and reconnaissance purposes only. Always ensure you have proper authorization before scanning any systems or networks. Unauthorized scanning may violate laws and regulations.
This README.md provides comprehensive information about "TheN0thing" tool, including:

1. An overview of its features
2. Installation instructions for all prerequisites
3. Configuration steps for API keys
4. Detailed usage instructions with command options and examples
5. Explanation of the output structure
6. Information about the reports generated
7. API integration details
8. Contributing guidelines and disclaimers

The documentation should help users understand how to properly install, configure, and use the tool for various reconnaissance tasks.
