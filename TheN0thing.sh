#!/usr/bin/env bash
# TheN0thing - Enhanced Enumeration Tool
# Improved version with separation of IPs, ASNs, and subdomains
# Added features: file import and all options mode
# Modified: Removed Wayback Machine and VirusTotal integrations

### Colors
yellow='\033[1;33m'
white='\033[1;97m'
blue='\033[1;34m'
red='\033[0;31m'
green='\033[0;32m'
reset='\033[0m'

### Configuration
THREADS=50
TIMEOUT=10
WORDLISTS="wordlist/subdomains-top1million-5000.txt"
RESOLVERS="wordlist/resolvers.txt"
MAX_RETRIES=3
VERSION="3.1"
TEMP_DIR=$(mktemp -d)
LOG_FILE="$TEMP_DIR/enum_log.txt"
WEB_PORTS="80,443,8080,8443,3000,8000,8081"
EXTENDED_PORTS="80,443,81,82,88,135,143,300,554,591,593,832,902,981,993,1010,1024,1311,2077,2079,2082,2083,2086,2087,2095,2096,2222,2480,3000,3128,3306,3333,3389,4243,4443,4567,4711,4712,4993,5000,5001,5060,5104,5108,5357,5432,5800,5985,6379,6543,7000,7170,7396,7474,7547,8000,8001,8008,8014,8042,8069,8080,8081,8083,8085,8088,8089,8090,8091,8118,8123,8172,8181,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9100,9200,9443,9800,9981,9999,10000,10443,12345,12443,16080,18091,18092,20720,28017,49152"

# Load API tokens from config file or environment
CONFIG_FILE="$HOME/.subenum_config"
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    # Use environment variables or defaults
    GITHUB_TOKEN=${GITHUB_TOKEN:-""}
    CHAOS_KEY=${CHAOS_KEY:-""}
    GITLAB_TOKEN=${GITLAB_TOKEN:-""}
    SHODAN_KEY=${SHODAN_KEY:-""}
    CENSYS_API_ID=${CENSYS_API_ID:-""}
    CENSYS_API_SECRET=${CENSYS_API_SECRET:-""}
    SPYSE_API_TOKEN=${SPYSE_API_TOKEN:-""}
fi
# Kali Linux compatibility shim
if grep -qi kali /etc/os-release; then
    export LD_PRELOAD=""
    alias sublist3r='sublist3r 2>/dev/null'
    alias jq='jq -r "try . catch \"\""'
fi
### Banner
display_banner() {
    printf "$green"
    if [[ -f "banner.txt" ]]; then
        cat banner.txt
    else
        echo "========================================="
        echo "  TheN0thing Enhanced Enumeration v$VERSION"
        echo "  IP/ASN/Subdomain Separator"
        echo "========================================="
    fi
    printf "$reset\n"
}

### Helper Functions
check_dependencies() {
    local missing_tools=()
    
    for tool in subfinder amass assetfinder findomain httpx anew jq curl puredns shuffledns gospider sublist3r whois ipinfo asnmap dig; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${red}[!] Missing dependencies: ${missing_tools[*]}${reset}"
        echo -e "${yellow}[i] Install these tools before running this script.${reset}"
        exit 1
    fi
}

usage() {
    echo -e "\nUsage: $0 [options] <target>"
    echo -e "\nOptions:"
    echo "  -o, --output DIR     Output directory (default: output/<target>)"
    echo "  -w, --wordlist FILE  Custom wordlist for bruteforce"
    echo "  -r, --resolvers FILE Custom resolvers file"
    echo "  -t, --threads NUM    Number of threads (default: $THREADS)"
    echo "  -p, --ports PORTS    Ports to scan (default: common web ports)"
    echo "  -a, --all-ports      Use extended port list"
    echo "  -s, --screenshot     Take screenshots of discovered web services"
    echo "  -f, --fast           Fast mode - skip intensive operations"
    echo "  -v, --verbose        Verbose output"
    echo "  -h, --help           Show this help message and exit"
    echo "  --type TYPE          Specify target type (domain, ip, asn) - auto-detect if not specified"
    echo "  --file FILE          Import targets from file (one target per line)"
    echo "  --all-options        Enable all features (equivalent to -a -s + extended scans)"
    echo ""
    exit 1
}

log() {
    local level="$1"
    local message="$2"
    local color=""
    
    case "$level" in
        "INFO") color="$blue" ;;
        "SUCCESS") color="$green" ;;
        "WARNING") color="$yellow" ;;
        "ERROR") color="$red" ;;
        *) color="$white" ;;
    esac
    
    # Send colored messages to stderr
    echo -e "${color}[$level] $message${reset}" >&2
    # Write plain text to log file
    echo "[$level] $message" >> "$LOG_FILE"
}

setup_directories() {
    local target="$1"
    local output_dir="$2"
    local target_type="$3"
    
    # Create base output directory if needed
    mkdir -p "output"

    # Generate unique directory name if exists
    if [[ -d "$output_dir" ]]; then
        log "WARNING" "Directory $output_dir already exists. Creating timestamped directory."
        output_dir="${output_dir}_$(date +"%Y%m%d%H%M%S")"
    fi

    # Create main directory
    mkdir -p "$output_dir" || {
        log "ERROR" "Failed to create output directory: $output_dir"
        exit 1
    }

    # Create subdirectories
    local subdirs=(
        "raw"
        "processed"
        "screenshots"
        "reports"
        "assets/subdomains"
        "assets/ips"
        "assets/asns"
        "assets/cidrs"
    )
    
    for dir in "${subdirs[@]}"; do
        mkdir -p "${output_dir}/${dir}" || {
            log "ERROR" "Failed to create subdirectory: ${output_dir}/${dir}"
            exit 1
        }
    done

    log "INFO" "Created directory structure: $output_dir"
    echo "$output_dir"  # This is the only stdout output
}
cleanup() {
    log "INFO" "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
    log "SUCCESS" "Cleanup complete."
}

# Set up trap for cleanup on exit
trap cleanup EXIT

# Function to detect input type (domain, IP, or ASN)
detect_input_type() {
    local input="$1"
    
    # Check if input is an ASN (AS followed by a number)
    if [[ "$input" =~ ^AS[0-9]+$ ]]; then
        echo "asn"
    # Check if input is an IP address (IPv4)
    elif [[ "$input" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "ip"
    # Check if input is an IP range (CIDR notation)
    elif [[ "$input" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        echo "ip_range"
    # Otherwise, assume it's a domain
    else
        echo "domain"
    fi
}

# Validate IP address
is_valid_ip() {
    local ip="$1"
    local IFS='.'
    local -a octets=($ip)
    
    # Check if we have 4 octets
    if [[ ${#octets[@]} -ne 4 ]]; then
        return 1
    fi
    
    # Check if each octet is a valid number between 0 and 255
    for octet in "${octets[@]}"; do
        if ! [[ "$octet" =~ ^[0-9]+$ ]] || [[ "$octet" -lt 0 ]] || [[ "$octet" -gt 255 ]]; then
            return 1
        fi
    done
    
    return 0
}

# Function to validate an ASN
is_valid_asn() {
    local asn="$1"
    
    # Check if input is in format AS1234
    if [[ "$asn" =~ ^AS[0-9]+$ ]]; then
        return 0
    fi
    
    return 1
}

### Main Functions
setup_directories() {
    local target="$1"
    local output_dir="$2"
    local target_type="$3"
    
    if [[ ! -d "output" ]]; then
        mkdir -p output
    fi
    
    if [[ -d "$output_dir" ]]; then
        log "WARNING" "Directory $output_dir already exists. Creating timestamped directory."
        output_dir="${output_dir}_$(date +"%Y%m%d%H%M%S")"
    fi
    
    mkdir -p "$output_dir"
    log "INFO" "Created output directory: $output_dir"
    
    # Create subdirectories for organization
    mkdir -p "$output_dir/raw"
    mkdir -p "$output_dir/processed"
    mkdir -p "$output_dir/screenshots"
    mkdir -p "$output_dir/reports"
    
    # Create specific asset directories
    mkdir -p "$output_dir/assets/subdomains"
    mkdir -p "$output_dir/assets/ips"
    mkdir -p "$output_dir/assets/asns"
    mkdir -p "$output_dir/assets/cidrs"
    
    echo "$output_dir"
}

# Function to process passive reconnaissance results
process_passive_results() {
    local output_dir="$1"
    local raw_dir="$output_dir/raw"
    local assets_dir="$output_dir/assets"
    
    log "INFO" "Processing reconnaissance results with awk..."
    
    # Ensure output files exist
    touch "$assets_dir/subdomains/all.txt"
    touch "$assets_dir/ips/all.txt"
    touch "$assets_dir/asns/all.txt"
    touch "$assets_dir/cidrs/all.txt"
    
    # Concatenate all raw files and process with awk
    cat "$raw_dir"/*.txt 2>/dev/null | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]' | awk '
    /^AS[0-9]+$/ { print > "'"$assets_dir/asns/all.txt"'" }
    /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}$/ { print > "'"$assets_dir/cidrs/all.txt"'" }
    /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/ {
        split($0, octets, ".")
        if (length(octets) == 4 && octets[1] >= 0 && octets[1] <= 255 &&
            octets[2] >= 0 && octets[2] <= 255 &&
            octets[3] >= 0 && octets[3] <= 255 &&
            octets[4] >= 0 && octets[4] <= 255) {
            print > "'"$assets_dir/ips/all.txt"'"
        }
    }
    /\./ && !/^[0-9\.]+$/ && !/\*\./ && !/[[:space:]]/ && !/@/ { print > "'"$assets_dir/subdomains/all.txt"'" }
    '
    
    # Sort and deduplicate each asset file
    for file in "$assets_dir"/*/all.txt; do
        if [[ -f "$file" ]]; then
            sort -u "$file" -o "$file"
        fi
    done
    
    log "SUCCESS" "Processing completed."
}

run_domain_enumeration() {
    local domain="$1"
    local output_dir="$2"
    local raw_dir="$output_dir/raw"
    
    log "INFO" "Starting passive reconnaissance for domain: $domain"
    
    # Run tools in parallel for faster execution
# Add this robust DNSdumpster implementation
dnsdumpster_scan() {
    echo "[*] Running custom DNSdumpster scan for $domain"
    tmpdir=$(mktemp -d)
    
    # Get initial cookies and CSRF token
    curl -s -L -c $tmpdir/cookies.txt https://dnsdumpster.com > $tmpdir/response.html
    csrf_token=$(grep -oP "csrfmiddlewaretoken.*?value='\K[^']+" $tmpdir/response.html)

    # Submit request
    curl -s -L -b $tmpdir/cookies.txt \
        -H "Referer: https://dnsdumpster.com/" \
        --data-raw "csrfmiddlewaretoken=$csrf_token&targetip=$domain" \
        https://dnsdumpster.com > $tmpdir/results.html

    # Extract subdomains
    grep -Po "[\w\.-]+\.$domain" $tmpdir/results.html | sort -u >> "$raw_dir/sublist3r.txt"
    
    rm -rf $tmpdir
}

    # Subfinder
    log "INFO" "Running subfinder..."
    subfinder -d "$domain" -all -silent > "$raw_dir/subfinder.txt" &
    
    # Amass passive mode
    log "INFO" "Running amass passive scan..."
    amass enum -passive -norecursive -d "$domain" > "$raw_dir/amass.txt" &
    
    # AssetFinder
    log "INFO" "Running assetfinder..."
    assetfinder -subs-only "$domain" | sort | uniq > "$raw_dir/assetfinder.txt" &
    
    # Findomain
    log "INFO" "Running findomain..."
    findomain -t "$domain" -q > "$raw_dir/findomain.txt" &
    
    # Sublist3r
log "INFO" "Running modified Sublist3r scan..."

# Temporary files
temp_sublist3r=$(mktemp)
temp_dnsdumpster=$(mktemp)

# Run Sublist3r with error suppression
sublist3r -d "$domain" -o "$temp_sublist3r" -v 2>&1 | \
    grep -vE "Error resolving|Timeout" || true

# Custom DNSdumpster implementation
dnsdumpster_scan() {
    echo "[*] Running enhanced DNSdumpster scan for $domain"
    tmpdir=$(mktemp -d)
    
    # Get initial cookies and CSRF token with timeout
    if ! curl -sS -m 15 -L -c "$tmpdir/cookies.txt" https://dnsdumpster.com > "$tmpdir/response.html"; then
        echo "[!] DNSdumpster connection failed"
        return 1
    fi
    
    # Extract CSRF token using XML parser
    csrf_token=$(xmllint --html --xpath "//input[@name='csrfmiddlewaretoken']/@value" "$tmpdir/response.html" 2>/dev/null | \
        awk -F\" '{print $2}')
    
    # Validate token format
    if [[ ! "$csrf_token" =~ ^[a-zA-Z0-9]{64}$ ]]; then
        echo "[!] Invalid CSRF token format"
        return 1
    fi
    
    # Submit request with timeout and validate response
    if ! curl -sS -m 20 -L -b "$tmpdir/cookies.txt" \
        -H "Referer: https://dnsdumpster.com/" \
        --data-raw "csrfmiddlewaretoken=$csrf_token&targetip=$domain" \
        https://dnsdumpster.com > "$tmpdir/results.html"; then
        echo "[!] DNSdumpster submission failed"
        return 1
    fi
    
    # Extract subdomains with strict validation
    grep -Po "(([a-zA-Z0-9\-]+\.)+$domain)(?=[\"'])" "$tmpdir/results.html" | \
        sort -u >> "$raw_dir/sublist3r.txt"
    
    # Cleanup
    rm -rf "$tmpdir"
}

# Call instead of Sublist3r's DNSdumpster module

# Merge and deduplicate results
cat "$temp_sublist3r" "$temp_dnsdumpster" 2>/dev/null | \
    sort -u > "$raw_dir/sublist3r.txt"

# Cleanup
rm -f "$temp_sublist3r" "$temp_dnsdumpster"
    
    # Run custom DNSdumpster scan
    dnsdumpster_scan
    # Merge results
    cat "$raw_dir/sublist3r_unfiltered.txt" >> "$raw_dir/sublist3r.txt"
    sort -u "$raw_dir/sublist3r.txt" -o "$raw_dir/sublist3r.txt"
    
    # Certificate transparency logs
    log "INFO" "Checking certificate transparency logs..."
    tmp_crtsh=$(mktemp)
    curl -fsS "https://crt.sh/?q=%.$domain&output=json" -o "$tmp_crtsh"

if [ -s "$tmp_crtsh" ]; then
    jq -r 'try .[].name_value catch empty' "$tmp_crtsh" | \
        sed 's/\*\.//g' | \
        sort -u > "$raw_dir/crtsh.txt"
else
    log "WARNING" "Certificate transparency check failed"
fi

rm -f "$tmp_crtsh"

    # REMOVED: Wayback Machine check

    # REMOVED: VirusTotal scan
    
    if [[ -n "$GITHUB_TOKEN" ]]; then
        log "INFO" "Running GitHub subdomain scan..."
        github-subdomains -d "$domain" -t "$GITHUB_TOKEN" -raw 2>/dev/null | sort -u > "$raw_dir/github.txt" &
    fi
    
# Add validation before CHAOS scan
# CHAOS Subdomain Enumeration
run_chaos_scan() {
    local domain="$1"
    local chaos_raw="$output_dir/raw/chaos_raw.json"
    local retry_after_file="$output_dir/raw/chaos_retry.txt"
    
    log "INFO" "Starting CHAOS scan with enhanced validation..."
    
    # Check existing rate limits
    if [[ -f "$retry_after_file" ]]; then
        local retry_time=$(cat "$retry_after_file")
        if [[ $(date +%s) -lt $retry_time ]]; then
            local wait_time=$((retry_time - $(date +%s)))
            log "WARNING" "CHAOS rate limit active. Resuming in ${wait_time}s..."
            sleep $wait_time
        fi
    fi

    # Run chaos with full debugging
    if response=$(chaos -d "$domain" -key "$CHAOS_KEY" -json -silent 2>&1 | tee "$chaos_raw"); then
        if jq -e '.subdomains' "$chaos_raw" >/dev/null; then
            # Successful scan
            jq -r '.subdomains[]' "$chaos_raw" | sort -u > "$raw_dir/chaos.txt"
            log "SUCCESS" "CHAOS found $(wc -l < "$raw_dir/chaos.txt") subdomains"
            return 0
        else
            # Handle API errors
            if grep -q "rate limited" "$chaos_raw"; then
                local retry_seconds=3600
                echo $(($(date +%s) + retry_seconds)) > "$retry_after_file"
                log "ERROR" "Rate limited! Next scan available: $(date -d @$(cat "$retry_after_file"))"
                return 2
            elif grep -q "invalid API key" "$chaos_raw"; then
                log "ERROR" "Invalid CHAOS API key. Update in $CONFIG_FILE"
                log "ERROR" "Get new key: https://chaos.projectdiscovery.io/#/"
                return 1
            fi
        fi
    fi

    # Network failure handling
    if ! ping -c1 dns.projectdiscovery.io &>/dev/null; then
        log "ERROR" "Network unreachable. Verify:"
        log "ERROR" "1. Internet connection"
        log "ERROR" "2. DNS resolution: dig dns.projectdiscovery.io"
        log "ERROR" "3. Firewall rules: sudo ufw status"
        return 3
    fi

    log "ERROR" "Unknown CHAOS failure. Debug with:"
    log "ERROR" "1. View raw response: jq . $chaos_raw"
    log "ERROR" "2. Test manually: chaos -d $domain -key $CHAOS_KEY -silent"
    return 4
}
    
    # Wait for all background processes to complete
    wait
    log "SUCCESS" "Passive reconnaissance completed for domain."
    
    # Add the main domain and www subdomain
    echo "$domain" >> "$raw_dir/main.txt"
    echo "www.$domain" >> "$raw_dir/main.txt"
    
    # Extract IPs from found subdomains
    log "INFO" "Resolving domains to find IPs..."
    mkdir -p "$output_dir/temp"
    
    # Create a list of all subdomains for resolution
    cat "$raw_dir"/*.txt | grep -v "*" | grep -v " " | grep -v "@" | grep "\." | sort -u > "$output_dir/temp/all_domains.txt"
    
    if command -v massdns &> /dev/null && [[ -f "$resolvers" ]]; then
        log "INFO" "Using massdns for faster resolution..."
        massdns -r "$resolvers" -t A -o S -w "$raw_dir/resolved_ips_massdns.txt" "$output_dir/temp/all_domains.txt"
        # Extract IPs from massdns output
        awk '{print $3}' "$raw_dir/resolved_ips_massdns.txt" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > "$raw_dir/resolved_ips.txt"
    else
        log "INFO" "Using dig for resolution..."
        while IFS= read -r subdomain; do
            dig +short "$subdomain" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' >> "$raw_dir/resolved_ips.txt" &
            if [[ $(jobs -r -p | wc -l) -ge $threads ]]; then
                wait -n
            fi
        done < "$output_dir/temp/all_domains.txt"
        wait
    fi
    
    # Sort and deduplicate resolved IPs
    sort -u "$raw_dir/resolved_ips.txt" -o "$raw_dir/resolved_ips.txt"
    
    log "SUCCESS" "Domain enumeration completed."
}

run_ip_enumeration() {
    local ip="$1"
    local output_dir="$2"
    local raw_dir="$output_dir/raw"
    
    log "INFO" "Starting reconnaissance for IP: $ip"
    
    # Get reverse DNS
    log "INFO" "Performing reverse DNS lookup..."
    dig -x "$ip" +short > "$raw_dir/reverse_dns.txt"
    
    # Get ASN information
    log "INFO" "Getting ASN information..."
    if command -v asnmap &> /dev/null; then
        echo "$ip" | asnmap -silent > "$raw_dir/asn_info.txt"
    else
        whois "$ip" | grep -i "origin" | awk '{print $2}' | grep -o "AS[0-9]*" > "$raw_dir/asn_info.txt"
    fi
    
    # Get IP metadata
    log "INFO" "Getting IP metadata..."
    if command -v ipinfo &> /dev/null; then
        ipinfo "$ip" > "$raw_dir/ip_metadata.txt"
    else
        curl -s "https://ipinfo.io/$ip/json" > "$raw_dir/ip_metadata.txt"
    fi
    
    # Store the IP in the IP assets file
    echo "$ip" > "$output_dir/assets/ips/all.txt"
    
    # Extract ASN from ASN info
    grep -o "AS[0-9]*" "$raw_dir/asn_info.txt" > "$output_dir/assets/asns/all.txt"
    
    # Extract domain names from reverse DNS
    cat "$raw_dir/reverse_dns.txt" | sort -u > "$output_dir/assets/subdomains/all.txt"
    
    log "SUCCESS" "IP enumeration completed."
}
# Add randomized user-agents and delays
google_enum() {
    declare -a agents=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
    )
    
    for i in {1..3}; do
        agent=${agents[$RANDOM % ${#agents[@]}]}
        curl -s -A "$agent" --retry 2 --retry-delay $((RANDOM%5+1)) \
            "https://www.google.com/search?q=site:$domain" | \
            grep -Po "([a-zA-Z0-9\-]+\.)+$domain" | \
            sort -u >> "$raw_dir/google.txt"
        
        sleep $((RANDOM%5+2))
    done
}

# Replace the original Google enumeration with
log "INFO" "Running Google enumeration with anti-blocking measures..."
google_enum
run_asn_enumeration() {
    local asn="$1"
    local output_dir="$2"
    local raw_dir="$output_dir/raw"
    
    log "INFO" "Starting reconnaissance for ASN: $asn"
    
    # Get ASN details
    log "INFO" "Getting ASN details..."
    whois -h whois.radb.net -- "-i origin $asn" > "$raw_dir/asn_details.txt"
    
    # Extract CIDR blocks for the ASN
    log "INFO" "Extracting CIDR blocks..."
    whois -h whois.radb.net -- "-i origin $asn" | grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}" > "$raw_dir/cidr_blocks.txt"
    
    # Alternative approach using BGP data if the above doesn't work well
    log "INFO" "Fetching BGP data for ASN..."
    curl -s "https://api.bgpview.io/asn/${asn#AS}/prefixes" | jq -r '.data.ipv4_prefixes[].prefix' > "$raw_dir/cidr_blocks_bgp.txt"
    
    # Combine the results
    cat "$raw_dir/cidr_blocks.txt" "$raw_dir/cidr_blocks_bgp.txt" | sort -u > "$output_dir/assets/cidrs/all.txt"
    
    # Store the ASN in the ASN assets file
    echo "$asn" > "$output_dir/assets/asns/all.txt"
    
    # Extract IPs from CIDR blocks (first few from each block)
    log "INFO" "Extracting sample IPs from CIDR blocks..."
    while IFS= read -r cidr; do
        # Get first IP in the block
        first_ip=$(ipcalc "$cidr" | grep "HostMin" | awk '{print $2}')
        echo "$first_ip" >> "$raw_dir/ips_from_cidr.txt"
    done < "$output_dir/assets/cidrs/all.txt"
    
    cat "$raw_dir/ips_from_cidr.txt" | sort -u > "$output_dir/assets/ips/all.txt"
    
    log "SUCCESS" "ASN enumeration completed."
}

run_active_recon() {
    local target="$1"
    local output_dir="$2"
    local wordlist="$3"
    local resolvers="$4"
    local target_type="$5"
    
    log "INFO" "Starting active reconnaissance for $target (type: $target_type)"
    
    # Only do DNS brute forcing for domains
    if [[ "$target_type" == "domain" ]]; then
        if [[ -f "$wordlist" && -f "$resolvers" ]]; then
            log "INFO" "Running DNS bruteforce with puredns..."
            puredns bruteforce "$wordlist" "$target" --resolvers "$resolvers" -q > "$output_dir/raw/puredns.txt"
            
            log "INFO" "Running shuffledns..."
            shuffledns -d "$target" -w "$wordlist" -r "$resolvers" -o "$output_dir/raw/shuffledns.txt" 2>/dev/null
            
            # Update the assets
            cat "$output_dir/raw/puredns.txt" "$output_dir/raw/shuffledns.txt" | sort -u >> "$output_dir/assets/subdomains/all.txt"
            sort -u "$output_dir/assets/subdomains/all.txt" -o "$output_dir/assets/subdomains/all.txt"
        else
            log "WARNING" "Wordlist or resolvers file not found. Skipping DNS bruteforce."
        fi
    fi
    
    log "SUCCESS" "Active reconnaissance completed."
}

fingerprint_web_services() {
    local output_dir="$1"
    local ports="$2"
    
    log "INFO" "Starting HTTP fingerprinting with ports: $ports"
    
    # Combine subdomains and IPs into a single target list
    cat "$output_dir/assets/subdomains/all.txt" "$output_dir/assets/ips/all.txt" 2>/dev/null | sort -u > "$output_dir/temp/all_targets.txt"
    
    if [[ -s "$output_dir/temp/all_targets.txt" ]]; then
        httpx -silent -l "$output_dir/temp/all_targets.txt" -p "$ports" -nc -title -status-code -content-length -content-type -ip -cname -cdn -location -favicon -jarm -threads "$threads" -timeout "$TIMEOUT" -o "$output_dir/processed/fingerprint.txt"
        
        # Extract URLs for further processing
        awk '{print $1}' "$output_dir/processed/fingerprint.txt" | sort -u > "$output_dir/processed/all_urls.txt"
    else
        log "WARNING" "No targets found for fingerprinting."
    fi
    
    log "SUCCESS" "HTTP fingerprinting complete."
}
run_content_discovery() {
    local output_dir="$1"
    local target="$2"
    local target_type="$3"
    
    log "INFO" "Starting content discovery..."
    
    # Only run if we have URLs to check
    if [[ ! -s "$output_dir/processed/all_urls.txt" ]]; then
        log "WARNING" "No URLs found to crawl. Skipping content discovery."
        return
    fi
    
    # Run gospider to crawl websites and discover content
    mkdir -p "$output_dir/processed/spider"
    gospider -S "$output_dir/processed/all_urls.txt" -o "$output_dir/processed/spider" -c 10 -d 2
    
    # Extract new subdomains from spider results
    if [[ -d "$output_dir/processed/spider" ]]; then
        local domain_regex=""
        
        # Only extract subdomains if target is a domain
        if [[ "$target_type" == "domain" ]]; then
            domain_regex="$target"
            cat "$output_dir/processed/spider"/* 2>/dev/null | grep -o -E "https?://[a-zA-Z0-9\.\-]+\.$domain_regex" | sort -u > "$output_dir/processed/spider_urls.txt"
            cat "$output_dir/processed/spider_urls.txt" | cut -d/ -f3 | sort -u >> "$output_dir/assets/subdomains/all.txt"
            sort -u "$output_dir/assets/subdomains/all.txt" -o "$output_dir/assets/subdomains/all.txt"
        fi
        
        # Extract IPs from the spider results
        cat "$output_dir/processed/spider"/* 2>/dev/null | grep -o -E "https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | sort -u > "$output_dir/processed/spider_ip_urls.txt"
        cat "$output_dir/processed/spider_ip_urls.txt" | cut -d/ -f3 | sort -u >> "$output_dir/assets/ips/all.txt"
        sort -u "$output_dir/assets/ips/all.txt" -o "$output_dir/assets/ips/all.txt"
    fi
    
    log "SUCCESS" "Content discovery complete."
}

take_screenshots() {
    local output_dir="$1"
    local screenshots_dir="$output_dir/screenshots"
    
    log "INFO" "Taking screenshots of discovered websites..."
    
    # Check if we have URLs to screenshot
    if [[ ! -s "$output_dir/processed/all_urls.txt" ]]; then
        log "WARNING" "No URLs found to screenshot. Skipping."
        return
    fi
    
    # Check if gowitness is installed
    if command -v gowitness &> /dev/null; then
        gowitness scan file -f "$output_dir/processed/all_urls.txt" --threads 10 --screenshot-path "$screenshots_dir"
        log "SUCCESS" "Screenshots captured and saved to $screenshots_dir"
    elif command -v aquatone &> /dev/null; then
        # Alternative: Use aquatone if gowitness is not available
        cat "$output_dir/processed/all_urls.txt" | aquatone -out "$screenshots_dir" -silent
        log "SUCCESS" "Screenshots captured using aquatone and saved to $screenshots_dir"
    else
        log "WARNING" "Neither gowitness nor aquatone found. Skipping screenshots."
    fi
}

update_assets_from_fingerprinting() {
    local output_dir="$1"
    
    log "INFO" "Updating assets from fingerprinting results..."
    
    # Extract IPs from subdomain fingerprinting
    if [[ -f "$output_dir/processed/subdomain_fingerprint.txt" ]]; then
        grep -o "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" "$output_dir/processed/subdomain_fingerprint.txt" | sort -u >> "$output_dir/assets/ips/all.txt"
        sort -u "$output_dir/assets/ips/all.txt" -o "$output_dir/assets/ips/all.txt"
    fi
    
    # Get ASNs for all IPs
    log "INFO" "Getting ASNs for all IPs..."
    if command -v asnmap &> /dev/null && [[ -s "$output_dir/assets/ips/all.txt" ]]; then
        cat "$output_dir/assets/ips/all.txt" | asnmap -silent > "$output_dir/raw/all_asns.txt"
        grep -o "AS[0-9]*" "$output_dir/raw/all_asns.txt" | sort -u >> "$output_dir/assets/asns/all.txt"
        sort -u "$output_dir/assets/asns/all.txt" -o "$output_dir/assets/asns/all.txt"
    fi
    
    log "SUCCESS" "Assets updated."
}

generate_report() {
    local output_dir="$1"
    local target="$2"
    local target_type="$3"
    local report_file="$output_dir/reports/summary_report.md"
    
    log "INFO" "Generating summary report..."
    
    # Count results
    local total_subdomains=$(wc -l < "$output_dir/assets/subdomains/all.txt" 2>/dev/null || echo 0)
    local total_ips=$(wc -l < "$output_dir/assets/ips/all.txt" 2>/dev/null || echo 0)
    local total_asns=$(wc -l < "$output_dir/assets/asns/all.txt" 2>/dev/null || echo 0)
    local total_cidrs=$(wc -l < "$output_dir/assets/cidrs/all.txt" 2>/dev/null || echo 0)
    local live_urls=$(wc -l < "$output_dir/processed/all_urls.txt" 2>/dev/null || echo 0)
    
    # Create markdown report
    cat << EOF > "$report_file"
# Enhanced Enumeration Report for $target
*Generated on $(date "+%Y-%m-%d %H:%M:%S")*

## Summary
- Target: $target
- Target Type: $target_type
- Total Subdomains Found: $total_subdomains
- Total IPs Found: $total_ips
- Total ASNs Found: $total_asns
- Total CIDR Ranges Found: $total_cidrs
- Live URLs Found: $live_urls

## Asset Details

### Top Subdomains
EOF

    # Add top 10 subdomains
    if [[ -s "$output_dir/assets/subdomains/all.txt" ]]; then
        echo "Showing top 10 subdomains (total: $total_subdomains):" >> "$report_file"
        echo '```' >> "$report_file"
        head -n 10 "$output_dir/assets/subdomains/all.txt" >> "$report_file"
        echo '```' >> "$report_file"
    else
        echo "No subdomains found." >> "$report_file"
    fi

    # Add IP information
    echo -e "\n### IP Information" >> "$report_file"
    if [[ -s "$output_dir/assets/ips/all.txt" ]]; then
        echo "Showing sample IPs (total: $total_ips):" >> "$report_file"
        echo '```' >> "$report_file"
        head -n 10 "$output_dir/assets/ips/all.txt" >> "$report_file"
        echo '```' >> "$report_file"
    else
        echo "No IPs found." >> "$report_file"
    fi

    # Add ASN information
    echo -e "\n### ASN Information" >> "$report_file"
    if [[ -s "$output_dir/assets/asns/all.txt" ]]; then
        echo "ASNs associated with the target:" >> "$report_file"
        echo '```' >> "$report_file"
        cat "$output_dir/assets/asns/all.txt" >> "$report_file"
        echo '```' >> "$report_file"
    else
        echo "No ASNs found." >> "$report_file"
    fi

    # Add live URL information
    echo -e "\n### Live URLs" >> "$report_file"
    if [[ -s "$output_dir/processed/all_urls.txt" ]]; then
        echo "Sample of live URLs (total: $live_urls):" >> "$report_file"
        echo '```' >> "$report_file"
        head -n 10 "$output_dir/processed/all_urls.txt" >> "$report_file"
        echo '```' >> "$report_file"
    else
        echo "No live URLs found." >> "$report_file"
    fi

    # Add recommendations section
    echo -e "\n## Recommendations" >> "$report_file"
    echo "Based on the enumeration results, consider the following actions:" >> "$report_file"
    echo "1. Validate all discovered assets to confirm ownership" >> "$report_file"
    echo "2. Check for exposed services that shouldn't be public-facing" >> "$report_file"
    echo "3. Review web applications for security vulnerabilities" >> "$report_file"
    echo "4. Monitor identified IP ranges for unauthorized assets" >> "$report_file"
    
    log "SUCCESS" "Report generated: $report_file"
}

### Main Entry Point
main() {
    # Default values
    local target=""
    local output_dir=""
    local wordlist="$WORDLISTS"
    local resolvers="$RESOLVERS"
    local threads="$THREADS"
    local ports="$WEB_PORTS"
    local take_ss=false
    local fast_mode=false
    local verbose=false
    local target_type=""
    local input_file=""
    local all_options=false
    
    # Parse options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -w|--wordlist)
                wordlist="$2"
                shift 2
                ;;
            -r|--resolvers)
                resolvers="$2"
                shift 2
                ;;
            -t|--threads)
                threads="$2"
                shift 2
                ;;
            -p|--ports)
                ports="$2"
                shift 2
                ;;
            -a|--all-ports)
                ports="$EXTENDED_PORTS"
                shift
                ;;
            -s|--screenshot)
                take_ss=true
                shift
                ;;
            -f|--fast)
                fast_mode=true
                shift
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            --type)
                target_type="$2"
                shift 2
                ;;
            --file)
                input_file="$2"
                shift 2
                ;;
            --all-options)
                all_options=true
                ports="$EXTENDED_PORTS"
                take_ss=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                if [[ -z "$target" ]]; then
                    target="$1"
                    shift
                else
                    echo "Error: Unexpected argument '$1'"
                    usage
                fi
                ;;
        esac
    done
    
    # Apply all_options settings
    if [[ "$all_options" == true ]]; then
        log "INFO" "Running with all options enabled"
        ports="$EXTENDED_PORTS"
        take_ss=true
        verbose=true
    fi

    # Check if we have a target or input file
    if [[ -z "$target" && -z "$input_file" ]]; then
        log "ERROR" "No target specified. Use -h for help."
        exit 1
    fi

    # Display banner
    display_banner
    
    # Check dependencies
    check_dependencies
    
    # Process multiple targets from file
    if [[ -n "$input_file" ]]; then
        if [[ ! -f "$input_file" ]]; then
            log "ERROR" "Input file not found: $input_file"
            exit 1
        fi
        
        log "INFO" "Processing multiple targets from $input_file"
        
        # Create a parent directory for all targets
        local timestamp=$(date +"%Y%m%d%H%M%S")
        local parent_dir="output/multi_${timestamp}"
        mkdir -p "$parent_dir"
        
        # Process each target
        while IFS= read -r line; do
            # Skip empty lines and comments
            if [[ -z "$line" || "$line" =~ ^# ]]; then
                continue
            fi
            
            local current_target=$(echo "$line" | tr -d '[:space:]')
            log "INFO" "Processing target: $current_target"
            
            # Auto-detect target type if not specified
            local current_type="$target_type"
            if [[ -z "$current_type" ]]; then
                current_type=$(detect_input_type "$current_target")
            fi
            
            # Set output directory for this target
            local current_output="$parent_dir/$current_target"
            
            # Process this target
            process_single_target "$current_target" "$current_output" "$wordlist" "$resolvers" "$threads" "$ports" "$take_ss" "$fast_mode" "$verbose" "$current_type"
        done < "$input_file"
        
        log "SUCCESS" "All targets processed. Results saved in $parent_dir"
    else
        # Auto-detect target type if not specified
        if [[ -z "$target_type" ]]; then
            target_type=$(detect_input_type "$target")
            log "INFO" "Auto-detected target type: $target_type"
        fi
        
        # Set default output directory if not specified
        if [[ -z "$output_dir" ]]; then
            output_dir="output/$target"
        fi
        
        # Process single target
        process_single_target "$target" "$output_dir" "$wordlist" "$resolvers" "$threads" "$ports" "$take_ss" "$fast_mode" "$verbose" "$target_type"
    fi
}

# Function to process a single target
process_single_target() {
    local target="$1"
    local output_dir="$2"
    local wordlist="$3"
    local resolvers="$4"
    local threads="$5"
    local ports="$6"
    local take_ss="$7"
    local fast_mode="$8"
    local verbose="$9"
    local target_type="${10}"
    
    # Setup directories
    output_dir=$(setup_directories "$target" "$output_dir" "$target_type")
    
    # Validate target type
    case "$target_type" in
        "domain")
            if [[ ! "$target" =~ \. ]]; then
                log "WARNING" "Target doesn't look like a valid domain. Proceeding anyway."
            fi
            ;;
        "ip")
            if ! is_valid_ip "$target"; then
                log "ERROR" "Invalid IP address: $target"
                return 1
            fi
            ;;
        "asn")
            if ! is_valid_asn "$target"; then
                log "ERROR" "Invalid ASN: $target (should be in format AS12345)"
                return 1
            fi
            ;;
        *)
            log "ERROR" "Unknown target type: $target_type"
            return 1
            ;;
    esac
    
    # Run appropriate enumeration based on target type
    case "$target_type" in
        "domain")
            run_domain_enumeration "$target" "$output_dir"
            ;;
        "ip")
            run_ip_enumeration "$target" "$output_dir"
            ;;
        "asn")
            run_asn_enumeration "$target" "$output_dir"
            ;;
    esac
    
    # Process the reconnaissance results
    process_passive_results "$output_dir"
    
    # Run active reconnaissance if not in fast mode
    if [[ "$fast_mode" != true ]]; then
        run_active_recon "$target" "$output_dir" "$wordlist" "$resolvers" "$target_type"
    fi
    
    # Fingerprint web services
    fingerprint_web_services "$output_dir" "$ports"
    
    # Update assets from fingerprinting
    update_assets_from_fingerprinting "$output_dir"
    
    # Run content discovery if not in fast mode
    if [[ "$fast_mode" != true ]]; then
        run_content_discovery "$output_dir" "$target" "$target_type"
    fi
    
    # Take screenshots if requested
    if [[ "$take_ss" == true ]]; then
        take_screenshots "$output_dir"
    fi
    
    # Generate report
    generate_report "$output_dir" "$target" "$target_type"
    
    log "SUCCESS" "Target enumeration completed: $target"
    log "SUCCESS" "Results saved to: $output_dir"
}

# Run the main function with all arguments
main "$@"
