#!/bin/bash

### Colors
yellow='\033[1;33m'
white='\033[1;97m'
blue='\033[1;34m'
red='\033[0;31m'
green='\033[0;32m'
reset='\033[0m'
#### TOKEN
GITHUB_TOKEN=<your_github_token>
CHAOS_KEY=<your_CHAOS_KEY>

### Banner
printf "$green"
cat banner.txt
printf "$reset"

### 
WORDLISTS=best-dns-wordlist.txt
RESOLVERS=resolvers.txt

### Helper
if [ $# -eq 0 ]
  then
    printf "$red[!] Domain not found!$reset\n" 
    printf "$yellow[i] Used: ./TheN0thing.sh example.com$reset\n"
    exit
fi

org=$1
domain_name=$1
cdir=`echo $org | tr '[:upper:]' '[:lower:]'| tr " " "_"`
cwhois=`echo $org | tr " " "+"`
webports="80,443,81,82,88,135,143,300,554,591,593,832,902,981,993,1010,1024,1311,2077,2079,2082,2083,2086,2087,2095,2096,2222,2480,3000,3128,3306,3333,3389,4243,4443,4567,4711,4712,4993,5000,5001,5060,5104,5108,5357,5432,5800,5985,6379,6543,7000,7170,7396,7474,7547,8000,8001,8008,8014,8042,8069,8080,8081,8083,8085,8088,8089,8090,8091,8118,8123,8172,8181,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9100,9200,9443,9800,9981,9999,10000,10443,12345,12443,16080,18091,18092,20720,28017,49152"


if [[ -d output ]]
then
        :
else
        mkdir output
fi
if [[ -d output/$cdir ]]
then
        printf "$blu[i] Creating the '$org' directory to store the results in the 'output' folder...$reset\n"
        rm -r -f output/$cdir
else
        echo -e "$blu[i] Creating the '$org' directory to store the results in the 'output' folder...$reset\n"
        mkdir output/$cdir
fi

echo -e "[i] Starting enumeration..."

### Subfinder Enum
subfinder -d $domain_name -all -silent >> output/$cdir/subfinder.txtls

### Chaos API KEY Check and run
if [ -z $CHAOS_KEY ];
then printf "[i] Missing Chaos key, moving to the next recon...\n";
else chaos -silent -d $domain_name -key $CHAOS_KEY | anew output/$cdir/chaos.txtls;
fi

### Amass Enum
amass enum -passive -norecursive -d $domain_name >> output/$cdir/amass.txtls &

### WaybackEngine Enum
curl -sk "http://web.archive.org/cdx/search/cdx?url=*."$domain_name"&output=txt&fl=original&collapse=urlkey&page=" | awk -F / '{gsub(/:.*/, "", $3); print $3}' | anew | sort -u >> output/$cdir/wayback.txtls

### BufferOver Enum
curl -s "https://dns.bufferover.run/dns?q=."$domain_name"" | grep $domain_name | awk -F, '{gsub("\"", "", $2); print $2}' | anew >> output/$cdir/bufferover.txtls

### AssetFinder Enum
assetfinder -subs-only $domain_name | sort | uniq >> output/$cdir/assetfinder.txtls

### Certificate Enum
curl -s "https://crt.sh/?q="$domain_name"&output=json" | jq -r ".[].name_value" | sed 's/*.//g' | anew >> output/$cdir/whois.txtls

### Sublist3r Enum
sublist3r -d $domain_name -o sublister_output.txt &> /dev/null

### Findomain Enum
findomain -t $domain_name -q >> output/$cdir/findomain.txtls

### haktrails Enum
echo $domain_name | haktrails subdomains 2>/dev/null | anew >> output/$cdir/haktrails.txtls

### gau Enum
gau --threads 10 --subs $domain_name |  unfurl -u domains | anew >> output/$cdir/gau.txtls

### github-subdomains Enum
github-subdomains -d $domain_name -t $GITHUB_TOKEN -raw 2>/dev/null | anew >> output/$cdir/github-subdomains.txtls

### gitlab-subdomains Enum
gitlab-subdomains -d $domain_name -t $GITLAB_TOKEN -raw 2>/dev/null | anew >> output/$cdir/gitlab-subdomains.txtls

### cero Enum
cero $domain_name | anew >> output/$cdir/cero.txtls

### censys Enum
censys subdomains $domain_name | sed 's/^[ \t]*-//; s/-//g' | anew >> output/$cdir/censys.txtls

### crtsh Enum
curl -sk "https://crt.sh/?q=%.$domain_name&output=json" | tr ',' '\n' | awk -F'"' '/name_value/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' | grep -w "$domain_name\$" | anew >> output/$cdir/crtsh.txtls

### jldc Enum
curl -sk "https://jldc.me/anubis/subdomains/$domain_name" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | anew >> output/$cdir/jldc.txtls

### alienvault Enum
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain_name/url_list?limit=1000&page=100" | grep -o '"hostname": *"[^"]*' | sed 's/"hostname": "//' | anew >> output/$cdir/alienvault.txtls

### Subdomain-center Enum
curl "https://api.subdomain.center/?domain=$domain_name" -s | jq -r '.[]' | sort -u | anew >> output/$cdir/Subdomain-center.txtls

### certspotter Enum
curl -sk "https://api.certspotter.com/v1/issuances?domain=$domain_name&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | anew >> output/$cdir/certspotter.txtls

### puredns Enum
puredns bruteforce $WORDLISTS $DOMAIN_name --resolvers $RESOLVERS -q | anew >> output/$cdir/puredns.txtls

### Subscraper Enum
subscraper -d $domain_name -silent -o output/$cdir/subscraper.txtls

### Brute subdomains
shuffledns -d $domain_name -w wordlist/subdomains-top1million-5000.txt -r wordlist/resolvers.txt -mode bruteforce -o output/$cdir/dnstemp.txtls &> /dev/null

### Checking existance of files
while [[ $(ps aux | grep amass | wc -l) != 1 ]]
do
        sleep 5
done

if [ -f "sublister_output.txt" ]; then
        cat sublister_output.txt|anew|grep -v " "|grep -v "@" | grep "\." >> output/$cdir/sublister.txtls
        rm sublister_output.txt
        cat output/$cdir/sublister.txtls|anew|grep -v " "|grep -v "@" | grep "\." >> all.txtls
else
        sleep 0.1
fi

### Housekeeping
cat output/$cdir/chaos.txtls | anew all.txtls
cat output/$cdir/subscraper.txtls | anew all.txtls
cat output/$cdir/subfinder.txtls | anew all.txtls
cat output/$cdir/amass.txtls | anew all.txtls
cat output/$cdir/wayback.txtls |anew all.txtls
cat output/$cdir/bufferover.txtls |anew all.txtls
cat output/$cdir/assetfinder.txtls |anew all.txtls
cat output/$cdir/haktrails.txtls | anew all.txtls
cat output/$cdir/gau.txtls | anew all.txtls
cat output/$cdir/github-subdomains.txtls | anew all.txtls
cat output/$cdir/gitlab-subdomains.txtls | anew all.txtls
cat output/$cdir/cero.txtls | anew all.txtls
cat output/$cdir/censys.txtls | anew all.txtls
cat output/$cdir/crtsh.txtls | anew all.txtls
cat output/$cdir/jldc.txtls | anew all.txtls
cat output/$cdir/alienvault.txtls | anew all.txtls
cat output/$cdir/Subdomain-center.txtls | anew all.txtls
cat output/$cdir/certspotter.txtls | anew all.txtls
cat output/$cdir/puredns.txtls | anew all.txtls
cat output/$cdir/whois.txtls|anew|grep -v " "|grep -v "@" | grep "\." >> all.txtls
cat output/$cdir/findomain.txtls|anew|grep -v " "|grep -v "@" | grep "\." >> all.txtls
cat output/$cdir/dnstemp.txtls | grep $domain_name | egrep -iv ".(DMARC|spf|=|[*])" | cut -d " " -f1 | anew | sort -u | grep -v " "|grep -v "@" | grep "\." >>  output/$cdir/dnscan.txtls
rm output/$cdir/dnstemp.txtls
echo "www.$domain_name" |anew all.txtls
echo "$domain_name" |anew all.txtls
cat all.txtls | tr '[:upper:]' '[:lower:]'| anew | grep -v "*." | grep -v " "|grep -v "@" | grep "\." >> $cdir.master
mv $cdir.master output/$cdir/master
sed -i 's/<br>/\n/g' output/$cdir/master

### Recursive subdomain search
subfinder -dL output/$cdir/master -recursive -all -silent -o output/$cdir/subfinder-rec.txtls

cat output/$cdir/subfinder-rec.txtls | anew output/$cdir/master

### httpx to get footprint
httpx -silent -l output/$cdir/master -p $webports -nc -title -status-code -content-length -content-type -ip -cname -cdn -location -favicon -jarm -o output/$cdir/fingerprint.txt

### Get urls
cat output/$cdir/fingerprint.txt | awk '{print $1}' | anew output/$cdir/urls.txt

### Gospider enum new subdomains
gospider -S output/$cdir/urls.txt -o output/$cdir/spider

### Get urls
cat output/$cdir/spider/* | grep "\[subdomains" | awk '{print $3}' | anew output/$cdir/urls.txt

### Get subdomains
cat output/$cdir/spider/* | grep "\[subdomains" | awk '{print $3}' | cut -d / -f 3 | anew output/$cdir/master

### CSP recon
csprecon -l output/$cdir/urls.txt -d $domain_name -o output/$cdir/csprecon.txtls -silent
httpx -l output/$cdir/csprecon.txtls -silent | anew output/$cdir/urls.txt
mv output/$cdir "output/$(date +"%Y%m%d%H%M%S")_$cdir"

rm all.txtls

printf "$green[+] Done recon for $domain_name $reset\n"

