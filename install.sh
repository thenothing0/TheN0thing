#!/bin/bash

#System packages install
sudo apt update
sudo apt install wget curl software-properties-common python3 python3-pip unzip jq -y
sudo apt-get install -y parallel jq python3 python3-pip unzip
pip3 install --break-system-packages shodan censys

#go Tools install
GO111MODULE=on go  install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
GO111MODULE=on go install -v github.com/tomnomnom/assetfinder@latest
GO111MODULE=on go install -v github.com/tomnomnom/anew@latest
GO111MODULE=on go install -v github.com/owasp-amass/amass/v4/...@master
GO111MODULE=on go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
GO111MODULE=on go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
GO111MODULE=on go install -v github.com/jaeles-project/gospider@latest
GO111MODULE=on go install -v github.com/edoardottt/csprecon/cmd/csprecon@latest
GO111MODULE=on go install -v github.com/hakluke/haktrails@latest
GO111MODULE=on go install github.com/lc/gau/v2/cmd/gau@latest
GO111MODULE=on go install github.com/gwen001/github-subdomains@latest
GO111MODULE=on go install github.com/gwen001/gitlab-subdomains@latest
GO111MODULE=on go install -v github.com/glebarez/cero@latest
GO111MODULE=on go install github.com/incogbyte/shosubgo@latest
GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
GO111MODULE=on go install -v github.com/tomnomnom/anew@latest
GO111MODULE=on go install github.com/tomnomnom/unfurl@latest
git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && sudo make install
GO111MODULE=on go install github.com/d3mondev/puredns/v2@latest
GO111MODULE=on go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest


#Installing Sublist3r
pip3 install git+https://github.com/aboul3la/Sublist3r.git

#Installing Subscraper
pip3 install git+https://github.com/m8sec/subscraper.git

#Installing Findomain
curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux-i386.zip
unzip findomain-linux-i386.zip -d findomain
chmod +x findomain/findomain
cp findomain/findomain /usr/bin/
rm -rf findomain/ findomain-linux-i386.zip

#Installing Massdns (Used for ShuffleDNS)
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
cp bin/massdns /usr/bin
cd .. && rm -rf massdns/

# Downloading wordlist
wget -O best-dns-wordlist.txt https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt

# Downloading Resolvers
git clone https://github.com/trickest/resolvers.git

# Downloading .gau.toml for gau
wget https://raw.githubusercontent.com/lc/gau/master/.gau.toml

