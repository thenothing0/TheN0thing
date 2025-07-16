#!/usr/bin/env python3
import asyncio
import aiohttp
import aiofiles
from urllib.parse import quote, urlparse, urljoin
import argparse
import os
import json
import time
from bs4 import BeautifulSoup
import waybackpy
from collections import defaultdict
import logging
import sys
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set, Tuple
import ssl
import certifi
from urllib.robotparser import RobotFileParser
import random
import re
import httpx
import tldextract

@dataclass
class ScanResult:
    """Data class for scan results"""
    url: str
    vulnerability_type: str
    payload: Optional[str] = None
    status_code: Optional[int] = None
    response_time: Optional[float] = None
    details: Dict = None

class EnhancedScanner:
    def __init__(self, threads=50, output_dir="scan_results", timeout=10, rate_limit=0.1):
        self.threads = threads
        self.output_dir = output_dir
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.results = []
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Setup logging
        self.setup_logging()
        
        # SSL context
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        
        # User agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        
        # Payloads
        self.crlf_payloads = [
            '%0d%0aLocation: http://evil.com',
            '%23%0d%0aLocation: http://evil.com',
            '%3f%0d%0aLocation: http://evil.com',
            '/%0d%0aLocation: http://evil.com',
            '%2e%2e%2f%0d%0aLocation: http://evil.com',
            '%9d%9aLocation: http://evil.com'
        ]
        
        # Wordlists
        self.param_wordlist = self._load_wordlist("param_wordlist.txt")
        self.subdomain_wordlist = self._load_wordlist("subdomains.txt")
        self.common_paths = self._load_wordlist("paths.txt")

    def setup_logging(self):
        """Setup logging configuration"""
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # File handler
        try:
            file_handler = logging.FileHandler(os.path.join(self.output_dir, 'scan.log'), encoding='utf-8')
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        except Exception as e:
            print(f"Warning: Could not create log file: {e}")
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        self.logger.propagate = False

    def _load_wordlist(self, filename: str) -> List[str]:
        """Load wordlist from file with improved error handling"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            self.logger.warning(f"Wordlist {filename} not found, using defaults")
            if filename == "param_wordlist.txt":
                return ['id', 'page', 'view', 'q', 'search', 'category', 'file', 
                        'url', 'redirect', 'next', 'ref', 'referer', 'view', 'cmd',
                        'debug', 'test', 'admin', 'user', 'action', 'callback',
                        'return', 'goto', 'continue', 'success', 'error']
            elif filename == "subdomains.txt":
                return ['www', 'mail', 'webmail', 'admin', 'blog', 'dev', 'test',
                        'api', 'secure', 'portal', 'app', 'beta', 'staging',
                        'cdn', 'assets', 'static', 'media', 'files', 'docs']
            elif filename == "paths.txt":
                return ['admin', 'login', 'wp-admin', 'wp-login.php', 'config', 
                        'backup', 'test', 'api', 'v1', 'v2', 'graphql']
            return []

    async def create_session(self) -> aiohttp.ClientSession:
        """Create aiohttp session with optimized settings"""
        connector = aiohttp.TCPConnector(
            limit=self.threads,
            limit_per_host=20,
            ssl=self.ssl_context,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        return aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': random.choice(self.user_agents)}
        )

    async def safe_request(self, session: aiohttp.ClientSession, url: str, 
                          method: str = 'GET', **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make safe HTTP request with error handling and rate limiting"""
        try:
            await asyncio.sleep(self.rate_limit)
            async with session.request(method, url, **kwargs) as response:
                return response
        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout for {url}")
        except Exception as e:
            self.logger.debug(f"Request failed for {url}: {str(e)}")
        return None

    async def scan_crlf_injection(self, session: aiohttp.ClientSession, url: str) -> List[ScanResult]:
        """Asynchronous CRLF injection scanning"""
        results = []
        
        async def test_payload(payload: str) -> Optional[ScanResult]:
            test_url = url.rstrip('/') + '/' + quote(payload)
            start_time = time.time()
            
            response = await self.safe_request(session, test_url, allow_redirects=False)
            if not response:
                return None
                
            response_time = time.time() - start_time
            
            vuln_headers = {}
            if 'location' in response.headers and 'evil.com' in str(response.headers['location']).lower():
                vuln_headers['location'] = response.headers['location']
            
            if vuln_headers:
                return ScanResult(
                    url=test_url,
                    vulnerability_type="CRLF_INJECTION",
                    payload=payload,
                    status_code=response.status,
                    response_time=response_time,
                    details={'vulnerable_headers': vuln_headers, 'all_headers': dict(response.headers)}
                )
            return None

        tasks = [test_payload(payload) for payload in self.crlf_payloads]
        test_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in test_results:
            if isinstance(result, ScanResult):
                results.append(result)
        
        return results

    async def discover_parameters(self, session: aiohttp.ClientSession, url: str) -> List[str]:
        """Asynchronous parameter discovery"""
        try:
            baseline_response = await self.safe_request(session, url)
            if not baseline_response:
                return []
            
            baseline_text = await baseline_response.text()
            baseline_length = len(baseline_text)
            baseline_hash = hash(baseline_text)
            
        except Exception:
            return []
        
        valid_params = []
        
        async def test_param(param: str) -> Optional[str]:
            test_url = f"{url}{'&' if '?' in url else '?'}{param}=scanner_test"
            response = await self.safe_request(session, test_url)
            
            if response:
                try:
                    response_text = await response.text()
                    if (len(response_text) != baseline_length or 
                        hash(response_text) != baseline_hash):
                        return param
                except Exception:
                    pass
            return None

        semaphore = asyncio.Semaphore(self.threads // 2)
        
        async def test_with_semaphore(param: str):
            async with semaphore:
                return await test_param(param)

        tasks = [test_with_semaphore(param) for param in self.param_wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, str):
                valid_params.append(result)
        
        return valid_params

    async def crawl_website(self, session: aiohttp.ClientSession, base_url: str, max_depth: int = 3) -> List[str]:
        """Improved website crawler with depth control"""
        visited = set()
        to_visit = [(base_url, 0)]
        results = []
        base_domain = urlparse(base_url).netloc
        
        while to_visit and len(results) < 1000:
            current_url, depth = to_visit.pop(0)
            
            if current_url in visited or depth > max_depth:
                continue
            
            response = await self.safe_request(session, current_url)
            if not response or response.status >= 400:
                continue
                
            visited.add(current_url)
            results.append(current_url)
            
            try:
                html_content = await response.text()
                soup = BeautifulSoup(html_content, 'html.parser')
                
                for link in soup.find_all(['a', 'form'], href=True):
                    href = link.get('href') or link.get('action')
                    if not href:
                        continue
                        
                    absolute_url = urljoin(current_url, href)
                    parsed_url = urlparse(absolute_url)
                    
                    if (parsed_url.netloc == base_domain and 
                        absolute_url not in visited and 
                        not any(absolute_url.endswith(ext) for ext in 
                               ['.jpg', '.png', '.css', '.js', '.pdf', '.ico', '.svg', '.woff'])):
                        to_visit.append((absolute_url, depth + 1))
                        
            except Exception as e:
                self.logger.debug(f"Crawling error for {current_url}: {str(e)}")
                continue
        
        return results

    async def check_robots_txt(self, session: aiohttp.ClientSession, base_url: str) -> List[str]:
        """Check robots.txt for interesting paths"""
        robots_url = urljoin(base_url, '/robots.txt')
        response = await self.safe_request(session, robots_url)
        
        if not response or response.status != 200:
            return []
        
        try:
            robots_content = await response.text()
            interesting_paths = []
            
            for line in robots_content.split('\n'):
                line = line.strip()
                if line.startswith('Disallow:') or line.startswith('Allow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        full_url = urljoin(base_url, path)
                        interesting_paths.append(full_url)
            
            return interesting_paths[:50]
        except Exception:
            return []

    async def probe_subdomains(self, domain: str) -> List[str]:
        """Asynchronous subdomain probing with scanning"""
        alive_subdomains = []
        
        async def check_and_scan_subdomain(session: aiohttp.ClientSession, subdomain: str) -> Optional[Dict]:
            for scheme in ['https', 'http']:
                full_url = f"{scheme}://{subdomain}.{domain}"
                response = await self.safe_request(session, full_url)
                if response and response.status < 400:
                    # Perform basic scan on subdomain
                    crlf_results = await self.scan_crlf_injection(session, full_url)
                    return {
                        'url': full_url,
                        'status': response.status,
                        'crlf_vulnerabilities': len(crlf_results)
                    }
            return None

        async with await self.create_session() as session:
            semaphore = asyncio.Semaphore(self.threads)
            
            async def check_with_semaphore(subdomain: str):
                async with semaphore:
                    return await check_and_scan_subdomain(session, subdomain)

            tasks = [check_with_semaphore(sub) for sub in self.subdomain_wordlist]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, dict):
                    alive_subdomains.append(result)
        
        return alive_subdomains

    async def get_wayback_urls(self, domain: str) -> Dict[str, List[str]]:
        """Get all Wayback URLs and save to separate files"""
        try:
            user_agent = random.choice(self.user_agents)
            wayback = waybackpy.Url(domain, user_agent)
            
            # Get all URLs
            all_urls = []
            for snapshot in wayback.near():
                all_urls.append(snapshot.archive_url)
                if len(all_urls) >= 1000:  # Limit results
                    break
            
            # Get robots.txt URLs
            robots_urls = []
            wayback_robots = waybackpy.Url(f"{domain}/robots.txt", user_agent)
            for snapshot in wayback_robots.near():
                robots_urls.append(snapshot.archive_url)
                if len(robots_urls) >= 50:
                    break
            
            return {
                'all_urls': all_urls,
                'robots_urls': robots_urls
            }
        except Exception as e:
            self.logger.error(f"Wayback Machine error: {str(e)}")
            return {'all_urls': [], 'robots_urls': []}

    async def extract_urls_from_js(self, session: aiohttp.ClientSession, url: str) -> List[str]:
        """Extract URLs from JavaScript files (similar to GoLinkFinder)"""
        try:
            response = await self.safe_request(session, url)
            if not response or response.status != 200:
                return []
            
            content = await response.text()
            
            # Regex patterns to find URLs in JS
            patterns = [
                r'(?:https?://|//)[^"\'\s<>\)]+',
                r'\.get\(["\']([^"\']+)["\']\)',
                r'\.post\(["\']([^"\']+)["\']\)',
                r'url\(["\']?([^"\')]+)["\']?\)',
                r'=\s*["\']([^"\']+\.(?:js|css|png|jpg|gif))["\']'
            ]
            
            found_urls = set()
            for pattern in patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    url_candidate = match.group(1) if match.groups() else match.group(0)
                    if url_candidate.startswith('//'):
                        url_candidate = f"https:{url_candidate}"
                    elif url_candidate.startswith('/'):
                        url_candidate = urljoin(url, url_candidate)
                    found_urls.add(url_candidate)
            
            return list(found_urls)
        except Exception as e:
            self.logger.debug(f"URL extraction failed for {url}: {str(e)}")
            return []

    async def save_results_async(self, filename: str, data) -> None:
        """Asynchronously save results to file"""
        path = os.path.join(self.output_dir, filename)
        
        try:
            if isinstance(data, list) and data and isinstance(data[0], ScanResult):
                data = [asdict(result) for result in data]
            
            async with aiofiles.open(path, 'w', encoding='utf-8') as f:
                if isinstance(data, (list, dict)):
                    await f.write(json.dumps(data, indent=2, ensure_ascii=False))
                else:
                    await f.write(str(data))
            
            self.logger.info(f"Results saved to {path}")
        except Exception as e:
            self.logger.error(f"Failed to save results to {path}: {str(e)}")

    async def run_full_scan(self, target: str) -> None:
        """Run complete enhanced scan on target"""
        self.logger.info(f"Starting enhanced scan on {target}")
        start_time = time.time()
        
        # Extract root domain
        domain_info = tldextract.extract(target)
        domain = f"{domain_info.domain}.{domain_info.suffix}"
        
        # Create results directory structure
        domain_dir = os.path.join(self.output_dir, domain)
        os.makedirs(domain_dir, exist_ok=True)
        
        # Save all results in domain-specific directory
        self.output_dir = domain_dir
        
        async with await self.create_session() as session:
            # Phase 1: CRLF Injection Scan
            self.logger.info("Phase 1: CRLF Injection Testing")
            crlf_results = await self.scan_crlf_injection(session, target)
            if crlf_results:
                self.logger.info(f"Found {len(crlf_results)} CRLF Injection vulnerabilities")
                await self.save_results_async("crlf_results.json", crlf_results)
            
            # Phase 2: Robots.txt Analysis
            self.logger.info("Phase 2: Robots.txt Analysis")
            robots_paths = await self.check_robots_txt(session, target)
            if robots_paths:
                self.logger.info(f"Found {len(robots_paths)} interesting paths in robots.txt")
                await self.save_results_async("robots_paths.txt", robots_paths)
            
            # Phase 3: Website Crawling
            self.logger.info("Phase 3: Website Crawling")
            crawled_urls = await self.crawl_website(session, target)
            if crawled_urls:
                self.logger.info(f"Crawled {len(crawled_urls)} URLs")
                await self.save_results_async("crawled_urls.txt", crawled_urls)
            
            # Phase 4: Parameter Discovery
            self.logger.info("Phase 4: Hidden Parameter Discovery")
            test_urls = (crawled_urls[:10] if crawled_urls else [target])
            
            all_params = {}
            for url in test_urls:
                self.logger.info(f"Testing URL: {url}")
                params = await self.discover_parameters(session, url)
                if params:
                    self.logger.info(f"Discovered parameters: {', '.join(params)}")
                    all_params[url] = params
            
            if all_params:
                await self.save_results_async("parameters.json", all_params)
            
            # Phase 5: JavaScript URL Extraction
            self.logger.info("Phase 5: JavaScript URL Extraction")
            js_urls = []
            if crawled_urls:
                js_files = [url for url in crawled_urls if url.endswith('.js')][:5]  # Limit to 5 JS files
                for js_file in js_files:
                    found_urls = await self.extract_urls_from_js(session, js_file)
                    if found_urls:
                        js_urls.extend(found_urls)
            
            if js_urls:
                self.logger.info(f"Found {len(js_urls)} URLs in JavaScript files")
                await self.save_results_async("js_urls.txt", js_urls)
        
        # Phase 6: Subdomain Probing with Scanning
        self.logger.info("Phase 6: Subdomain Probing with Scanning")
        alive_subdomains = await self.probe_subdomains(domain)
        if alive_subdomains:
            self.logger.info(f"Found {len(alive_subdomains)} alive subdomains")
            await self.save_results_async("subdomains.json", alive_subdomains)
        
        # Phase 7: Wayback URLs Collection
        self.logger.info("Phase 7: Wayback URLs Collection")
        wayback_data = await self.get_wayback_urls(domain)
        if wayback_data['all_urls']:
            self.logger.info(f"Found {len(wayback_data['all_urls'])} historical URLs")
            await self.save_results_async("wayback_urls.txt", wayback_data['all_urls'])
        if wayback_data['robots_urls']:
            self.logger.info(f"Found {len(wayback_data['robots_urls'])} historical robots.txt URLs")
            await self.save_results_async("wayback_robots.txt", wayback_data['robots_urls'])
        
        total_time = time.time() - start_time
        self.logger.info(f"Scan completed in {total_time:.2f} seconds!")

async def main():
    parser = argparse.ArgumentParser(description="Enhanced Web Security Scanner")
    parser.add_argument("target", help="URL or domain to scan")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of concurrent threads")
    parser.add_argument("-o", "--output", default="scan_results", help="Output directory")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--rate-limit", type=float, default=0.1, help="Delay between requests")
    args = parser.parse_args()
    
    if not args.target.startswith(('http://', 'https://')):
        args.target = 'https://' + args.target
    
    print(f"[+] Starting enhanced scan on {args.target}")
    print(f"[+] Output directory: {args.output}")
    print(f"[+] Threads: {args.threads}")
    print(f"[+] Timeout: {args.timeout}s")
    print(f"[+] Rate limit: {args.rate_limit}s")
    print("-" * 50)
    
    try:
        scanner = EnhancedScanner(
            threads=args.threads, 
            output_dir=args.output,
            timeout=args.timeout,
            rate_limit=args.rate_limit
        )
        
        await scanner.run_full_scan(args.target)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Scan failed: {str(e)}")
        print(f"[!] Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    if sys.version_info < (3, 7):
        print("This script requires Python 3.7 or higher")
        sys.exit(1)
    
    asyncio.run(main())
