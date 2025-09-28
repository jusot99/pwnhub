#!/usr/bin/env python3

import argparse
import dns.resolver
import dns.query
import dns.zone
import subprocess
import json
import threading
import time
import sys
import socket
import signal
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
from urllib.parse import urlparse
import warnings
warnings.filterwarnings("ignore")

init(autoreset=True)

class DNSRecon:
    def __init__(self):
        self.spinner_chars = "⣾⣽⣻⢿⡿⣟⣯⣷"
        self.spinner_idx = 0
        self.running = True
        
    def banner(self):
        print(f"""
{Fore.GREEN + Style.BRIGHT}
    ╔═╗╔╦╗╔═╗╦  ╔═╗╔═╗╔╦╗╔═╗
    ╠═╣ ║ ╠═╣║  ║╣ ║   ║ ║ ║
    ╩ ╩ ╩ ╩ ╩╩═╝╚═╝╚═╝ ╩ ╚═╝
    ╔═╗╔═╗╔╗╔╔╦╗╦ ╦╔═╗╦═╗
    ╠═╣╠═╝║║║ ║ ║ ║║ ║╠╦╝
    ╩ ╩╩  ╝╚╝ ╩ ╚═╝╚═╝╩╚═
{Fore.CYAN + Style.BRIGHT}
        ╔══════════════════════════════════════╗
        ║   🚀 GHOST DNS RECON v2.0            ║
        ║   Professional Intel Gathering       ║
        ║   by jusot99                         ║
        ╚══════════════════════════════════════╝
{Style.RESET_ALL}""")

    def animate_loading(self, text, duration=2):
        """Enhanced loading animation with progress"""
        end_time = time.time() + duration
        start_time = time.time()
        
        while time.time() < end_time and self.running:
            elapsed = time.time() - start_time
            progress = min(100, (elapsed / duration) * 100)
            bar_length = 30
            filled = int(bar_length * progress / 100)
            bar = '█' * filled + '░' * (bar_length - filled)
            
            spinner = self.spinner_chars[self.spinner_idx % len(self.spinner_chars)]
            self.spinner_idx += 1
            
            print(f"\r{Fore.CYAN}{spinner} {text} [{bar}] {progress:.1f}%", end="", flush=True)
            time.sleep(0.1)
        
        if self.running:
            print(f"\r{Fore.GREEN}✅ {text} - Complete!{' '*50}")

    def handle_interrupt(self, sig, frame):
        print(f"\n{Fore.RED + Style.BRIGHT}[✖] Scan interrupted by user. Exiting...{Style.RESET_ALL}")
        self.running = False
        sys.exit(1)

    def query_records(self, domain, record_type):
        """Enhanced DNS query with multiple resolvers"""
        try:
            # Try multiple DNS resolvers
            resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
            
            for resolver_ip in resolvers:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = 5
                    resolver.lifetime = 10
                    
                    answers = resolver.resolve(domain, record_type, raise_on_no_answer=False)
                    if answers.rrset is not None:
                        return answers, None
                except:
                    continue
            
            return None, "All resolvers failed"
            
        except Exception as e:
            return None, str(e)

    def zone_transfer(self, ns, domain):
        """Enhanced zone transfer with detailed results"""
        try:
            xfr = dns.query.xfr(ns, domain, timeout=8)
            zone = dns.zone.from_xfr(xfr)
            
            hosts = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        record_name = str(name) if str(name) != '@' else domain
                        hosts.append({
                            'name': f"{record_name}.{domain}" if record_name != domain else domain,
                            'type': dns.rdatatype.to_text(rdataset.rdtype),
                            'data': str(rdata)
                        })
            return hosts, None
        except Exception as e:
            return None, str(e)

    def get_crtsh_subdomains(self, domain):
        """Enhanced certificate transparency with multiple sources"""
        self.animate_loading(f"Scanning certificate transparency logs", 3)
        
        subdomains = set()
        sources = [
            f"https://crt.sh/?q=%25.{domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
            f"https://tls.bufferover.run/dns?q=.{domain}"
        ]
        
        for source in sources:
            try:
                if "crt.sh" in source:
                    result = subprocess.run(
                        ["curl", "-s", "--connect-timeout", "10", "-A", "Mozilla/5.0", source],
                        capture_output=True, text=True, timeout=30
                    )
                    if result.stdout.strip():
                        data = json.loads(result.stdout)
                        for entry in data:
                            name_value = entry.get("name_value", "")
                            common_name = entry.get("common_name", "")
                            
                            for name in [name_value, common_name]:
                                if name:
                                    for line in str(name).splitlines():
                                        subdomain = line.strip().lower()
                                        if subdomain and not subdomain.startswith('*') and domain in subdomain:
                                            subdomains.add(subdomain)
                
                elif "certspotter" in source:
                    response = requests.get(source, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
                    if response.status_code == 200:
                        data = response.json()
                        for entry in data:
                            for dns_name in entry.get("dns_names", []):
                                if not dns_name.startswith('*') and domain in dns_name.lower():
                                    subdomains.add(dns_name.lower())
                
                elif "bufferover" in source:
                    response = requests.get(source, timeout=15)
                    if response.status_code == 200:
                        data = response.json()
                        if 'Results' in data:
                            for result in data['Results']:
                                if domain in result.lower():
                                    subdomains.add(result.split(',')[0].lower())
                                    
            except Exception as e:
                continue
        
        return sorted(list(subdomains)), None

    def brute_force_subdomains(self, domain, wordlist_size="medium"):
        """Enhanced subdomain bruteforce with progress"""
        self.animate_loading(f"Bruteforcing subdomains", 3)
        
        # Dynamic wordlists based on size
        wordlists = {
            "small": [
                'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 
                'cpanel', 'whm', 'admin', 'blog', 'dev', 'test', 'api', 'vpn'
            ],
            "medium": [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'ns3', 'imap', 'test', 'ns', 'blog', 
                'pop3', 'dev', 'www2', 'admin', 'forum', 'vpn', 'ns4', 'mail2', 'mysql', 
                'www1', 'beta', 'api', 'support', 'store', 'mx', 'secure', 'web', 'app'
            ],
            "large": [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'imap',
                'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news',
                'vpn', 'ns4', 'mail2', 'new', 'mysql', 'old', 'www1', 'beta', 'exchange',
                'api', 'support', 'store', 'mx', 'secure', 'demo', 'cp', 'calendar',
                'wiki', 'web', 'media', 'images', 'img', 'cdn', 'shop', 'app'
            ]
        }
        
        wordlist = wordlists.get(wordlist_size, wordlists["medium"])
        found_subdomains = []
        
        def check_subdomain(sub):
            if not self.running:
                return None
                
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                return subdomain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            
            completed = 0
            total = len(wordlist)
            
            for future in as_completed(futures):
                if not self.running:
                    break
                    
                completed += 1
                progress = (completed / total) * 100
                result = future.result()
                if result:
                    found_subdomains.append(result)
                
                # Update progress
                bar_length = 30
                filled = int(bar_length * progress / 100)
                bar = '█' * filled + '░' * (bar_length - filled)
                print(f"\r{Fore.YELLOW}⏳ Bruteforcing... [{bar}] {progress:.1f}% ({completed}/{total})", end="", flush=True)
        
        print(f"\r{Fore.GREEN}✅ Bruteforce completed - Found {len(found_subdomains)} subdomains{' '*50}")
        return found_subdomains, None

    def check_security_vulnerabilities(self, domain, records):
        """Enhanced security assessment"""
        vulnerabilities = []
        
        # Check SPF records
        txt_records = records.get('TXT', [])
        spf_found = False
        
        for txt in txt_records:
            txt_str = str(txt).lower()
            if 'spf' in txt_str:
                spf_found = True
                if '+all' in txt_str:
                    vulnerabilities.append({
                        'type': 'Weak SPF Policy',
                        'severity': 'HIGH',
                        'record': str(txt),
                        'impact': 'Allows email spoofing from any server',
                        'fix': 'Change +all to ~all or -all'
                    })
                elif '?all' in txt_str:
                    vulnerabilities.append({
                        'type': 'Neutral SPF Policy',
                        'severity': 'MEDIUM', 
                        'record': str(txt),
                        'impact': 'Potential email delivery issues',
                        'fix': 'Change ?all to ~all'
                    })
        
        if not spf_found:
            vulnerabilities.append({
                'type': 'Missing SPF Record',
                'severity': 'MEDIUM',
                'record': 'None',
                'impact': 'Email spoofing possible',
                'fix': 'Add SPF record: v=spf1 mx ~all'
            })
        
        # Check DMARC
        dmarc_found = any('v=dmarc' in str(txt).lower() for txt in txt_records)
        if not dmarc_found:
            vulnerabilities.append({
                'type': 'Missing DMARC',
                'severity': 'MEDIUM',
                'record': 'None',
                'impact': 'No email authentication policy',
                'fix': 'Add DMARC record: v=DMARC1; p=none; rua=mailto:admin@domain.com'
            })
        
        # Check for exposed services
        if records.get('A'):
            for a_record in records['A']:
                if 'localhost' in a_record or '127.0.0.1' in a_record:
                    vulnerabilities.append({
                        'type': 'Localhost Exposure',
                        'severity': 'LOW',
                        'record': a_record,
                        'impact': 'Potential internal service exposure',
                        'fix': 'Review DNS configuration'
                    })
        
        return vulnerabilities

    def port_scan_host(self, host):
        """Quick port scan for common services with animation"""
        common_ports = [
            (21, 'FTP'), (22, 'SSH'), (23, 'Telnet'), (25, 'SMTP'), 
            (53, 'DNS'), (80, 'HTTP'), (110, 'POP3'), (143, 'IMAP'),
            (443, 'HTTPS'), (993, 'IMAPS'), (995, 'POP3S'), 
            (2082, 'cPanel'), (2083, 'cPanel SSL'), (2086, 'WHM'),
            (2087, 'WHM SSL'), (3306, 'MySQL'), (3389, 'RDP'),
            (5432, 'PostgreSQL'), (5900, 'VNC'), (6379, 'Redis'),
            (27017, 'MongoDB'), (9200, 'Elasticsearch')
        ]
        
        open_ports = []
        
        def scan_port(port_info):
            if not self.running:
                return None
                
            port, service = port_info
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                sock.close()
                return (port, service) if result == 0 else None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(scan_port, port_info): port_info for port_info in common_ports}
            
            completed = 0
            total = len(common_ports)
            
            for future in as_completed(futures):
                if not self.running:
                    break
                    
                completed += 1
                result = future.result()
                if result:
                    open_ports.append(result)
                
                progress = (completed / total) * 100
                print(f"\r{Fore.BLUE}🔍 Scanning {host}... {completed}/{total} ports ({progress:.1f}%)", end="", flush=True)
        
        print(f"\r{' '*70}\r", end="")
        return sorted(open_ports)

    def run_scan(self, domain, brute=False, full=False, wordlist_size="medium"):
        """Main scanning function"""
        self.banner()
        print(f"{Fore.CYAN}[🎯] Target Domain: {Fore.YELLOW + Style.BRIGHT}{domain}")
        print(f"{Fore.CYAN}[⚡] Scan Mode: {Fore.GREEN}{'Full Reconnaissance' if full else 'Standard'}")
        if brute:
            print(f"{Fore.CYAN}[💥] Bruteforce: {Fore.GREEN}Enabled ({wordlist_size} wordlist)")
        print()

        # Phase 1: DNS Records
        print(f"{Fore.MAGENTA + Style.BRIGHT}{'═'*60}")
        print(f"{Fore.MAGENTA}🔍 PHASE 1: DNS RECORDS ENUMERATION")
        print(f"{'═'*60}{Style.RESET_ALL}")
        
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        all_records = {}
        ns_list = []

        for rtype in record_types:
            self.animate_loading(f"Querying {rtype} records", 1)
            answers, err = self.query_records(domain, rtype)
            
            print(f"{Fore.YELLOW + Style.BRIGHT}┌─ [{rtype} Records]")
            if answers:
                records_list = []
                for rdata in answers:
                    if rtype == "MX":
                        record = f"{rdata.preference} {rdata.exchange}"
                    elif rtype == "TXT":
                        txt = ''.join([part.decode() if isinstance(part, bytes) else part for part in getattr(rdata, 'strings', [])])
                        record = txt
                    elif rtype == "SOA":
                        record = f"MNAME: {rdata.mname} | RNAME: {rdata.rname} | Serial: {rdata.serial}"
                    else:
                        record = str(getattr(rdata, 'target', getattr(rdata, 'address', rdata)))
                    
                    records_list.append(record)
                    color = Fore.GREEN if rtype in ['A', 'AAAA'] else Fore.CYAN
                    print(f"{Fore.WHITE}├─ {color}{record}")
                    
                    if rtype == "NS":
                        ns_list.append(str(rdata.target).rstrip('.'))
                
                all_records[rtype] = records_list
            elif err:
                print(f"{Fore.RED}├─ ✖ Error: {str(err)}")
            else:
                print(f"{Fore.YELLOW}├─ No records found")
            print(f"{Fore.YELLOW}└─{'─'*50}")
            print()

        # Security Assessment
        print(f"{Fore.RED + Style.BRIGHT}{'═'*60}")
        print(f"{Fore.RED}🛡️ PHASE 2: SECURITY ASSESSMENT")  
        print(f"{'═'*60}{Style.RESET_ALL}")
        
        vulnerabilities = self.check_security_vulnerabilities(domain, all_records)
        if vulnerabilities:
            for vuln in vulnerabilities:
                severity_color = Fore.RED if vuln['severity'] == 'HIGH' else Fore.YELLOW
                print(f"{severity_color + Style.BRIGHT}🚨 {vuln['type']} ({vuln['severity']})")
                print(f"{Fore.WHITE}   ├─ Impact: {vuln['impact']}")
                print(f"{Fore.GREEN}   └─ Fix: {vuln['fix']}")
        else:
            print(f"{Fore.GREEN}[✓] No critical security issues detected")
        print()

        # Zone Transfer
        print(f"{Fore.BLUE + Style.BRIGHT}{'═'*60}")
        print(f"{Fore.BLUE}🔄 PHASE 3: ZONE TRANSFER TESTING")
        print(f"{'═'*60}{Style.RESET_ALL}")
        
        if not ns_list:
            print(f"{Fore.YELLOW}[!] No NS servers found")
        else:
            vulnerable_ns = []
            for ns in ns_list:
                self.animate_loading(f"Testing {ns}", 1)
                hosts, err = self.zone_transfer(ns, domain)
                
                if hosts:
                    vulnerable_ns.append((ns, hosts))
                    print(f"{Fore.RED + Style.BRIGHT}[!] VULNERABLE: {ns}")
                    print(f"{Fore.GREEN}    └─ Retrieved {len(hosts)} records")
                    for host in hosts[:3]:  # Show first 3
                        print(f"{Fore.YELLOW}      • {host['name']} → {host['data']}")
                    if len(hosts) > 3:
                        print(f"{Fore.WHITE}      [...] and {len(hosts)-3} more")
                else:
                    print(f"{Fore.GREEN}[✓] {ns} - Secure")
            
            if vulnerable_ns:
                print(f"\n{Fore.RED + Style.BRIGHT}💀 CRITICAL: {len(vulnerable_ns)} nameservers allow zone transfers!")
        print()

        # Certificate Transparency
        print(f"{Fore.GREEN + Style.BRIGHT}{'═'*60}")
        print(f"{Fore.GREEN}📜 PHASE 4: CERTIFICATE TRANSPARENCY")
        print(f"{'═'*60}{Style.RESET_ALL}")
        
        subdomains, err = self.get_crtsh_subdomains(domain)
        all_subdomains = set(subdomains) if subdomains else set()
        
        if subdomains:
            print(f"{Fore.GREEN}[✓] Found {len(subdomains)} subdomains:")
            for i, sub in enumerate(subdomains[:15], 1):
                print(f"{Fore.WHITE}  [{i:2}] {Fore.CYAN}{sub}")
            if len(subdomains) > 15:
                print(f"{Fore.WHITE}  [...] and {len(subdomains)-15} more")
        else:
            print(f"{Fore.YELLOW}[!] No subdomains found in certificate logs")
        print()

        # Bruteforce if enabled
        if brute or full:
            print(f"{Fore.CYAN + Style.BRIGHT}{'═'*60}")
            print(f"{Fore.CYAN}💥 PHASE 5: SUBDOMAIN BRUTEFORCE")
            print(f"{'═'*60}{Style.RESET_ALL}")
            
            brute_subs, err = self.brute_force_subdomains(domain, wordlist_size)
            if brute_subs:
                new_subs = [sub for sub in brute_subs if sub not in all_subdomains]
                print(f"{Fore.GREEN}[+] Found {len(new_subs)} new subdomains:")
                for sub in new_subs:
                    print(f"{Fore.WHITE}    └─ {Fore.GREEN}{sub}")
                    all_subdomains.add(sub)
            else:
                print(f"{Fore.YELLOW}[!] No additional subdomains found")
            print()

        # Live Host Detection
        if all_subdomains or full:
            print(f"{Fore.YELLOW + Style.BRIGHT}{'═'*60}")
            print(f"{Fore.YELLOW}🌐 PHASE 6: LIVE HOST DETECTION")
            print(f"{'═'*60}{Style.RESET_ALL}")
            
            targets = list(all_subdomains) + [domain]
            live_hosts = []
            
            def check_host(host):
                if not self.running:
                    return None
                try:
                    ip = socket.gethostbyname(host)
                    return host, ip
                except:
                    return None
            
            with ThreadPoolExecutor(max_workers=30) as executor:
                futures = {executor.submit(check_host, host): host for host in targets}
                
                completed = 0
                total = len(targets)
                
                for future in as_completed(futures):
                    if not self.running:
                        break
                        
                    completed += 1
                    result = future.result()
                    if result:
                        live_hosts.append(result)
                    
                    progress = (completed / total) * 100
                    print(f"\r{Fore.BLUE}🔍 Checking hosts... {completed}/{total} ({progress:.1f}%)", end="", flush=True)
            
            print(f"\r{Fore.GREEN}[✓] Found {len(live_hosts)} live hosts{' '*30}")
            
            # Quick port scan on live hosts
            if live_hosts:
                print(f"\n{Fore.MAGENTA}[🔧] Quick port scan on live hosts:")
                for host, ip in live_hosts[:5]:  # Limit to first 5
                    open_ports = self.port_scan_host(ip)
                    if open_ports:
                        ports_str = ', '.join([f"{port}({service})" for port, service in open_ports])
                        print(f"{Fore.WHITE}  └─ {Fore.CYAN}{host} → {Fore.GREEN}{ip} → {Fore.YELLOW}{ports_str}")
                    else:
                        print(f"{Fore.WHITE}  └─ {Fore.CYAN}{host} → {Fore.GREEN}{ip} → {Fore.RED}No common ports")
            print()

        # Final Summary
        print(f"{Fore.WHITE + Style.BRIGHT}{'═'*60}")
        print(f"{Fore.WHITE}📊 RECONNAISSANCE SUMMARY")
        print(f"{'═'*60}{Style.RESET_ALL}")
        
        total_records = sum(len(recs) for recs in all_records.values() if isinstance(recs, list))
        
        print(f"{Fore.CYAN}[📈] Statistics:")
        print(f"    ├─ DNS Records: {Fore.WHITE}{total_records}")
        print(f"    ├─ Subdomains: {Fore.WHITE}{len(all_subdomains)}")
        print(f"    ├─ Live Hosts: {Fore.WHITE}{len(live_hosts) if 'live_hosts' in locals() else 'N/A'}")
        print(f"    ├─ Vulnerabilities: {Fore.WHITE}{len(vulnerabilities)}")
        print(f"    └─ Nameservers: {Fore.WHITE}{len(ns_list)}")
        
        if vulnerabilities:
            print(f"\n{Fore.RED + Style.BRIGHT}[⚠️] Security Issues Found:")
            for vuln in vulnerabilities:
                severity_icon = '🔴' if vuln['severity'] == 'HIGH' else '🟡'
                print(f"    {severity_icon} {vuln['type']}: {vuln['impact']}")
        
        print(f"\n{Fore.GREEN + Style.BRIGHT}[🎉] Reconnaissance completed!")
        print(f"{Fore.MAGENTA}[👻] Ghost out! Happy hunting, elite hacker! 🔥")

def main():
    parser = argparse.ArgumentParser(description="Ghost DNS Recon - Advanced DNS Enumeration")
    parser.add_argument("domain", help="Domain to enumerate")
    parser.add_argument("--brute", "-b", action="store_true", help="Enable subdomain bruteforce")
    parser.add_argument("--full", "-f", action="store_true", help="Full comprehensive scan")
    parser.add_argument("--wordlist", "-w", choices=["small", "medium", "large"], default="medium", help="Bruteforce wordlist size")
    
    args = parser.parse_args()
    
    recon = DNSRecon()
    signal.signal(signal.SIGINT, recon.handle_interrupt)
    
    try:
        recon.run_scan(args.domain, args.brute, args.full, args.wordlist)
    except KeyboardInterrupt:
        recon.handle_interrupt(None, None)
    except Exception as e:
        print(f"{Fore.RED}[💥] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
