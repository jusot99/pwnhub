#!/usr/bin/env python3

import argparse
import dns.resolver
import dns.query
import dns.zone
import subprocess
import json
from colorama import init, Fore, Style

init(autoreset=True)

BANNER = f"""
{Fore.GREEN + Style.BRIGHT}
    ██████  ██   ██ ███    ██ ██   ██ ██ ███    ██
    ██      ██   ██ ████   ██ ██   ██ ██ ████   ██
    █████   ███████ ██ ██  ██ ███████ ██ ██ ██  ██
    ██      ██   ██ ██  ██ ██ ██   ██ ██ ██  ██ ██
    ██      ██   ██ ██   ████ ██   ██ ██ ██   ████

         {Fore.WHITE + Style.BRIGHT}DNS Recon & Subdomain Hunt by Elimane
"""

def query_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
        if answers.rrset is None:
            return None, None
        return answers, None
    except Exception as e:
        return None, e

def zone_transfer(ns, domain):
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
        hosts = [str(n) for n in zone.nodes.keys()]
        return hosts, None
    except Exception as e:
        return None, e

def get_crtsh_subdomains(domain):
    try:
        result = subprocess.run(
            ["curl", "-s", f"https://crt.sh/?q=%25.{domain}&output=json"],
            capture_output=True, text=True, check=True
        )
        if not result.stdout.strip():
            return None, "Empty response from crt.sh"
        data = json.loads(result.stdout)
        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value")
            if name_value:
                for line in name_value.splitlines():
                    subdomains.add(line.strip())
        return sorted(subdomains), None
    except json.JSONDecodeError as e:
        return None, f"JSON Decode Error: {e}"
    except Exception as e:
        return None, e

def main():
    parser = argparse.ArgumentParser(description="DNS Enumeration Tool")
    parser.add_argument("domain", help="Domain to enumerate")
    args = parser.parse_args()
    domain = args.domain

    print(BANNER)
    print(f"{Fore.CYAN}[+] Domain Target: {Fore.YELLOW}{domain}\n")

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    ns_list = []

    for rtype in record_types:
        answers, err = query_records(domain, rtype)
        print(Fore.MAGENTA + f"[{rtype} Record]")
        if answers:
            for rdata in answers:
                if rtype == "MX":
                    print(Fore.WHITE + f" → {Fore.YELLOW}{rdata.preference} {rdata.exchange}")
                elif rtype == "TXT":
                    txt = ''.join([part.decode() if isinstance(part, bytes) else part for part in getattr(rdata, 'strings', [])])
                    print(Fore.WHITE + f" → {Fore.YELLOW}{txt}")
                else:
                    output = getattr(rdata, 'target', getattr(rdata, 'address', rdata))
                    print(Fore.WHITE + f" → {Fore.YELLOW}{output}")
                    if rtype == "NS":
                        ns_list.append(str(rdata.target).rstrip('.'))
        elif err:
            print(Fore.RED + f" ✖ Error: {str(err).strip() or 'Unknown error'}")
        else:
            print(Fore.YELLOW + " → No record found.")
        print()

    # Zone Transfer Test
    print(Fore.MAGENTA + "[Zone Transfer Test]")
    if not ns_list:
        print(Fore.YELLOW + " → Skipped (No NS Records)")
    else:
        for ns in ns_list:
            print(Fore.CYAN + f" → Trying NS: {ns}")
            hosts, err = zone_transfer(ns, domain)
            if hosts:
                print(Fore.GREEN + f"   ✔ Zone transfer successful! {len(hosts)} entries:")
                for h in hosts:
                    print(Fore.YELLOW + f"     - {h}")
            else:
                print(Fore.RED + f"   ✖ Failed: {str(err).strip() or 'Unknown reason'}")
    print()

    # crt.sh Subdomain Search
    print(Fore.MAGENTA + "[crt.sh Subdomain Enumeration]")
    subdomains, err = get_crtsh_subdomains(domain)
    if subdomains:
        for sub in subdomains:
            print(Fore.WHITE + f" → {Fore.YELLOW}{sub}")
    elif err:
        print(Fore.RED + f" ✖ crt.sh Error: {str(err).strip()}")
    else:
        print(Fore.YELLOW + " → No subdomains found.")

    print()

if __name__ == "__main__":
    main()
