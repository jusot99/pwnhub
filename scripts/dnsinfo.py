#!/usr/bin/env python3

import argparse
import dns.resolver
import dns.query
import dns.zone
from colorama import init, Fore, Style

init(autoreset=True)

BANNER = f"""
{Fore.GREEN + Style.BRIGHT}
    ██████  ██   ██ ███    ██ ██   ██ ██ ███    ██
    ██      ██   ██ ████   ██ ██   ██ ██ ████   ██
    █████   ███████ ██ ██  ██ ███████ ██ ██ ██  ██
    ██      ██   ██ ██  ██ ██ ██   ██ ██ ██  ██ ██
    ██      ██   ██ ██   ████ ██   ██ ██ ██   ████

                {Fore.WHITE + Style.BRIGHT}DNS Info & Recon by Elimane
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
        names = zone.nodes.keys()
        hosts = []
        for n in names:
            hosts.append(str(n))
        return hosts, None
    except Exception as e:
        return None, e

def main():
    parser = argparse.ArgumentParser(description="DNS Enumeration Tool")
    parser.add_argument("domain", help="Domain or IP to enumerate")
    args = parser.parse_args()

    print(Fore.CYAN + BANNER)
    print(f"[+] Resolving DNS for: {Fore.YELLOW}{args.domain}\n")

    # Query A records
    answers, err = query_records(args.domain, "A")
    print(Fore.GREEN + "[A Record]")
    if answers:
        for rdata in answers:
            print(f" → {rdata.address}")
    elif err:
        print(Fore.RED + f" ✖ A Record Error: {err}")
    else:
        print(" → No A record found.")
    print()

    # Query AAAA records
    answers, err = query_records(args.domain, "AAAA")
    print(Fore.GREEN + "[AAAA Record]")
    if answers:
        for rdata in answers:
            print(f" → {rdata.address}")
    elif err:
        print(Fore.RED + f" ✖ AAAA Record Error: {err}")
    else:
        print(" → No AAAA record found.")
    print()

    # Query MX records
    answers, err = query_records(args.domain, "MX")
    print(Fore.GREEN + "[MX Record]")
    if answers:
        for rdata in answers:
            print(f" → {rdata.preference} {rdata.exchange}")
    elif err:
        print(Fore.RED + f" ✖ MX Record Error: {err}")
    else:
        print(" → No MX record found.")
    print()

    # Query NS records
    answers, err = query_records(args.domain, "NS")
    print(Fore.GREEN + "[NS Record]")
    ns_list = []
    if answers:
        for rdata in answers:
            ns = str(rdata.target).rstrip('.')
            ns_list.append(ns)
            print(f" → {ns}")
    elif err:
        print(Fore.RED + f" ✖ NS Record Error: {err}")
    else:
        print(" → No NS record found.")
    print()

    # Query TXT records
    answers, err = query_records(args.domain, "TXT")
    print(Fore.GREEN + "[TXT Record]")
    if answers:
        for rdata in answers:
            # TXT records are list of strings, join them
            txt = ''.join([part.decode() if isinstance(part, bytes) else part for part in rdata.strings]) if hasattr(rdata, 'strings') else str(rdata)
            print(f" → {txt}")
    elif err:
        print(Fore.RED + f" ✖ TXT Record Error: {err}")
    else:
        print(" → No TXT record found.")
    print()

    # Query CNAME record
    answers, err = query_records(args.domain, "CNAME")
    print(Fore.GREEN + "[CNAME Record]")
    if answers:
        for rdata in answers:
            print(f" → {rdata.target}")
    elif err:
        print(Fore.RED + f" ✖ CNAME Error: {err}")
    else:
        print(" → No CNAME record found.")
    print()

    # Zone Transfer test
    print(Fore.GREEN + "[Zone Transfer Test]")
    if not ns_list:
        print(" → No NS records found, skipping zone transfer test.")
    else:
        for ns in ns_list:
            print(f" → Trying NS: {ns}")
            hosts, err = zone_transfer(ns, args.domain)
            if hosts:
                print(Fore.YELLOW + f"   ✔ Zone transfer successful! Found {len(hosts)} entries:")
                for h in hosts:
                    print(f"     - {h}")
            else:
                print(Fore.RED + f"   ✖ Failed on {ns}: {err}")
    print()

if __name__ == "__main__":
    main()
