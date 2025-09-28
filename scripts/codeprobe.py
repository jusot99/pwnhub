#!/usr/bin/env python3
from colorama import Fore, Style
import random, sys, requests, json, argparse
from datetime import datetime

banner = f"""{Fore.RED}
██╗  ██╗████████╗████████╗██████╗ 
██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗
███████║   ██║      ██║   ██████╔╝
██╔══██║   ██║      ██║   ██╔═══╝ 
██║  ██║   ██║      ██║   ██║     
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝     
{Fore.YELLOW}         by jusot99{Style.RESET_ALL}"""

codes = {100:("Continue","ℹ️",Fore.CYAN),101:("Switching Protocols","🔄",Fore.CYAN),200:("OK","✅",Fore.GREEN),
         201:("Created","✅",Fore.GREEN),301:("Moved Permanently","📦",Fore.BLUE),302:("Found","🔍",Fore.BLUE),
         400:("Bad Request","⚠️",Fore.YELLOW),403:("Forbidden","🚫",Fore.YELLOW),404:("Not Found","❓",Fore.YELLOW),
         500:("Internal Server Error","💥",Fore.RED),503:("Service Unavailable","🔧",Fore.RED)}

parser = argparse.ArgumentParser(description='HTTP CodeProbe - Advanced HTTP Analysis')
parser.add_argument('-u','--url', help='Test URL status code')
parser.add_argument('-f','--file', help='Save results to file')
args = parser.parse_args()

def test_url(url):
    try:
        r = requests.get(url, timeout=5)
        code = r.status_code
        msg, icon, color = codes.get(code, (f"HTTP {code}", "🔍", Fore.WHITE))
        print(f"{icon} {color}{code}: {msg} | URL: {url}{Style.RESET_ALL}")
        if args.file:
            with open(args.file, 'a') as f:
                f.write(f"{datetime.now()} | {code} | {url}\n")
    except Exception as e:
        print(f"{Fore.RED}❌ Error testing {url}: {e}{Style.RESET_ALL}")

print(banner)
print(f"{Fore.CYAN}HTTP CodeProbe v2.0 | by jusot99 | 'help' for commands{Style.RESET_ALL}")

if args.url:
    test_url(args.url)
    sys.exit()

while True:
    try:
        cmd = input(f"{Fore.YELLOW}🔍> {Style.RESET_ALL}").strip().lower()
        if cmd in ['quit','exit']: break
        elif cmd == 'help': 
            print(f"{Fore.GREEN}Commands: <code>, random, range X-Y, test <url>, scan <file>, quit{Style.RESET_ALL}")
        elif cmd == 'random': 
            code = random.choice(list(codes.keys()))
            msg, icon, color = codes[code]
            print(f"{icon} {color}{code}: {msg}{Style.RESET_ALL}")
        elif cmd.startswith('test '):
            test_url(cmd[5:])
        elif cmd.startswith('scan '):
            try:
                with open(cmd[5:], 'r') as f:
                    for url in f.readlines():
                        test_url(url.strip())
            except: print(f"{Fore.RED}❌ File error{Style.RESET_ALL}")
        elif cmd.startswith('range'):
            try: 
                start, end = map(int, cmd.split()[1:3])
                [print(f"{codes[k][1]} {codes[k][2]}{k}: {codes[k][0]}{Style.RESET_ALL}") for k in codes if start<=k<=end]
            except: print(f"{Fore.RED}❌ Usage: range 200 400{Style.RESET_ALL}")
        elif cmd.isdigit(): 
            code = int(cmd)
            if code in codes: 
                msg, icon, color = codes[code]
                print(f"{icon} {color}{code}: {msg}{Style.RESET_ALL}")
                tips = {404:"💡 Resource not found",403:"💡 Access denied",500:"💡 Server error - check logs"}
                if code in tips: print(f"   {Fore.YELLOW}{tips[code]}{Style.RESET_ALL}")
            else: 
                print(f"{Fore.RED}❌ Unknown HTTP code{Style.RESET_ALL}")
                print(f"{Fore.CYAN}💡 Use 'range 100 600' to see all codes{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}🛑 Stay stealthy! - jusot99{Style.RESET_ALL}")
        break
