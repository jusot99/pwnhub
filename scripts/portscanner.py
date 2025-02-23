import socket
import threading
import argparse
from queue import Queue
from colorama import Fore, Style, init
import datetime

# Initialize colorama
init(autoreset=True)

# Banner
def banner():
    print(Fore.RED + Style.BRIGHT + """
██████╗  ██████╗ ███████╗████████╗    ██████╗  ██████╗ ████████╗
██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝    ██╔══██╗██╔═══██╗╚══██╔══╝
██████╔╝██║   ██║███████╗   ██║       ██████╔╝██║   ██║   ██║
██╔═══╝ ██║   ██║╚════██║   ██║       ██╔═══╝ ██║   ██║   ██║
██║     ╚██████╔╝███████║   ██║       ██║     ╚██████╔╝   ██║
╚═╝      ╚═════╝ ╚══════╝   ╚═╝       ╚═╝      ╚═════╝    ╚═╝
    Network Port Scanner - For Ethical Hacking & Testing Only!
    """ + Fore.YELLOW + Style.BRIGHT + "Author: Elimane")

# Service detection
def get_service(port):
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS",
        110: "POP3", 143: "IMAP", 3306: "MySQL", 8080: "HTTP Proxy", 21: "FTP", 6379: "Redis"
    }
    return services.get(port, "Unknown Service")

# Scan port and get banner
def scan_port(target, port, results):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            conn = s.connect_ex((target, port))
            if conn == 0:
                try:
                    s.send(b'\n')  # Try to grab a banner
                    banner = s.recv(1024).decode().strip()
                except:
                    banner = "No banner retrieved"

                service = get_service(port)
                result = f"[OPEN] {target}:{port} - {service} - Banner: {banner}"
                print(Fore.GREEN + result)
                results.append(result)
    except Exception as e:
        pass

# Worker to handle threads
def worker(target, ports_queue, results):
    while not ports_queue.empty():
        port = ports_queue.get()
        scan_port(target, port, results)
        ports_queue.task_done()

def main():
    banner()
    parser = argparse.ArgumentParser(description="Network Port Scanner")
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("-p", "--ports", type=str, default="1-1024", help="Port range to scan (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    args = parser.parse_args()

    target = args.target
    port_range = args.ports
    threads = args.threads

    start_port, end_port = map(int, port_range.split("-"))
    ports_queue = Queue()

    for port in range(start_port, end_port + 1):
        ports_queue.put(port)

    results = []
    thread_list = []

    print(Fore.YELLOW + f"[INFO] Scanning {target} for open ports...")

    for _ in range(threads):
        thread = threading.Thread(target=worker, args=(target, ports_queue, results))
        thread_list.append(thread)
        thread.start()

    for thread in thread_list:
        thread.join()

    print(Fore.CYAN + "[INFO] Scan completed.")

    # Save results to a file named after the target IP/domain
    target_filename = f"{target.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_scan_results.txt"
    if results:
        with open(target_filename, "w") as f:
            for res in results:
                f.write(res + "\n")
        print(Fore.GREEN + f"[SAVED] Results saved to {target_filename}")
    else:
        print(Fore.RED + "[INFO] No open ports found.")

if __name__ == "__main__":
    main()

# python portscanner.py <target> -p <port_range> -t <number_of_threads>
# python portscanner.py 192.168.1.1 -p 1-1024 -t 20
# python portscanner.py 192.168.1.1 -p 80-100 -t 20
