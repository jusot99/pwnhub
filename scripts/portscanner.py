#!/usr/bin/env python3
import socket
import threading
import argparse
from queue import Queue
from colorama import Fore, Style, init
import datetime
import time
import sys
import random

init(autoreset=True)

class PortScanner:
    def __init__(self):
        self.open_ports = []
        self.scanned = 0
        self.total_ports = 0
        self.running = True
        self.spinner = ['⣾','⣽','⣻','⢿','⡿','⣟','⣯','⣷']
        self.spinner_idx = 0
        
    def banner(self):
        print(Fore.RED + Style.BRIGHT + """
╔═╗╔═╗╔╦╗╔═╗╦  ╦  ╔═╗╔═╗╔╦╗╔═╗╔╦╗
║ ╦╠═╝║║║╠═╣║  ║  ║  ║ ║║║║╠═╣ ║ 
╚═╝╩  ╩ ╩╩ ╩╩═╝╩═╝╚═╝╚═╝╩ ╩╩ ╩ ╩ 
        """ + Fore.YELLOW + "by jusot99" + Fore.CYAN + " | Ethical Scanning Only!\n")

    def get_service(self, port):
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
            80: "HTTP", 443: "HTTPS", 110: "POP3", 143: "IMAP", 993: "IMAPS",
            995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 5601: "Kibana"
        }
        return services.get(port, "Unknown")

    def grab_banner(self, sock):
        try:
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:100] if banner else "No banner"
        except:
            return "No banner"

    def scan_port(self, target, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    banner = self.grab_banner(sock)
                    service = self.get_service(port)
                    return port, service, banner
        except:
            pass
        return None

    def worker(self, target, ports_queue):
        while not ports_queue.empty() and self.running:
            port = ports_queue.get()
            result = self.scan_port(target, port)
            if result:
                port, service, banner = result
                self.open_ports.append((port, service, banner))
                print(f"{Fore.GREEN}🎯 {target}:{port} | {service} | {banner}")
            self.scanned += 1
            ports_queue.task_done()

    def progress_animation(self):
        while self.running and self.scanned < self.total_ports:
            progress = (self.scanned / self.total_ports) * 100
            bar = "█" * int(progress / 2) + "░" * (50 - int(progress / 2))
            spinner = self.spinner[self.spinner_idx % len(self.spinner)]
            self.spinner_idx += 1
            print(f"\r{Fore.CYAN}{spinner} Scanning: [{bar}] {progress:.1f}% ({self.scanned}/{self.total_ports})", end="", flush=True)
            time.sleep(0.1)
        print()

    def resolve_target(self, target):
        try:
            ip = socket.gethostbyname(target)
            return ip
        except socket.gaierror:
            print(f"{Fore.RED}❌ Cannot resolve: {target}")
            sys.exit(1)

    def scan(self, target, start_port, end_port, threads):
        target_ip = self.resolve_target(target)
        self.total_ports = end_port - start_port + 1
        
        print(f"{Fore.YELLOW}🎯 Target: {target} ({target_ip})")
        print(f"{Fore.YELLOW}📊 Ports: {start_port}-{end_port} | Threads: {threads}")
        print(f"{Fore.YELLOW}⏰ Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        ports_queue = Queue()
        for port in range(start_port, end_port + 1):
            ports_queue.put(port)

        # Start progress animation
        progress_thread = threading.Thread(target=self.progress_animation, daemon=True)
        progress_thread.start()

        # Start scanning threads
        thread_list = []
        for _ in range(threads):
            thread = threading.Thread(target=self.worker, args=(target_ip, ports_queue))
            thread_list.append(thread)
            thread.start()

        # Wait for completion
        try:
            for thread in thread_list:
                thread.join()
        except KeyboardInterrupt:
            self.running = False
            print(f"\n{Fore.RED}🛑 Scan interrupted by user!")
            return

        self.running = False
        time.sleep(0.2)  # Let progress thread finish

    def save_results(self, target):
        if not self.open_ports:
            print(f"{Fore.RED}📭 No open ports found")
            return

        filename = f"{target.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(f"Port Scan Results - {target}\n")
            f.write(f"Scanned: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Open ports: {len(self.open_ports)}\n\n")
            for port, service, banner in sorted(self.open_ports):
                f.write(f"Port {port}: {service} | {banner}\n")
        
        print(f"{Fore.GREEN}💾 Results saved: {filename}")

    def show_summary(self):
        if self.open_ports:
            print(f"\n{Fore.CYAN}📈 SCAN SUMMARY:")
            print(f"{Fore.GREEN}✅ Open ports: {len(self.open_ports)}")
            for port, service, banner in sorted(self.open_ports):
                print(f"   {Fore.YELLOW}└─ {port}/tcp - {service}")
        else:
            print(f"\n{Fore.RED}📭 No open ports discovered")

def main():
    scanner = PortScanner()
    scanner.banner()
    
    parser = argparse.ArgumentParser(description="Advanced Port Scanner")
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range (default: 1-1000)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Threads (default: 50)")
    
    args = parser.parse_args()
    
    try:
        # Parse port range
        if "-" in args.ports:
            start_port, end_port = map(int, args.ports.split("-"))
        else:
            start_port = end_port = int(args.ports)
        
        # Validate inputs
        if start_port < 1 or end_port > 65535:
            print(f"{Fore.RED}❌ Ports must be between 1-65535")
            return
        
        if args.threads < 1 or args.threads > 500:
            print(f"{Fore.RED}❌ Threads must be between 1-500")
            return
            
    except ValueError:
        print(f"{Fore.RED}❌ Invalid port format. Use: 80 or 1-1000")
        return

    try:
        scanner.scan(args.target, start_port, end_port, args.threads)
        scanner.show_summary()
        scanner.save_results(args.target)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}🚪 Exiting...")
    except Exception as e:
        print(f"{Fore.RED}💥 Error: {e}")

if __name__ == "__main__":
    main()
