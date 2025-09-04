import scapy.all as scapy
import psutil
import argparse
from colorama import Fore, Style, init
from datetime import datetime

# Initialize colorama
init(autoreset=True)

# For deduplication (prevent spam alerts)
detected_arp_spoofs = set()
detected_icmp_redirects = set()

def print_banner():
    banner = f"""{Style.BRIGHT}{Fore.RED}

⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀
⠀⠀⠀⣀⣀⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀
⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀
⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀
⠀⠀⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀
⠀⠀⠀⠀⠈⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⣿⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠀

{Style.BRIGHT}{Fore.CYAN}          [ ETHICAL NETWORK THREAT DETECTOR ]
{Style.BRIGHT}{Fore.YELLOW}            Created by Jusot99
"""
    print(banner)

def log_event(msg):
    now = datetime.now().strftime("%H:%M:%S")
    print(f"{Fore.CYAN}[{now}] {msg}")

def detect_arp_spoof(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            ip = packet[scapy.ARP].psrc
            real_mac = scapy.getmacbyip(ip)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac and real_mac != response_mac:
                if (ip, response_mac) not in detected_arp_spoofs:
                    detected_arp_spoofs.add((ip, response_mac))
                    log_event(f"{Fore.YELLOW}[!] ARP Spoofing Detected:")
                    print(f"{Fore.RED}    IP: {ip} | Fake MAC: {response_mac} | Real MAC: {real_mac}")
        except Exception:
            pass

def detect_dns_spoof(packet):
    if packet.haslayer(scapy.DNSRR) and packet.haslayer(scapy.DNSQR):
        qname = packet[scapy.DNSQR].qname.decode()
        spoofed_ip = packet[scapy.DNSRR].rdata
        log_event(f"{Fore.MAGENTA}[!] DNS Spoofing Detected:")
        print(f"{Fore.RED}    Domain: {qname} | Spoofed IP: {spoofed_ip}")

def detect_icmp_redirect(packet):
    if packet.haslayer(scapy.ICMP) and packet[scapy.ICMP].type == 5:
        router_ip = packet[scapy.IP].src
        target_ip = packet[scapy.IP].dst
        if (router_ip, target_ip) not in detected_icmp_redirects:
            detected_icmp_redirects.add((router_ip, target_ip))
            log_event(f"{Fore.BLUE}[!] ICMP Redirect Detected:")
            print(f"{Fore.RED}    Router: {router_ip} is redirecting traffic to: {target_ip}")

def sniff(interface):
    log_event(f"[+] Sniffing on interface: {interface}...\n")
    scapy.sniff(iface=interface, store=False, prn=analyze_packet)

def analyze_packet(packet):
    detect_arp_spoof(packet)
    detect_icmp_redirect(packet)
    if packet.haslayer(scapy.DNS):
        detect_dns_spoof(packet)

def get_default_interface():
    return list(psutil.net_if_stats().keys())[0]

def main():
    parser = argparse.ArgumentParser(description="Ethical Network Threat Detector")
    parser.add_argument('-i', '--interface', type=str, help="Network interface to sniff on (e.g., wlan0)", default=None)
    args = parser.parse_args()

    print_banner()

    interface = args.interface if args.interface else get_default_interface()
    sniff(interface)

if __name__ == "__main__":
    main()

# sudo python3 secforce.py -> for sniffing the lo (loopback) interface, which is usually used for internal communications within the local machine.
# sudo python3 secforce.py -i wlan0 -> for detecting network threats on a local area network (LAN).
