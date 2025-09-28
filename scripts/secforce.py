#!/usr/bin/env python3
import scapy.all as scapy
import psutil
import argparse
from colorama import Fore, Style, init
from datetime import datetime
import threading
import time
import sys

init(autoreset=True)

class SecForce:
    def __init__(self):
        self.detected_threats = set()
        self.running = True
        self.stats = {"arp_spoof": 0, "dns_spoof": 0, "icmp_redirect": 0, "port_scan": 0}
        
    def print_banner(self):
        banner = f"""{Style.BRIGHT}{Fore.RED}
    ╔═╗╔═╗╔═╗╦═╗╔═╗╔═╗╔╦╗╔═╗
    ╚═╗║ ║║ ║╠╦╝║╣ ║   ║ ║ ║
    ╚═╝╚═╝╚═╝╩╚═╚═╝╚═╝ ╩ ╚═╝
    {Fore.CYAN}    NETWORK THREAT DETECTOR v2.0
    {Fore.YELLOW}         by jusot99
    """
        print(banner)

    def log_event(self, msg, level="INFO"):
        now = datetime.now().strftime("%H:%M:%S")
        colors = {"INFO": Fore.CYAN, "WARN": Fore.YELLOW, "ALERT": Fore.RED}
        print(f"{colors.get(level, Fore.CYAN)}[{now}] {msg}{Style.RESET_ALL}")

    def detect_arp_spoof(self, packet):
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            try:
                ip = packet[scapy.ARP].psrc
                real_mac = scapy.getmacbyip(ip)
                response_mac = packet[scapy.ARP].hwsrc
                if real_mac and real_mac != response_mac:
                    threat_id = f"arp_{ip}_{response_mac}"
                    if threat_id not in self.detected_threats:
                        self.detected_threats.add(threat_id)
                        self.stats["arp_spoof"] += 1
                        self.log_event(f"🚨 ARP SPOOF DETECTED!", "ALERT")
                        print(f"    {Fore.RED}IP: {ip} | Fake MAC: {response_mac}")
                        print(f"    {Fore.YELLOW}Real MAC: {real_mac}")
            except: pass

    def detect_dns_spoof(self, packet):
        if packet.haslayer(scapy.DNSRR) and packet.haslayer(scapy.DNSQR):
            try:
                qname = packet[scapy.DNSQR].qname.decode()
                spoofed_ip = packet[scapy.DNSRR].rdata
                threat_id = f"dns_{qname}_{spoofed_ip}"
                if threat_id not in self.detected_threats:
                    self.detected_threats.add(threat_id)
                    self.stats["dns_spoof"] += 1
                    self.log_event(f"🌐 DNS SPOOF DETECTED!", "ALERT")
                    print(f"    {Fore.RED}Domain: {qname} | Spoofed IP: {spoofed_ip}")
            except: pass

    def detect_icmp_redirect(self, packet):
        if packet.haslayer(scapy.ICMP) and packet[scapy.ICMP].type == 5:
            try:
                router_ip = packet[scapy.IP].src
                target_ip = packet[scapy.IP].dst
                threat_id = f"icmp_{router_ip}_{target_ip}"
                if threat_id not in self.detected_threats:
                    self.detected_threats.add(threat_id)
                    self.stats["icmp_redirect"] += 1
                    self.log_event(f"🔄 ICMP REDIRECT DETECTED!", "WARN")
                    print(f"    {Fore.RED}Router {router_ip} redirecting to {target_ip}")
            except: pass

    def detect_port_scan(self, packet):
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 2:  # SYN scan
            src_ip = packet[scapy.IP].src
            threat_id = f"scan_{src_ip}"
            if threat_id not in self.detected_threats:
                self.detected_threats.add(threat_id)
                self.stats["port_scan"] += 1
                self.log_event(f"🔍 PORT SCAN DETECTED!", "WARN")
                print(f"    {Fore.RED}Scanner IP: {src_ip}")

    def show_stats(self):
        while self.running:
            time.sleep(10)
            self.log_event(f"📊 Stats: ARP({self.stats['arp_spoof']}) DNS({self.stats['dns_spoof']}) ICMP({self.stats['icmp_redirect']}) SCAN({self.stats['port_scan']})")

    def analyze_packet(self, packet):
        try:
            self.detect_arp_spoof(packet)
            self.detect_icmp_redirect(packet)
            self.detect_port_scan(packet)
            if packet.haslayer(scapy.DNS):
                self.detect_dns_spoof(packet)
        except Exception as e:
            pass

    def sniff(self, interface):
        self.log_event(f"🎯 Starting monitoring on {interface}...", "INFO")
        self.log_event("Press Ctrl+C to stop", "INFO")
        
        stats_thread = threading.Thread(target=self.show_stats, daemon=True)
        stats_thread.start()
        
        try:
            scapy.sniff(iface=interface, store=False, prn=self.analyze_packet, stop_filter=lambda x: not self.running)
        except PermissionError:
            self.log_event("❌ Permission denied! Run with sudo", "ALERT")
        except Exception as e:
            self.log_event(f"❌ Error: {e}", "ALERT")

    def get_interfaces(self):
        return psutil.net_if_stats().keys()

def main():
    detector = SecForce()
    detector.print_banner()
    
    parser = argparse.ArgumentParser(description="SecForce - Network Threat Detector")
    parser.add_argument('-i', '--interface', help="Network interface (e.g., wlan0, eth0)")
    parser.add_argument('-l', '--list', action='store_true', help="List available interfaces")
    
    args = parser.parse_args()
    
    if args.list:
        print(f"{Fore.CYAN}Available interfaces:{Style.RESET_ALL}")
        for iface in detector.get_interfaces():
            print(f"  {Fore.GREEN}{iface}{Style.RESET_ALL}")
        return
    
    interface = args.interface
    if not interface:
        interfaces = list(detector.get_interfaces())
        # Prefer non-loopback interfaces
        non_loopback = [i for i in interfaces if i != 'lo']
        interface = non_loopback[0] if non_loopback else interfaces[0]
        detector.log_event(f"Auto-selected interface: {interface}", "INFO")
    
    try:
        detector.sniff(interface)
    except KeyboardInterrupt:
        detector.running = False
        detector.log_event("🛑 Stopping SecForce...", "INFO")
        print(f"\n{Fore.CYAN}Final Stats:{Style.RESET_ALL}")
        for threat, count in detector.stats.items():
            print(f"  {Fore.YELLOW}{threat}: {count}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
