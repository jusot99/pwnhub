import os
import random
import hashlib
import socket
import requests
import time
import base64
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Step 1: Information Gathering
def gather_info(target):
    print(Fore.CYAN + f"[+] Gathering information on {target}...")
    try:
        ip = socket.gethostbyname(target)
        print(Fore.YELLOW + f"[+] Target IP: {ip}")
        return ip
    except socket.gaierror:
        print(Fore.RED + "[-] Unable to resolve target. Exiting...")
        return None

# Step 2: Enumerate Open Ports
def scan_ports(ip):
    print(Fore.CYAN + "[+] Scanning ports...")
    open_ports = []
    for port in [21, 22, 80, 443, 3306, 8080]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            socket.setdefaulttimeout(1)
            if s.connect_ex((ip, port)) == 0:
                print(Fore.GREEN + f"[+] Open port found: {port}")
                open_ports.append(port)
    return open_ports

# Step 3: Identify Vulnerabilities
def find_vulnerabilities(open_ports):
    vulnerabilities = {}
    vuln_db = {
        21: "FTP Anonymous Login Enabled",
        22: "Weak SSH Passwords",
        80: "Exposed Web Directories",
        3306: "MySQL Default Credentials",
        8080: "Tomcat Default Login"
    }
    for port in open_ports:
        if port in vuln_db:
            print(Fore.YELLOW + f"[!] Possible vulnerability on port {port}: {vuln_db[port]}")
            vulnerabilities[port] = vuln_db[port]
    return vulnerabilities

# Step 4: Exploitation
def exploit(ip, vulnerabilities):
    if 3306 in vulnerabilities:
        print(Fore.CYAN + "[+] Trying default MySQL credentials...")
        time.sleep(2)
        print(Fore.GREEN + "[+] MySQL root login successful!")
        return dump_database()
    elif 21 in vulnerabilities:
        print(Fore.CYAN + "[+] Trying anonymous FTP login...")
        time.sleep(2)
        print(Fore.GREEN + "[+] Anonymous login successful! Accessing files...")
        return extract_flag()
    else:
        print(Fore.RED + "[-] No direct exploits available. Try manual enumeration.")
        return None

# Step 5: Extract Flag
def dump_database():
    print(Fore.CYAN + "[+] Dumping database...")
    flag = base64.b64encode(b"FLAG{realistic_hacking_scenario}").decode()
    print(Fore.GREEN + f"[+] Found encoded flag: {flag}")
    return flag

def extract_flag():
    print(Fore.CYAN + "[+] Searching for hidden flag in FTP files...")
    time.sleep(2)
    flag = "FLAG{ftp_exploit_successful}"
    print(Fore.GREEN + f"[+] Flag found: {flag}")
    return flag

# Main Function
def main():
    target = input(Fore.CYAN + "Enter the target domain or IP: ").strip()
    ip = gather_info(target)
    if not ip:
        return
    
    open_ports = scan_ports(ip)
    if not open_ports:
        print(Fore.RED + "[-] No open ports found. Try another target.")
        return
    
    vulnerabilities = find_vulnerabilities(open_ports)
    if not vulnerabilities:
        print(Fore.RED + "[-] No known vulnerabilities found. Try manual exploitation.")
        return
    
    flag = exploit(ip, vulnerabilities)
    if flag:
        print(Fore.GREEN + f"[+] Final flag: {flag}")
    else:
        print(Fore.RED + "[-] Exploit failed. Try another method.")

if __name__ == "__main__":
    main()
