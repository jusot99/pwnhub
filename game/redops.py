import os
import time
import random
import hashlib
import socket
import subprocess
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Hidden flag (hard to find)
FLAG = "FLAG{p3rs1st3nc3_1s_k3y}"

def banner():
    print(Fore.RED + Style.BRIGHT + "\nRedOps: Cyber Intrusion Simulator")
    print(Fore.YELLOW + "A realistic hacking challenge. Can you find the flag?\n")

def network_scan():
    print(Fore.CYAN + "Scanning network...")
    time.sleep(2)
    print(Fore.YELLOW + "Discovered open ports:")
    print(Fore.GREEN + "22/tcp - SSH")
    print(Fore.GREEN + "80/tcp - HTTP")
    print(Fore.GREEN + "3306/tcp - MySQL")

    return True

def exploit_ssh():
    print(Fore.CYAN + "Brute-forcing SSH login...")
    time.sleep(3)

    users = ["admin", "root", "developer"]
    passwords = ["password123", "admin", "letmein"]

    for user in users:
        for pwd in passwords:
            hashed_pwd = hashlib.md5(pwd.encode()).hexdigest()
            if hashed_pwd.startswith("5f4dcc3b5aa765d61d8327deb882cf99"):  # Hash for 'password'
                print(Fore.GREEN + f"Success! Logged in as {user} with password {pwd}")
                return True

    print(Fore.RED + "Failed to log in. Try a different approach.")
    return False

def escalate_privileges():
    print(Fore.CYAN + "Checking for SUID binaries...")
    time.sleep(2)

    suid_binaries = ["/usr/bin/find", "/usr/bin/python3"]
    if "/usr/bin/find" in suid_binaries:
        print(Fore.GREEN + "Privilege escalation possible with find binary!")
        time.sleep(1)
        print(Fore.YELLOW + "Executing: find . -exec /bin/sh \; -quit")
        time.sleep(2)
        print(Fore.GREEN + "Root shell obtained! You now have full access.")
        return True

    print(Fore.RED + "No privilege escalation vectors found.")
    return False

def locate_flag():
    print(Fore.CYAN + "Searching for the flag...")
    time.sleep(2)
    hidden_dirs = ["/var/backups", "/home/dev/.config", "/opt/hidden"]

    if random.choice(hidden_dirs) == "/opt/hidden":
        print(Fore.GREEN + "Flag found in /opt/hidden!")
        print(Fore.YELLOW + f"\n{FLAG}\n")
        return True

    print(Fore.RED + "Flag not found. Keep searching.")
    return False

def main():
    banner()
    if network_scan():
        if exploit_ssh():
            if escalate_privileges():
                locate_flag()
            else:
                print(Fore.RED + "Privilege escalation failed.")
        else:
            print(Fore.RED + "Exploitation unsuccessful.")
    else:
        print(Fore.RED + "Network scan failed.")

if __name__ == "__main__":
    main()
