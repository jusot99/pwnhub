#!/bin/bash
# root-hunter.sh — Jusot99's Ultimate Linux Privilege Escalation Recon Tool
# Author: @jusot99 | Elite Hacker Mode

set -e

# Colors & Animations
B="\e[1m"
G="\e[32m"
Y="\e[33m"
R="\e[31m"
C="\e[36m"
RESET="\e[0m"
SPINNER=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')

# Functions
banner() {
  echo -e "\n${B}${G}"
  cat <<"EOF"
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
██║  ███╗███████║██║   ██║███████╗   ██║   
██║   ██║██╔══██║██║   ██║╚════██║   ██║   
╚██████╔╝██║  ██║╚██████╔║███████║   ██║   
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
EOF
  echo -e "${RESET}${C}         Ghost PrivEsc v2.0 by jusot99${RESET}\n"
}

spin() {
  local pid=$1
  local text=$2
  local spin_idx=0

  while kill -0 $pid 2>/dev/null; do
    printf "\r${C}${SPINNER[$spin_idx]}${RESET} ${text}..."
    spin_idx=$(((spin_idx + 1) % ${#SPINNER[@]}))
    sleep 0.1
  done
  printf "\r${G}✅${RESET} ${text} completed\n"
}

section() { echo -e "\n${B}${G}==> $1${RESET}"; }
warn() { echo -e "${R}[!] $1${RESET}"; }
info() { echo -e "${Y}[*] $1${RESET}"; }
success() { echo -e "${G}[+] $1${RESET}"; }

# Check essential tools
check_tools() {
  section "System Reconnaissance"
  info "Checking available tools..."

  local tools=("curl" "wget" "find" "python3" "sudo" "ss" "uname" "getcap")
  local missing=()

  for tool in "${tools[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing+=("$tool")
    fi
  done

  if [ ${#missing[@]} -gt 0 ]; then
    warn "Missing tools: ${missing[*]}"
  else
    success "All essential tools available"
  fi
}

# System Identity
system_identity() {
  section "System Identity"
  info "Gathering system information..."

  (
    echo -e "${Y}User:${RESET} $(whoami)"
    echo -e "${Y}UID:${RESET} $(id)"
    echo -e "${Y}Hostname:${RESET} $(hostname -f 2>/dev/null || hostname)"
    echo -e "${Y}Kernel:${RESET} $(uname -a)"
    echo -e "${Y}OS:${RESET} $(grep PRETTY /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"')"
  ) &
  spin $! "System identity"
}

# Privilege Escalation Vectors
privilege_checks() {
  section "Privilege Escalation Vectors"

  # Sudo permissions
  (
    sudo -l 2>/dev/null | head -20 >/tmp/sudo_out
    if [ -s /tmp/sudo_out ]; then
      echo -e "${G}SUDO Permissions:${RESET}"
      cat /tmp/sudo_out
    else
      warn "No sudo permissions or sudo not available"
    fi
  ) &
  spin $! "Sudo checks"

  # SUID binaries
  (
    find / -perm -4000 -type f 2>/dev/null | grep -vE "/snap|/proc|/sys" >/tmp/suid_out
    if [ -s /tmp/suid_out ]; then
      echo -e "\n${G}SUID Binaries:${RESET}"
      head -20 /tmp/suid_out
    fi
  ) &
  spin $! "SUID scan"

  # Capabilities
  (if command -v getcap >/dev/null; then
    getcap -r / 2>/dev/null | head -10 >/tmp/cap_out
    if [ -s /tmp/cap_out ]; then
      echo -e "\n${G}Capabilities:${RESET}"
      cat /tmp/cap_out
    fi
  fi) &
  spin $! "Capabilities scan"
}

# Container & Service Detection
container_checks() {
  section "Container & Service Analysis"

  (
    if grep -qa docker /proc/1/cgroup 2>/dev/null; then
      warn "Inside Docker container"
      [ -S /var/run/docker.sock ] && success "Docker socket available"
    fi

    getent group | grep -q docker && warn "User in docker group"
    getent group | grep -q lxd && warn "User in lxd group"
  ) &
  spin $! "Container checks"
}

# Network Recon
network_scan() {
  section "Network Reconnaissance"

  (
    echo -e "${Y}Network Interfaces:${RESET}"
    ip a 2>/dev/null | grep -E "^[0-9]|inet" | head -20
  ) &
  spin $! "Network interfaces"

  (
    echo -e "\n${Y}Listening Services:${RESET}"
    ss -tunlp 2>/dev/null | head -20
  ) &
  spin $! "Service discovery"

  (if command -v curl >/dev/null; then
    echo -e "\n${Y}Public IP:${RESET} $(curl -s ifconfig.me)" 2>/dev/null
  fi) &
  spin $! "External IP check"
}

# Process Analysis
process_scan() {
  section "Process Analysis"

  (
    echo -e "${Y}Notable Processes:${RESET}"
    ps aux 2>/dev/null | grep -E "root|nc|python|php|perl|java" | grep -v grep | head -15
  ) &
  spin $! "Process scan"
}

# Cron & Automation
cron_checks() {
  section "Scheduled Tasks"

  (
    crontab -l 2>/dev/null | head -10 >/tmp/cron_user
    if [ -s /tmp/cron_user ]; then
      echo -e "${G}User Crontab:${RESET}"
      cat /tmp/cron_user
    fi

    ls -la /etc/cron* 2>/dev/null | head -10
  ) &
  spin $! "Cron jobs"
}

# File System Analysis
filesystem_scan() {
  section "File System Analysis"

  (
    echo -e "${Y}Interesting Mounts:${RESET}"
    mount | grep -E "nfs|tmpfs|overlay" | head -10
  ) &
  spin $! "Mount points"

  (
    echo -e "\n${Y}Writable Sensitive Paths:${RESET}"
    find /etc -type f -writable 2>/dev/null | head -10
  ) &
  spin $! "Writable paths"
}

# Loot Discovery
loot_scan() {
  section "Loot & Secrets"

  (
    echo -e "${Y}Bash History:${RESET}"
    tail -5 ~/.bash_history 2>/dev/null
  ) &
  spin $! "History check"

  (if [ -d ~/.ssh ]; then
    echo -e "\n${Y}SSH Directory:${RESET}"
    ls -la ~/.ssh 2>/dev/null
  fi) &
  spin $! "SSH keys"

  (
    echo -e "\n${Y}Interesting Files:${RESET}"
    find / -type f \( -name "*.pem" -o -name "id_rsa" -o -name "*.key" -o -name "*password*" \) 2>/dev/null | grep -v "/proc" | head -10
  ) &
  spin $! "File discovery"
}

# Auto Tools Download
auto_tools() {
  section "Automated Enumeration Tools"

  if command -v curl >/dev/null || command -v wget >/dev/null; then
    mkdir -p /tmp/ghost-recon
    cd /tmp/ghost-recon

    (
      if command -v curl >/dev/null; then
        curl -sL https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh -o linpeas.sh 2>/dev/null
      else
        wget -q https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh 2>/dev/null
      fi
      [ -f linpeas.sh ] && chmod +x linpeas.sh && success "LinPEAS downloaded"
    ) &
    spin $! "Downloading LinPEAS"

    (
      if command -v curl >/dev/null; then
        curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o pspy64 2>/dev/null
      else
        wget -q https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 2>/dev/null
      fi
      [ -f pspy64 ] && chmod +x pspy64 && success "pspy downloaded"
    ) &
    spin $! "Downloading pspy"

    echo -e "\n${G}Tools available in: /tmp/ghost-recon/${RESET}"
  else
    warn "curl/wget not available - skipping tool downloads"
  fi
}

# Cleanup function
cleanup() {
  section "Cleanup"
  info "Cleaning temporary files..."
  rm -rf /tmp/sudo_out /tmp/suid_out /tmp/cap_out /tmp/cron_user /tmp/ghost-recon 2>/dev/null
  success "Temporary files cleaned"
}

# Main execution
main() {
  clear
  banner
  sleep 1

  # Parse arguments
  case "${1:-}" in
  "--auto-tools")
    AUTO_TOOLS=true
    ;;
  "--clean")
    CLEANUP=true
    ;;
  esac

  check_tools
  system_identity
  privilege_checks
  container_checks
  network_scan
  process_scan
  cron_checks
  filesystem_scan
  loot_scan

  if [ "$AUTO_TOOLS" = true ]; then
    auto_tools
  fi

  if [ "$CLEANUP" = true ]; then
    cleanup
  fi

  section "Reconnaissance Complete"
  echo -e "${G}👻 Ghost recon finished. Check above for privilege escalation vectors.${RESET}"
  echo -e "${Y}Next steps:${RESET}"
  echo -e "  • Review SUDO/SUID findings"
  echo -e "  • Check writable paths"
  echo -e "  • Analyze running services"
  echo -e "  • Use downloaded tools if needed\n"
}

# Signal handling
trap 'cleanup; exit 130' INT

main "$@"
