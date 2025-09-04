#!/bin/bash
# Jusot99's Enum Script - Quick Recon after Foothold
# Author: @jusot99 | Ghost Hacker Mode

# Colors
BOLD="\e[1m"
BLUE="\e[34m"
GREEN="\e[32m"
YELLOW="\e[33m"
RESET="\e[0m"

section() {
  echo -e "\n${BOLD}${BLUE}==================[+] $1 =================${RESET}"
}

sub() {
  echo -e "${GREEN}[$1]${RESET}"
}

highlight() {
  echo -e "${YELLOW}$1${RESET}"
}

# ---------------- START ENUM ----------------

section "User Info"
highlight "whoami:"; whoami
highlight "id:"; id
highlight "hostname -f:"; hostname -f
highlight "SHELL: $SHELL"
highlight "HOME: $HOME"
highlight "PATH: $PATH"

section "System Info"
highlight "uname -a:"; uname -a
cat /etc/os-release 2>/dev/null || cat /etc/issue

section "Filesystem"
highlight "pwd:"; pwd
ls -la
df -h
highlight "Mounts:"; mount | column -t
sub "SUID Binaries"
find / -perm -4000 -type f 2>/dev/null

section "Users & Groups"
sub "Users"; cut -d: -f1 /etc/passwd
sub "Groups"; cat /etc/group
sub "Logged In"; who
w
last -a | head

section "Network Info"
ip a
ip r
sub "Listening Ports"; ss -tunlp
sub "ARP Table"; arp -a
sub "Public IP"; curl -s ifconfig.me

section "Processes"
ps aux | head -n 20
sub "Process Tree"; pstree | head -n 20

section "Privilege Checks"
groups
sub "Sudo Permissions"; sudo -l 2>/dev/null

section "Languages/Tools"
which python && python --version 2>/dev/null
which python3 && python3 --version
which perl && perl -v | head -n 1
which ruby && ruby -v
which gcc && gcc --version | head -n 1

section "Cron Jobs"
crontab -l 2>/dev/null
ls -la /etc/cron*
cat /etc/crontab 2>/dev/null

section "Interesting Files"
sub "Bash History"; cat ~/.bash_history 2>/dev/null
sub "SSH Keys"; ls -la ~/.ssh/ 2>/dev/null
cat ~/.ssh/id_rsa 2>/dev/null
cat ~/.ssh/authorized_keys 2>/dev/null
sub "Config Files"; find / -name "*config*" 2>/dev/null | grep -v "/usr"

echo -e "\n${BOLD}${GREEN}[+] Done. You’re now ghosting this box like a pro.${RESET}"
