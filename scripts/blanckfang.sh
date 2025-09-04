#!/bin/bash

# BLACKFANG v1.0 - The Ruthless Linux Hardener
# By jusot99

LOG="/var/log/blackfang.log"
mkdir -p /var/log && touch $LOG && chmod 600 $LOG

RED="\e[31m"; GREEN="\e[32m"; BLUE="\e[34m"; NC="\e[0m"
banner() {
echo -e "${BLUE}
██████╗ ██╗      █████╗  ██████╗██╗  ██╗███████╗ █████╗ ███╗   ██╗ ██████╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗████╗  ██║██╔════╝
██║  ██║██║     ███████║██║     █████╔╝ ███████╗███████║██╔██╗ ██║██║  ███╗
██║  ██║██║     ██╔══██║██║     ██╔═██╗ ╚════██║██╔══██║██║╚██╗██║██║   ██║
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗███████║██║  ██║██║ ╚████║╚██████╔╝
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝
${NC}"
}

log() { echo -e "[$(date +%F\ %T)] $1" | tee -a "$LOG"; }
error_exit() { echo -e "${RED}[✘] $1${NC}" | tee -a "$LOG"; exit 1; }
ok() { echo -e "${GREEN}[✔] $1${NC}" | tee -a "$LOG"; }

require_root() {
  [[ $EUID -ne 0 ]] && error_exit "You must run as root!"
}

########################################
# 🧠 SAFE STARTUP CHECKS
########################################
require_root
banner
log "Welcome to BLACKFANG - System Hardening Begins"

########################################
# 🔧 SYSTEM UPDATE & TOOLING
########################################
log "Updating system and installing tools..."
apt update -y && apt upgrade -y && apt install -y curl wget ufw fail2ban chkrootkit rkhunter auditd net-tools unzip sudo || error_exit "System update/tools failed"
ok "System updated and tools installed"

########################################
# 🔐 SSH HARDENING
########################################
log "Hardening SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i 's/^#Port.*/Port 2200/' /etc/ssh/sshd_config
sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh && ok "SSH hardened (Port 2200, no root login, no password login)"

########################################
# 🔥 FIREWALL SETUP
########################################
log "Setting up UFW..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 2200/tcp && ufw allow 80,443/tcp && ufw --force enable
ok "UFW firewall enabled with safe rules"

########################################
# 🧬 ROOTKIT + BACKDOOR CHECK
########################################
log "Checking for rootkits and malware..."
chkrootkit | tee -a "$LOG"
rkhunter --update
rkhunter --propupd
rkhunter --check --sk | tee -a "$LOG"
ok "Rootkit scans complete (review log if suspicious)"

########################################
# 🔍 SUID / SGID / NETSTAT / HIDDEN PIDS
########################################
log "Scanning for dangerous binaries..."
find / -type f -perm /6000 -exec ls -lh {} \; 2>/dev/null | tee -a "$LOG"
log "Checking hidden processes..."
for pid in $(ps -e -o pid=); do
  [[ ! -f /proc/$pid/exe ]] && echo "[!] PID $pid has no exe!" | tee -a "$LOG"
done

########################################
# 🛡️ FAIL2BAN + AUDITD
########################################
log "Configuring Fail2Ban..."
systemctl enable fail2ban && systemctl start fail2ban
log "Enabling audit logging..."
systemctl enable auditd && systemctl start auditd
ok "Fail2Ban and Auditd enabled"

########################################
# 💣 DISABLE WEAK STUFF
########################################
log "Disabling unneeded protocols..."
echo -e "install cramfs /bin/true\ninstall squashfs /bin/true\ninstall udf /bin/true\ninstall hfsplus /bin/true" > /etc/modprobe.d/blackfang_nofs.conf
echo "install usb-storage /bin/true" > /etc/modprobe.d/blackfang_usbblock.conf
ok "Weak filesystems and USB disabled"

########################################
# 🧬 IMMUTABLE FILE PROTECTION
########################################
log "Locking important config files..."
chattr +i /etc/resolv.conf /etc/passwd /etc/shadow /etc/group 2>/dev/null
ok "/etc files locked with chattr +i"

########################################
# 🧠 PASSWORD POLICY ENFORCED
########################################
log "Setting password policy..."
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
ok "Password aging policy applied"

########################################
# ☣️ REMOVE JUNK
########################################
log "Removing legacy trash (telnet, talk, etc.)..."
apt purge -y telnet xinetd rsh-client talk talkd || true
ok "Legacy network services removed"

########################################
# 🧼 CLEANUP
########################################
apt autoremove -y && apt clean -y
ok "System cleaned and hardened"

########################################
# 🧾 COMPLETION
########################################
echo -e "${GREEN}\n[✓] BLACKFANG hardening complete! Full log at $LOG${NC}"
