#!/bin/bash

# Universal Linux Hardening Script
# Author: jusot99
# Usage: sudo ./harden-linux.sh

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'
log() { echo -e "${GREEN}[✔] $1${NC}"; }
warn() { echo -e "${YELLOW}[!] $1${NC}"; }
error() { echo -e "${RED}[✘] $1${NC}"; }
info() { echo -e "${BLUE}[i] $1${NC}"; }

# Root check
[[ $EUID -ne 0 ]] && error "Run as root: sudo $0" && exit 1

# Banner
echo -e "${GREEN}
╔══════════════════════════════════════╗
║        LOCKDOWN - Linux Hardener     ║
║              by jusot99              ║
╚══════════════════════════════════════╝${NC}"

# Detect OS
source /etc/os-release
info "Detected: $PRETTY_NAME"

# Backup function
backup_file() {
    cp "$1" "$1.bak.$(date +%s)" 2>/dev/null && log "Backed up: $1"
}

# 1. SYSTEM UPDATE
info "Updating system..."
apt update && apt upgrade -y && apt autoremove -y || warn "Some updates failed"

# 2. ESSENTIAL SECURITY TOOLS
info "Installing security tools..."
apt install -y fail2ban ufw auditd chkrootkit rkhunter lynis unattended-upgrades \
               apt-listbugs debsums needrestart || warn "Some packages failed"

# 3. SSH HARDENING
info "Hardening SSH..."
backup_file "/etc/ssh/sshd_config"
sed -i 's/#\?PermitRootLogin.*/PermitRootLogin no/g;
        s/#\?PasswordAuthentication.*/PasswordAuthentication no/g;
        s/#\?Port.*/Port 2200/g;
        s/#\?X11Forwarding.*/X11Forwarding no/g;
        s/#\?ClientAliveInterval.*/ClientAliveInterval 300/g' /etc/ssh/sshd_config
systemctl restart sshd && log "SSH secured (Port 2200, no root)"

# 4. FIREWALL CONFIG
info "Configuring UFW..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 2200/tcp comment 'SSH'
ufw allow 80,443/tcp comment 'HTTP/HTTPS'
ufw --force enable && log "Firewall active"

# 5. FAIL2BAN SETUP
info "Configuring Fail2Ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = 2200
logpath = /var/log/auth.log
EOF
systemctl restart fail2ban && log "Fail2Ban running"

# 6. KERNEL HARDENING
info "Hardening kernel parameters..."
cat >> /etc/sysctl.conf << 'EOF'
# Security hardening
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_redirects=0
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
EOF
sysctl -p && log "Kernel hardened"

# 7. FILESYSTEM PROTECTION
info "Securing filesystems..."
cat > /etc/modprobe.d/hardening.conf << 'EOF'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install usb-storage /bin/true
EOF

# 8. SECURE DNS
info "Configuring secure DNS..."
cat > /etc/resolv.conf << 'EOF'
nameserver 1.1.1.1
nameserver 1.0.0.1
nameserver 2606:4700:4700::1111
options edns0
EOF
chattr +i /etc/resolv.conf 2>/dev/null && log "DNS locked"

# 9. PASSWORD POLICY
info "Setting password policies..."
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/;
        s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/;
        s/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
apt install -y libpam-pwquality
echo "password requisite pam_pwquality.so retry=3 minlen=12" >> /etc/pam.d/common-password

# 10. AUDIT & MONITORING
info "Enabling audit system..."
systemctl enable auditd && systemctl start auditd
cat > /etc/audit/rules.d/hardening.rules << 'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd
-a always,exit -F arch=b64 -S execve
EOF
auditctl -R /etc/audit/rules.d/hardening.rules

# 11. ANONYMIZATION TOOLS
info "Installing privacy tools..."
apt install -y tor proxychains4
systemctl enable tor --now
sed -i 's/#dynamic_chain/dynamic_chain/; s/strict_chain/#strict_chain/' /etc/proxychains4.conf
echo "socks5 127.0.0.1 9050" >> /etc/proxychains4.conf

# 12. SECURE PERMISSIONS
info "Fixing permissions..."
chmod 600 /etc/shadow
chmod 644 /etc/passwd /etc/group
chmod 600 /etc/ssh/sshd_config
find /var/log -type f -exec chmod 600 {} \;

# 13. MALWARE SCAN
info "Running security scans..."
chkrootkit 2>/dev/null | grep -E "INFECTED|VULNERABLE" || true
rkhunter --update && rkhunter --propupd && rkhunter --check --sk 2>/dev/null | tail -20

# 14. CLEANUP
info "Cleaning up..."
apt autoremove -y && apt clean
journalctl --vacuum-time=7d

# FINAL REPORT
echo -e "${GREEN}
╔══════════════════════════════════════╗
║           HARDENING COMPLETE         ║
╠══════════════════════════════════════╣
║ ✅ System Updated                    ║
║ ✅ SSH Secured (Port 2200)           ║
║ ✅ Firewall Enabled                  ║
║ ✅ Fail2Ban Active                   ║
║ ✅ Kernel Hardened                   ║
║ ✅ DNS Secured                       ║
║ ✅ Audit Logging Enabled             ║
║ ✅ Privacy Tools Installed           ║
╚══════════════════════════════════════╝${NC}"

warn "Important: Test SSH on port 2200 before disconnecting!"
warn "Recommended: Reboot system to apply all changes"
log "Hardening complete by jusot99 - Stay secure! 🔒"
