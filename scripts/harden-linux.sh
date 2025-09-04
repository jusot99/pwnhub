#!/bin/bash

# Universal Linux Hardening Script
# Supports: Debian, Ubuntu, Kali, ParrotOS
# Author: jusot99
# Use: sudo ./harden-linux.sh

# COLORS
GREEN='\033[0;32m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
success_msg () { echo -e "${GREEN}[✔] $1${NC}"; }
fail_msg () { echo -e "${RED}[✘] $1${NC}"; exit 1; }
info_msg () { echo -e "${BLUE}[i] $1${NC}"; }

# Ensure root
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[-] Run this script as root.${NC}"; exit 1
fi

echo -e "${GREEN}[*] Starting Universal Linux Hardening Script...${NC}"

#######################
# 1. SYSTEM UPDATE
#######################
info_msg "Updating and upgrading system..."
apt update -y && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y && apt autoclean -y || fail_msg "System update failed"
success_msg "System updated"

#######################
# 2. BASIC TOOLING
#######################
info_msg "Installing essential tools..."
apt install -y curl wget git build-essential apt-transport-https ca-certificates gnupg2 software-properties-common jq zsh glances fail2ban ufw auditd audispd-plugins chkrootkit rkhunter || fail_msg "Tool install failed"
success_msg "Tools installed"

#######################
# 3. SSH HARDENING
#######################
info_msg "Hardening SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i 's/#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#\?Port .*/Port 2200/' /etc/ssh/sshd_config
systemctl restart ssh || fail_msg "SSH service failed to restart"
success_msg "SSH hardened (Port 2200, no root login)"

#######################
# 4. UFW FIREWALL
#######################
info_msg "Configuring UFW..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 2200/tcp
ufw allow 80,443/tcp
ufw --force enable
success_msg "UFW firewall configured"

#######################
# 5. FAIL2BAN
#######################
info_msg "Configuring Fail2Ban..."
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
cat <<EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = 2200
logpath = /var/log/auth.log
maxretry = 5
EOF
systemctl restart fail2ban
success_msg "Fail2Ban configured"

#######################
# 6. FILESYSTEM & USB HARDENING
#######################
info_msg "Disabling unused filesystems and USB..."
cat <<EOF > /etc/modprobe.d/harden_unused_fs.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true
install usb-storage /bin/true
EOF
success_msg "Unused filesystems and USB disabled"

#######################
# 7. AUTOMATIC UPDATES
#######################
info_msg "Enabling automatic security updates..."
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
success_msg "Unattended upgrades enabled"

#######################
# 8. AUDIT LOGGING
#######################
info_msg "Enabling audit logging..."
systemctl enable auditd && systemctl start auditd
success_msg "Auditd enabled"

#######################
# 9. DNS HARDENING
#######################
info_msg "Securing DNS settings..."
cp /etc/resolv.conf /etc/resolv.conf.bak
cat <<EOF > /etc/resolv.conf
nameserver 1.1.1.1
nameserver 9.9.9.9
options edns0
EOF
chattr +i /etc/resolv.conf
success_msg "/etc/resolv.conf locked"

#######################
# 10. SECURE SHM
#######################
info_msg "Securing shared memory..."
echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab

#######################
# 11. PASSWORD POLICY
#######################
info_msg "Enforcing password policy..."
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
success_msg "Password policies set"

#######################
# 12. PROXYCHAINS & TOR
#######################
info_msg "Installing Tor and ProxyChains..."
apt install -y tor proxychains4
systemctl enable tor && systemctl start tor
sed -i 's/#dynamic_chain/dynamic_chain/' /etc/proxychains4.conf
sed -i 's/strict_chain/#strict_chain/' /etc/proxychains4.conf
echo "socks5 127.0.0.1 9050" >> /etc/proxychains4.conf
success_msg "Tor and ProxyChains configured"

#######################
# 13. VPN (ProtonVPN CLI)
#######################
info_msg "Installing ProtonVPN CLI..."
wget https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.4_all.deb
dpkg -i ./protonvpn-stable-release_1.0.4_all.deb && apt update
apt install -y protonvpn-cli
rm -f protonvpn-stable-release_1.0.4_all.deb
success_msg "ProtonVPN CLI installed"

#######################
# 14. ROOTKIT SCANS
#######################
info_msg "Running rootkit scans..."
chkrootkit
rkhunter --update && rkhunter --propupd && rkhunter --checkall
success_msg "Rootkit scan complete"

#######################
# 15. PERMISSIONS HARDENING
#######################
info_msg "Hardening sensitive file permissions..."
chmod 600 /etc/shadow
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/ssh/sshd_config
success_msg "Permissions hardened"

#######################
# 16. REMOVE UNUSED SERVICES
#######################
info_msg "Removing unnecessary services..."
apt purge -y telnet xinetd rsh-server rsh-client talk talkd
success_msg "Unused services removed"

#######################
# 17. CLEANUP
#######################
info_msg "Cleaning up..."
apt autoremove -y && apt clean -y
success_msg "System cleaned"

#######################
# DONE
#######################
echo -e "${GREEN}[✓] System hardening complete. Review settings and reboot.${NC}"
