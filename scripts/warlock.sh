# ⚠️ WARNING: THIS SCRIPT IS STILL IN DEVELOPMENT - NOT READY FOR PRODUCTION USE. USE WITH CAUTION! - By EJusot99
#!/bin/bash


# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

success_msg () {
  echo -e "${GREEN}[✔] Success: $1${NC}"
}

fail_msg () {
  echo -e "${RED}[✘] Fail: $1${NC}"
  exit 1
}

show_progress () {
  echo -n "Progressing"
  for i in {1..3}; do
    echo -n "."
    sleep 1
  done
  echo ""
}

# Header
echo -e "${GREEN}============================"
echo -e " Hardened Linux Setup "
echo -e "============================${NC}\n"

# Backup and edit sources.list
echo -e "[+] ${BLUE}Backing up /etc/apt/sources.list...${NC}"
show_progress
sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
if [ $? -eq 0 ]; then
    success_msg "/etc/apt/sources.list backed up"
else
    fail_msg "Failed to back up /etc/apt/sources.list"
fi

echo -e "[+] ${BLUE}Editing /etc/apt/sources.list...${NC}"
show_progress
sudo bash -c 'cat > /etc/apt/sources.list' << EOL
deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware
deb-src http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware
EOL
if [ $? -eq 0 ]; then
    success_msg "/etc/apt/sources.list updated"
else
    fail_msg "Failed to update /etc/apt/sources.list"
fi

# Backup and edit .zshrc
echo -e "[+] ${BLUE}Backing up ~/.zshrc...${NC}"
show_progress
cp ~/.zshrc ~/.zshrc.bak
if [ $? -eq 0 ]; then
    success_msg "~/.zshrc backed up"
else
    fail_msg "Failed to back up ~/.zshrc"
fi

echo -e "[+] ${BLUE}Editing ~/.zshrc...${NC}"
show_progress
sed -i 's/PROMPT_ALTERNATIVE=twoline/PROMPT_ALTERNATIVE=oneline/' ~/.zshrc
sed -i 's/NEWLINE_BEFORE_PROMPT=yes/NEWLINE_BEFORE_PROMPT=no/' ~/.zshrc
if [ $? -eq 0 ]; then
    success_msg "~/.zshrc updated"
else
    fail_msg "Failed to update ~/.zshrc"
fi

# Source the updated .zshrc
echo -e "[+] ${BLUE}Sourcing ~/.zshrc...${NC}"
show_progress
zsh -c "source ~/.zshrc"
if [ $? -eq 0 ]; then
    success_msg "~/.zshrc sourced"
else
    fail_msg "Failed to source ~/.zshrc"
fi

# Connect to WiFi
echo -e "[+] ${BLUE}Connecting to WiFi...${NC}"
show_progress
nmcli device wifi connect 'Link Lagoon' password 'GapFL2ib$'
if [ $? -eq 0 ]; then
    success_msg "Connected to WiFi"
else
    fail_msg "Failed to connect to WiFi"
fi

# Update system and install basic tools
echo -e "[+] ${BLUE}Updating system and installing basic tools...${NC}"
show_progress
sudo apt update -y && sudo apt install -y apt-transport-https curl wget git zsh build-essential jq ca-certificates proxychains4 bettercap cht.sh glances
if [ $? -eq 0 ]; then
    success_msg "System updated and basic tools installed"
else
    fail_msg "Failed to update system or install basic tools"
fi

# Install additional utilities
# echo -e "[+] ${BLUE}Installing additional utilities...${NC}"
# show_progress
# sudo apt install -y ddgr googler w3m lynx tmux fzf sherlock ripgrep neofetch exiftool tcpdump masscan wireguard-tools iperf3 net-tools speedtest-cli bettercap links software-properties-common gnupg2 lsb-release tldr terminator dirsearch dstat chkrootkit iftop golang-go gobuster httpie bluez bluez-tools bluetooth btscanner glances htop subfinder assetfinder sublist3r nmap rkhunter
# if [ $? -eq 0 ]; then
#     success_msg "Additional utilities installed"
# else
#     fail_msg "Failed to install additional utilities"
# fi

# Install Sublime Text
echo -e "[+] ${BLUE}Installing Sublime Text...${NC}"
show_progress
curl -fsSL https://download.sublimetext.com/sublimehq-pub.gpg | sudo tee /etc/apt/trusted.gpg.d/sublimehq-archive.asc
echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
sudo apt update
sudo apt install sublime-text
if [ $? -eq 0 ]; then
    success_msg "Sublime Text installed"
else
    fail_msg "Failed to install Sublime Text"
fi

# Install tgpt
echo -e "[+] ${BLUE}Installing tgpt...${NC}"
show_progress
curl -sSL https://raw.githubusercontent.com/aandrew-me/tgpt/main/install | bash -s /usr/local/bin
if [ $? -eq 0 ]; then
    success_msg "tgpt installed"
else
    fail_msg "Failed to install tgpt"
fi

# Download and install ProtonVPN
echo -e "[+] ${BLUE}Installing ProtonVPN...${NC}"
show_progress
wget https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.4_all.deb
sudo dpkg -i ./protonvpn-stable-release_1.0.4_all.deb && sudo apt update
sudo apt install protonvpn-cli -y
rm -rf protonvpn-stable-release_1.0.4_all.deb
if [ $? -eq 0 ]; then
    success_msg "ProtonVPN installed"
else
    fail_msg "Failed to install ProtonVPN"
fi

# Install and configure Tor
echo -e "[+] ${BLUE}Installing and configuring Tor...${NC}"
show_progress
sudo apt install -y tor && sudo systemctl start tor && sudo systemctl enable tor
if [ $? -eq 0 ]; then
    success_msg "Tor installed and configured"
else
    fail_msg "Failed to install or configure Tor"
fi

# Configure ProxyChains for Tor
echo -e "[+] ${BLUE}Configuring ProxyChains for Tor...${NC}"
show_progress
sudo cp /etc/proxychains4.conf /etc/proxychains4.conf.bak
sudo sed -i 's/^#dynamic_chain/dynamic_chain/' /etc/proxychains4.conf && sudo sed -i 's/^strict_chain/#strict_chain/' /etc/proxychains4.conf && echo "socks5  127.0.0.1 9050" | sudo tee -a /etc/proxychains4.conf
if [ $? -eq 0 ]; then
    success_msg "ProxyChains configured"
else
    fail_msg "Failed to configure ProxyChains"
fi

# Rsyslog Installation
echo -e "[+] ${BLUE}Installing and configuring rsyslog...${NC}"
show_progress
sudo apt install rsyslog -y
sudo systemctl enable rsyslog
sudo systemctl start rsyslog

# Configure rsyslog to allow remote logging
sudo cp /etc/rsyslog.conf /etc/rsyslog.conf.bak
sudo sed -i 's/#module(load="imtcp")/module(load="imtcp")/' /etc/rsyslog.conf
sudo sed -i 's/#input(type="imtcp" port="514")/input(type="imtcp" port="514")/' /etc/rsyslog.conf
sudo systemctl restart rsyslog
if [ $? -eq 0 ]; then
    success_msg "rsyslog installed and configured"
else
    fail_msg "Failed to configure rsyslog"
fi

# Disable root login over SSH
echo -e "[+] ${RED}Disabling root login over SSH for security...${NC}"
show_progress

# Backup existing sshd_config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#Port 22/Port 2200/' /etc/ssh/sshd_config
sudo systemctl restart ssh
if [ $? -eq 0 ]; then
    success_msg "Root login over SSH disabled"
else
    fail_msg "Failed to disable root login over SSH"
fi

# Install and configure Fail2Ban
echo -e "[+] ${BLUE}Installing and configuring Fail2Ban...${NC}"
show_progress
sudo apt install -y fail2ban
sudo systemctl start fail2ban
sudo systemctl enable fail2ban

# Backup and configure Fail2Ban for SSH
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

sudo bash -c 'cat > /etc/fail2ban/jail.local' << EOL
[sshd]
enabled = true
port = 2200
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
ignoreip = 127.0.0.1

[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache*/*error.log
maxretry = 6
EOL

sudo systemctl restart fail2ban
if [ $? -eq 0 ]; then
    success_msg "Fail2Ban installed and configured"
else
    fail_msg "Failed to install or configure Fail2Ban"
fi

# Configure /etc/resolv.conf for DNS settings
echo -e "[+] ${BLUE}Configuring /etc/resolv.conf for DNS settings...${NC}"
show_progress

# Backup resolv.conf
sudo cp /etc/resolv.conf /etc/resolv.conf.bak

# Harden DNS settings
sudo bash -c 'cat > /etc/resolv.conf' << EOL
# Use public DNS servers and disable domain name leakage
nameserver 1.1.1.1
nameserver 9.9.9.9
options edns0
EOL

# Prevent changes to resolv.conf
sudo chattr +i /etc/resolv.conf
if [ $? -eq 0 ]; then
    success_msg "resolv.conf configured and locked"
else
    fail_msg "Failed to configure resolv.conf"
fi

# Configure resolvectl for advanced DNS settings
# echo -e "[+] ${BLUE}Configuring resolvectl for advanced DNS management...${NC}"
# show_progress
# sudo apt install -y systemd-resolved
# Set resolvectl DNS servers
# sudo resolvectl dns eth0 1.1.1.1 9.9.9.9
# sudo resolvectl dnssec eth0 yes
# sudo resolvectl domain eth0 ~

# if [ $? -eq 0 ]; then
#     success_msg "resolvectl configured"
# else
#     fail_msg "Failed to configure resolvectl"
# fi

# Setup UFW (Uncomplicated Firewall) and enable strict rules
echo -e "[+] ${BLUE}Setting up UFW (firewall) with strict rules...${NC}"
show_progress
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2200/tcp
sudo ufw allow 514/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
if [ $? -eq 0 ]; then
    success_msg "UFW setup complete"
else
    fail_msg "Failed to set up UFW"
fi

# Set up Zsh as default shell and Oh-My-Zsh
# echo -e "[+] ${BLUE}Setting up Zsh and Oh-My-Zsh...${NC}"
# show_progress
# sudo chsh -s /bin/zsh $(whoami)
# sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
# git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/themes/powerlevel10k
# git clone https://github.com/MichaelAquilina/zsh-auto-notify.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/auto-notify
# git clone https://github.com/MichaelAquilina/zsh-you-should-use.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/you-should-use
# git clone https://github.com/jhwohlgemuth/zsh-pentest.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-pentest
# cp /media/kali/pentesters/secguide/system_config/zshrc.md ~/.zshrc
# source ~/.zshrc
# if [ $? -eq 0 ]; then
#     success_msg "Zsh and Oh-My-Zsh installed"
# else
#     fail_msg "Failed to set up Zsh and Oh-My-Zsh"
# fi

# Clean up system
echo -e "[+] ${BLUE}Cleaning up the system...${NC}"
show_progress
sudo apt-get clean -y && sudo apt-get autoclean -y && sudo apt-get autoremove -y
# sudo apt autoremove -y && sudo apt clean -y
if [ $? -eq 0 ]; then
    success_msg "System cleaned up"
else
    fail_msg "Failed to clean up the system"
fi

# Completion message
echo -e "${GREEN}[*] Setup completed successfully! Enjoy using Kali Linux . Happy Hacking!!${NC}"


######

#!/bin/bash

# Linux Hardening Script for Ubuntu and Kali Linux
# Must be run as root

if [[ $EUID -ne 0 ]]; then
    echo "[-] Please run this script as root."
    exit 1
fi

echo "[+] Starting Linux Hardening..."

# 1. System update
echo "[+] Updating system..."
apt update && apt upgrade -y

# 2. Configure UFW Firewall
echo "[+] Configuring UFW Firewall..."
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable

# 3. SSH Hardening
echo "[+] Hardening SSH..."
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
echo "AllowUsers youruser" >> /etc/ssh/sshd_config  # Replace 'youruser'
systemctl restart ssh

# 4. Disable unused filesystems
echo "[+] Disabling uncommon filesystems..."
echo -e "install cramfs /bin/true\ninstall freevxfs /bin/true\ninstall jffs2 /bin/true\ninstall hfs /bin/true\ninstall hfsplus /bin/true\ninstall squashfs /bin/true\ninstall udf /bin/true\ninstall vfat /bin/true" > /etc/modprobe.d/harden_unused_fs.conf

# 5. Enabling automatic security updates
echo "[+] Enabling unattended security upgrades..."
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# 6. Auditing and logging
echo "[+] Installing and enabling auditd..."
apt install -y auditd audispd-plugins
systemctl enable auditd
systemctl start auditd

# 7. Fail2ban for brute-force protection
echo "[+] Installing Fail2ban..."
apt install -y fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# 8. Rootkit & malware scanner
echo "[+] Installing chkrootkit and rkhunter..."
apt install -y chkrootkit rkhunter
chkrootkit
rkhunter --update
rkhunter --propupd
rkhunter --checkall

# 9. Secure shared memory
echo "[+] Securing shared memory..."
echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab

# 10. Set password aging policies
echo "[+] Enforcing password aging policies..."
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

# 11. Disable USB storage (optional)
echo "[+] Disabling USB storage (optional)..."
echo "install usb-storage /bin/true" > /etc/modprobe.d/usb-storage.conf

# 12. Remove unnecessary packages
echo "[+] Removing unnecessary packages..."
apt purge -y telnet xinetd rsh-server rsh-client talk talkd

# 13. Setting permissions for /etc
echo "[+] Setting strict permissions for sensitive files..."
chmod 700 /etc/ssh/sshd_config
chmod 600 /etc/passwd
chmod 600 /etc/shadow
chmod 600 /etc/group

# 14. Reboot notice
echo "[+] Hardening complete. Please review the SSH settings and reboot if needed."
