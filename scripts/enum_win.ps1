# Elimane's PowerShell Post-Exploitation Recon Script
# Ghost Hacker Edition 🧠👻

function Section($title) {
    Write-Host "`n===== [ $title ] =====" -ForegroundColor Cyan
}

function Sub($label) {
    Write-Host "[*] $label" -ForegroundColor Green
}

function Highlight($text) {
    Write-Host "$text" -ForegroundColor Yellow
}

Section "User & Privilege Info"
Sub "Current User"; Highlight (whoami)
Sub "Domain/User"; Highlight "$env:USERDOMAIN\$env:USERNAME"
Sub "Groups"; whoami /groups
Sub "Privileges"; whoami /priv

Section "System Info"
Sub "Hostname"; hostname
Sub "OS Version"; Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
Sub "System Manufacturer & Model"; Get-CimInstance Win32_ComputerSystem | Select Manufacturer, Model
Sub "System Info Dump"; systeminfo | findstr /B /C:"OS" /C:"System" /C:"Domain"

Section "Users"
Sub "All Users"; net users
Sub "Admins"; net localgroup administrators
Sub "Logged On Users"; query user

Section "Network"
Sub "IP Config"; ipconfig /all
Sub "Routing Table"; route print
Sub "Netstat"; netstat -ano
Sub "ARP Table"; arp -a
Sub "Shares"; net share
Sub "SMB Hosts on Net"; net view

Section "Running Tasks & Processes"
Sub "Tasklist"; tasklist /v
Sub "Services"; Get-Service | Where-Object {$_.Status -eq "Running"} | Select Name, DisplayName
Sub "Startup Commands"; Get-CimInstance Win32_StartupCommand | Select Name, Command, Location

Section "Scheduled Tasks"
schtasks /query /fo LIST /v | Out-String | more

Section "Installed Programs"
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select DisplayName, DisplayVersion | Sort DisplayName | Format-Table -AutoSize

Section "Antivirus & Defender Status"
Sub "Defender Status"; Get-MpComputerStatus | Select RealTimeProtectionEnabled, AntivirusEnabled
Sub "AV Preferences"; Get-MpPreference | Select DisableRealtimeMonitoring, ExclusionPath

Section "Interesting Files to Loot"
Sub "Desktop Files"; Get-ChildItem "C:\Users\*\Desktop\*" -Include *.txt,*.doc*,*.pdf -Recurse -ErrorAction SilentlyContinue | Select FullName
Sub "SSH/Config/Key Files"; Get-ChildItem -Recurse -Include *id_rsa*,*.kdbx,*.ovpn,*config* -ErrorAction SilentlyContinue C:\ 2>$null | Select FullName

Write-Host "`n[+] Recon Complete. Ghost out, bro." -ForegroundColor Magenta
