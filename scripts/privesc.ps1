# red-privesc-tools.ps1 - Download RedOps privesc tools for Windows targets

$dest = "$env:USERPROFILE\Downloads\RedOpsTools"
mkdir $dest -Force

Write-Host "[*] Downloading winPEAS..."
Invoke-WebRequest -Uri "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe" -OutFile "$dest\winPEAS.exe"

Write-Host "[*] Downloading Seatbelt..."
Invoke-WebRequest -Uri "https://github.com/GhostPack/Seatbelt/releases/latest/download/Seatbelt.exe" -OutFile "$dest\Seatbelt.exe"

Write-Host "[*] Downloading SharpUp..."
Invoke-WebRequest -Uri "https://github.com/GhostPack/SharpUp/releases/latest/download/SharpUp.exe" -OutFile "$dest\SharpUp.exe"

Write-Host "[*] Downloading PowerUp..."
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" -OutFile "$dest\PowerUp.ps1"

Write-Host "`n[+] Tools saved to $dest"
