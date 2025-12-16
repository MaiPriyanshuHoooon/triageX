"""
Commands Configuration
======================
All forensic commands organized by category
"""

# Simple command list - no need to specify type!
COMMANDS = {
    "users": [
        "net user",
        "wmic useraccount list",
        "Get-LocalUser|Format-List"
    ],
    "network": [
        "ipconfig /all",
        "netstat -nao",
        "netstat -e",
        "netstat -s",
        "arp -a",
        "route print",
        "Get-NetAdapter|Format-List",
        "Get-NetIPAddress|Format-Table -AutoSize",
        "Get-NetRoute|Format-Table -AutoSize"
    ],
    "network_admin": [
        "netstat -naob",
    ],
    "usb_forensics": [
        "$usb=Get-ChildItem HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR -Recurse -ErrorAction SilentlyContinue|Get-ItemProperty -ErrorAction SilentlyContinue|Select-Object FriendlyName,PSChildName,DeviceDesc,Mfg,Service;$events=Get-WinEvent -LogName System|Where-Object {$_.Id -eq 2100 -or $_.Id -eq 2101 -or $_.Message -like '*USB*'}|Select-Object TimeCreated,Id,Message;Write-Output '=== USB DEVICE INFO ===';$usb;Write-Output '=== USB INSERT / REMOVE EVENTS ===';$events"
    ],
    "recent_files": [
        "Get-ChildItem \"$env:APPDATA\\Microsoft\\Windows\\Recent\" -Filter *.lnk|ForEach-Object {$s=(New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName);$t=$s.TargetPath;if([string]::IsNullOrWhiteSpace($t)){$status='No Target / Invalid Link'}elseif(Test-Path $t){$status='Exists'}else{$status='Deleted/Moved'};Write-Output ('LinkFile='+$_.Name+' | LastAccess='+$_.LastAccessTime+' | Target='+$t+' | Status='+$status)}"
    ],
    "prefetch": [
        "Get-ChildItem C:\\Windows\\Prefetch\\ -Filter *.pf|ForEach-Object {$name=$_.Name;$time=$_.LastWriteTime;$source=$name -replace '_.*','';Write-Output (\"PrefetchFile=$name | LastModified=$time | SourceEXE=$source.exe\")}",
        "Get-ChildItem C:\\Windows\\Prefetch\\|Select-Object Name,LastWriteTime,Length|Format-Table -AutoSize"
    ],
    "wifi_passwords": [
        # Get all WiFi profiles and their passwords
        "$profiles = (netsh wlan show profiles) | Select-String '\\:(.+)$' | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }; foreach ($profile in $profiles) { Write-Host \"Profile: $profile\" -ForegroundColor Cyan; netsh wlan show profile name=$profile key=clear | Select-String 'Key Content' }"
    ],
    "event_logs": [
        "wevtutil qe system /q:\"*[System[(EventID=6005)]]\" /f:text /c:20",
        "wevtutil qe system /q:\"*[System[(EventID=1074)]]\" /f:text /c:20"
    ],
    "processes": [
        "tasklist",
        "tasklist /svc",
        "Get-Process|Select-Object Name,Id,CPU,WorkingSet|Sort-Object CPU -Descending|Select-Object -First 20|Format-Table -AutoSize"
    ],
    "services": [
        "sc query",
        "Get-Service|Format-Table -AutoSize",
        "Get-Service|Where-Object {$_.Status -eq 'Running'}|Format-Table Name,DisplayName,Status -AutoSize",
        "Get-Service|Where-Object {$_.Status -eq 'Running'}|Select-Object Name,DisplayName,Status|Format-Table -AutoSize"
    ],
    "system": [
        "systeminfo",
        "Get-ComputerInfo|Select-Object CsName,OsName,OsVersion,OsArchitecture,BiosSeralNumber|Format-List",
        "Get-HotFix|Select-Object -First 20|Format-Table -AutoSize"
    ],
    "regex_analysis": [
        "ANALYZE_ALL_OUTPUTS_FOR_IOCS"
    ],
    "hash_analysis": [
        "HASH_SYSTEM_FILES",
        "HASH_TEMP_EXECUTABLES",
        "HASH_STARTUP_PROGRAMS"
    ]
}

# Command descriptions - What each command does (user-friendly)
COMMAND_DESCRIPTIONS = {
    # Users
    "net user": "Display all user accounts on the system",
    "wmic useraccount list": "List detailed user account information",
    "Get-LocalUser|Format-List": "Show local user accounts with full details",

    # Network
    "ipconfig /all": "Display complete network configuration (IP addresses, DNS, MAC addresses)",
    "netstat -nao": "Show all active network connections with process IDs",
    "netstat -e": "Display network interface statistics (packets sent/received, errors)",
    "netstat -s": "Show detailed protocol statistics (TCP, UDP, ICMP)",
    "arp -a": "Display ARP cache (IP to MAC address mappings)",
    "route print": "Show network routing table",
    "Get-NetAdapter|Format-List": "List all network adapters with detailed properties",
    "Get-NetIPAddress|Format-Table -AutoSize": "Display IP address configuration for all interfaces",
    "Get-NetRoute|Format-Table -AutoSize": "Show routing table entries",

    # Network Admin
    "netstat -naob": "Show active connections with process names (requires admin)",

    # USB Forensics
    "$usb=Get-ChildItem HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR -Recurse -ErrorAction SilentlyContinue|Get-ItemProperty -ErrorAction SilentlyContinue|Select-Object FriendlyName,PSChildName,DeviceDesc,Mfg,Service;$events=Get-WinEvent -LogName System|Where-Object {$_.Id -eq 2100 -or $_.Id -eq 2101 -or $_.Message -like '*USB*'}|Select-Object TimeCreated,Id,Message;Write-Output '=== USB DEVICE INFO ===';$usb;Write-Output '=== USB INSERT / REMOVE EVENTS ===';$events": "Retrieve USB device history and connection events",

    # Recent Files
    "Get-ChildItem \"$env:APPDATA\\Microsoft\\Windows\\Recent\" -Filter *.lnk|ForEach-Object {$s=(New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName);$t=$s.TargetPath;if([string]::IsNullOrWhiteSpace($t)){$status='No Target / Invalid Link'}elseif(Test-Path $t){$status='Exists'}else{$status='Deleted/Moved'};Write-Output ('LinkFile='+$_.Name+' | LastAccess='+$_.LastAccessTime+' | Target='+$t+' | Status='+$status)}": "Show recently opened files with access time and target status",

    # Prefetch Files
    "Get-ChildItem C:\\Windows\\Prefetch\\ -Filter *.pf|ForEach-Object {$name=$_.Name;$time=$_.LastWriteTime;$source=$name -replace '_.*','';Write-Output (\"PrefetchFile=$name | LastModified=$time | SourceEXE=$source.exe\")}": "Analyze prefetch files to show executed programs with timestamps",
    "Get-ChildItem C:\\Windows\\Prefetch\\|Select-Object Name,LastWriteTime,Length|Format-Table -AutoSize": "List prefetch files with last modified time and size",

    # WiFi Passwords
    "$profiles = (netsh wlan show profiles) | Select-String '\\:(.+)$' | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }; foreach ($profile in $profiles) { Write-Host \"Profile: $profile\" -ForegroundColor Cyan; netsh wlan show profile name=$profile key=clear | Select-String 'Key Content' }": "Extract saved WiFi network names and passwords from WLAN profiles",

    # Event Logs
    "wevtutil qe system /q:\"*[System[(EventID=6005)]]\" /f:text /c:20": "Display system boot/startup events (Event ID 6005)",
    "wevtutil qe system /q:\"*[System[(EventID=1074)]]\" /f:text /c:20": "Show logon/logoff and shutdown events (Event ID 1074)",

    # Processes
    "tasklist": "List all running processes",
    "tasklist /svc": "Show processes with associated services",
    "Get-Process|Select-Object Name,Id,CPU,WorkingSet|Sort-Object CPU -Descending|Select-Object -First 20|Format-Table -AutoSize": "Display top 20 processes by CPU usage",

    # Services
    "sc query": "List all Windows services and their status",
    "Get-Service|Format-Table -AutoSize": "Display all services with status",
    "Get-Service|Where-Object {$_.Status -eq 'Running'}|Format-Table Name,DisplayName,Status -AutoSize": "Show only running services",
    "Get-Service|Where-Object {$_.Status -eq 'Running'}|Select-Object Name,DisplayName,Status|Format-Table -AutoSize": "List running services with details",

    # System
    "systeminfo": "Display comprehensive system information (OS, hardware, updates)",
    "Get-ComputerInfo|Select-Object CsName,OsName,OsVersion,OsArchitecture,BiosSeralNumber|Format-List": "Show computer and OS details",
    "Get-HotFix|Select-Object -First 20|Format-Table -AutoSize": "List recently installed Windows updates",

    # Analysis placeholders
    "ANALYZE_ALL_OUTPUTS_FOR_IOCS": "Scan all collected data for Indicators of Compromise (suspicious patterns)",
    "HASH_SYSTEM_FILES": "Calculate cryptographic hashes of system files",
    "HASH_TEMP_EXECUTABLES": "Hash files in temporary directories",
    "HASH_STARTUP_PROGRAMS": "Hash programs in startup folders"
}

# PowerShell cmdlets and keywords
POWERSHELL_INDICATORS = [
    'Get-', 'Set-', 'New-', 'Remove-', 'Add-', 'Clear-', 'Export-', 'Import-',
    'Select-Object', 'Where-Object', 'ForEach-Object', 'Sort-Object',
    'Write-Output', 'Write-Host', 'Out-File',
    '$_', '|', '-eq', '-ne', '-like', '-match',
    'Format-List', 'Format-Table',
    'Get-WinEvent', 'Get-EventLog', 'Get-Process', 'Get-Service',
    'Get-ChildItem', 'Get-ItemProperty', 'Get-Content',
    '-ErrorAction', '-Recurse', '-Filter'
]
