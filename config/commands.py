"""
Commands Configuration
======================
All forensic commands organized by category for Windows, Linux, and macOS
"""

import sys

# ========================================
# WINDOWS COMMANDS
# ========================================

WINDOWS_COMMANDS = {
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


# ========================================
# LINUX COMMANDS
# ========================================

LINUX_COMMANDS = {
    "system": [
        # Comprehensive system info
        'echo -e "User: $(whoami)\\nHostname: $(hostname)\\nOS: $(lsb_release -ds 2>/dev/null || cat /etc/*-release | head -n 1)\\nKernel: $(uname -r)\\nArchitecture: $(uname -m)\\nIP Address: $(ip route get 1 2>/dev/null | awk \'{print $7}\' || hostname -I | awk \'{print $1}\')"',
        "uname -a",
        "cat /etc/*-release",
        "lscpu",
        "free -h",
        "df -h",
        "uptime"
    ],
    "users": [
        # Comprehensive user enumeration and login tracking
        '''echo "===== LOGGED-IN USERS CHECK (TRIAGE) ====="
echo
echo "--- CURRENT LOGINS (who) ---"
who 2>/dev/null || echo "who not available"
echo
echo "--- ACTIVE SESSIONS (w) ---"
w 2>/dev/null || echo "w not available"
echo
echo "--- LOGIN HISTORY ---"
if command -v last >/dev/null; then
    last -n 10
elif command -v wtmpdb >/dev/null; then
    wtmpdb last -n 10
else
    echo "login history tool not installed"
fi
echo
echo "--- LAST LOGIN PER USER ---"
if command -v lastlog >/dev/null; then
    lastlog
elif command -v lastlog2 >/dev/null; then
    lastlog2
else
    echo "lastlog tool not installed"
fi
echo "========================================"''',
        "cat /etc/passwd",
        "cat /etc/shadow 2>/dev/null || echo 'Access denied (requires root)'",
        "cat /etc/group",
        "who",
        "w",
        "last -n 20",
        "lastlog"
    ],
    "processes": [
        # Process & malware triage
        '''echo "===== PROCESS & MALWARE TRIAGE ====="
echo
echo "--- ps aux (snapshot) ---"
ps aux 2>/dev/null | head -n 15
echo
echo "--- ps -ef (full format) ---"
ps -ef 2>/dev/null | head -n 15
echo
echo "--- top (batch mode) ---"
top -b -n 1 2>/dev/null | head -n 20
echo
echo "--- Executables from /tmp, /var/tmp, /dev (SUSPICIOUS) ---"
for p in /proc/[0-9]*/exe; do
    exe=$(readlink "$p" 2>/dev/null)
    pid=$(echo "$p" | cut -d/ -f3)
    case "$exe" in
        /tmp/*|/var/tmp/*|/dev/*)
            echo "PID: $pid  EXE: $exe"
            ;;
    esac
done
echo "====================================="''',
        "ps aux",
        "ps -ef",
        "top -b -n 1 | head -n 30",
        "pstree -p",
        "lsof | head -n 100"
    ],
    "network": [
        # Comprehensive network triage
        '''echo "===== NETWORK CONNECTIONS TRIAGE ====="
echo
echo "--- Active Network Connections (ss / netstat) ---"
if command -v ss >/dev/null 2>&1; then
    ss -antup 2>/dev/null
elif command -v netstat >/dev/null 2>&1; then
    netstat -plant 2>/dev/null
else
    echo "ss / netstat not available"
fi
echo
echo "--- Open Network Files (lsof) ---"
if command -v lsof >/dev/null 2>&1; then
    lsof -i -n -P 2>/dev/null
else
    echo "lsof not available"
fi
echo
echo "--- ARP Table (LAN Mapping) ---"
if command -v arp >/dev/null 2>&1; then
    arp -a 2>/dev/null
elif command -v ip >/dev/null 2>&1; then
    ip neigh 2>/dev/null
else
    echo "ARP information not available"
fi
echo
echo "--- Suspicious External Connections (Potential C2 / Reverse Shell) ---"
if command -v ss >/dev/null 2>&1; then
    ss -antup 2>/dev/null | awk '$5 !~ /127.0.0.1|::1/ && $1=="ESTAB"'
elif command -v netstat >/dev/null 2>&1; then
    netstat -antp 2>/dev/null | awk '$6=="ESTABLISHED" && $5 !~ /127.0.0.1/'
fi
echo "========================================"''',
        "ip addr show || ifconfig -a",
        "ss -tunapl || netstat -tunapl",
        "ss -antup || netstat -antup",
        "ip route || route -n",
        "arp -a || ip neigh",
        "lsof -i -n -P"
    ],
    "services": [
        "systemctl list-units --type=service || service --status-all",
        "systemctl list-unit-files --type=service",
        "chkconfig --list 2>/dev/null || echo 'chkconfig not available'",
        "ps aux | grep -E '(systemd|init)'"
    ],
    "usb_forensics": [
        "lsusb",
        "lsusb -v 2>/dev/null | head -n 100",
        "dmesg | grep -i usb | tail -n 50",
        "cat /var/log/messages 2>/dev/null | grep -i usb | tail -n 50 || echo '/var/log/messages not accessible'",
        "cat /var/log/syslog 2>/dev/null | grep -i usb | tail -n 50 || echo '/var/log/syslog not accessible'"
    ],
    "recent_files": [
        # Command history triage
        '''echo "===== USER COMMAND HISTORY TRIAGE ====="
echo
echo "--- Current User ---"
whoami
echo
echo "--- Bash History (~/.bash_history) ---"
if [ -f "$HOME/.bash_history" ]; then
    tail -n 50 "$HOME/.bash_history"
else
    echo "No bash history file found"
fi
echo
echo "--- Zsh History (~/.zsh_history) ---"
if [ -f "$HOME/.zsh_history" ]; then
    tail -n 50 "$HOME/.zsh_history"
else
    echo "No zsh history file found"
fi
echo
echo "--- Root Bash History (/root/.bash_history) ---"
if [ -f "/root/.bash_history" ]; then
    tail -n 50 "/root/.bash_history"
else
    echo "No root bash history found (check permissions)"
fi
echo
echo "--- Other Users History (Quick Check) ---"
for h in /home/*/.bash_history /home/*/.zsh_history; do
    if [ -f "$h" ]; then
        echo "### $h ###"
        tail -n 10 "$h"
    fi
done
echo "========================================"''',
        "ls -lah ~/.bash_history ~/.zsh_history 2>/dev/null",
        "find /home -name '.*_history' -type f 2>/dev/null",
        "find /tmp -type f -mtime -7 2>/dev/null | head -n 50",
        "find /var/tmp -type f -mtime -7 2>/dev/null | head -n 50"
    ],
    "event_logs": [
        "journalctl -n 100 || echo 'journalctl not available'",
        "journalctl --since '1 hour ago' || echo 'journalctl not available'",
        "tail -n 100 /var/log/syslog 2>/dev/null || echo '/var/log/syslog not accessible'",
        "tail -n 100 /var/log/messages 2>/dev/null || echo '/var/log/messages not accessible'",
        "tail -n 100 /var/log/auth.log 2>/dev/null || tail -n 100 /var/log/secure 2>/dev/null || echo 'auth logs not accessible'"
    ],
    "wifi_passwords": [
        "cat /etc/NetworkManager/system-connections/* 2>/dev/null | grep -E '^\\[|^ssid|^psk' || echo 'NetworkManager configs not accessible (requires root)'",
        "nmcli device wifi list 2>/dev/null || echo 'nmcli not available'"
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


# ========================================
# macOS COMMANDS
# ========================================

MACOS_COMMANDS = {
    "system": [
        "system_profiler SPSoftwareDataType",
        "system_profiler SPHardwareDataType",
        "sw_vers",
        "uname -a",
        "sysctl -a | head -n 50",
        "df -h",
        "vm_stat"
    ],
    "users": [
        "dscl . list /Users",
        "dscl . read /Users/$(whoami)",
        "who",
        "w",
        "last -n 20",
        "lastlog 2>/dev/null || echo 'lastlog not available on this macOS version'",
        "dscacheutil -q user"
    ],
    "processes": [
        "ps aux",
        "ps -ef",
        "top -l 1 | head -n 30",
        "lsof | head -n 100",
        "launchctl list"
    ],
    "network": [
        "ifconfig -a",
        "netstat -an",
        "netstat -rn",
        "arp -a",
        "lsof -i -n -P",
        "system_profiler SPNetworkDataType",
        "networksetup -listallhardwareports"
    ],
    "services": [
        "launchctl list",
        "sudo launchctl list 2>/dev/null || echo 'Run with sudo for system services'",
        "ls -la /Library/LaunchDaemons/",
        "ls -la /Library/LaunchAgents/",
        "ls -la ~/Library/LaunchAgents/"
    ],
    "usb_forensics": [
        "system_profiler SPUSBDataType",
        "log show --predicate 'eventMessage contains \"USB\"' --last 1h --style syslog 2>/dev/null || echo 'Requires admin access'",
        "ioreg -p IOUSB -w0 | head -n 100"
    ],
    "recent_files": [
        "ls -lah ~/.bash_history ~/.zsh_history 2>/dev/null",
        "mdfind 'kMDItemFSContentChangeDate >= $time.now(-86400)' 2>/dev/null | head -n 50 || echo 'Spotlight search unavailable'",
        "find ~ -type f -mtime -7 2>/dev/null | head -n 50"
    ],
    "event_logs": [
        "log show --last 1h --style syslog 2>/dev/null | head -n 100 || echo 'Requires admin access'",
        "log show --predicate 'eventType == logEvent' --last 1h 2>/dev/null | head -n 100",
        "tail -n 100 /var/log/system.log 2>/dev/null || echo '/var/log/system.log not accessible'"
    ],
    "wifi_passwords": [
        "networksetup -listallhardwareports",
        "security find-generic-password -ga 'WIFI_SSID' 2>&1 || echo 'Requires admin password for WiFi credential access'"
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


# Backward compatibility - defaults to Windows
COMMANDS = WINDOWS_COMMANDS


def get_commands_for_os(os_type=None):
    """
    Return the correct command set for the given (or detected) OS.

    Args:
        os_type: "Windows", "Linux", "macOS", or None (auto-detect)

    Returns:
        Tuple of (commands_dict, os_name_str)
    """
    if os_type is None:
        # Auto-detect
        if sys.platform == 'win32':
            os_type = "Windows"
        elif sys.platform == 'darwin':
            os_type = "macOS"
        elif sys.platform.startswith('linux'):
            os_type = "Linux"
        else:
            os_type = "Windows"  # fallback

    if os_type == "Linux":
        return LINUX_COMMANDS, "Linux"
    elif os_type == "macOS":
        return MACOS_COMMANDS, "macOS"
    else:
        return WINDOWS_COMMANDS, "Windows"


# ========================================
# COMMAND DESCRIPTIONS
# ========================================

COMMAND_DESCRIPTIONS = {
    # ===== WINDOWS =====
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
    "netstat -naob": "Show active connections with process names (requires admin)",

    # USB Forensics
    "$usb=Get-ChildItem HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR -Recurse -ErrorAction SilentlyContinue|Get-ItemProperty -ErrorAction SilentlyContinue|Select-Object FriendlyName,PSChildName,DeviceDesc,Mfg,Service;$events=Get-WinEvent -LogName System|Where-Object {$_.Id -eq 2100 -or $_.Id -eq 2101 -or $_.Message -like '*USB*'}|Select-Object TimeCreated,Id,Message;Write-Output '=== USB DEVICE INFO ===';$usb;Write-Output '=== USB INSERT / REMOVE EVENTS ===';$events": "Retrieve USB device history and connection events",

    # Recent Files
    "Get-ChildItem \"$env:APPDATA\\Microsoft\\Windows\\Recent\" -Filter *.lnk|ForEach-Object {$s=(New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName);$t=$s.TargetPath;if([string]::IsNullOrWhiteSpace($t)){$status='No Target / Invalid Link'}elseif(Test-Path $t){$status='Exists'}else{$status='Deleted/Moved'};Write-Output ('LinkFile='+$_.Name+' | LastAccess='+$_.LastAccessTime+' | Target='+$t+' | Status='+$status)}": "Show recently opened files with access time and target status",

    # Prefetch
    "Get-ChildItem C:\\Windows\\Prefetch\\ -Filter *.pf|ForEach-Object {$name=$_.Name;$time=$_.LastWriteTime;$source=$name -replace '_.*','';Write-Output (\"PrefetchFile=$name | LastModified=$time | SourceEXE=$source.exe\")}": "Analyze prefetch files to show executed programs with timestamps",
    "Get-ChildItem C:\\Windows\\Prefetch\\|Select-Object Name,LastWriteTime,Length|Format-Table -AutoSize": "List prefetch files with last modified time and size",

    # WiFi
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

    # ===== LINUX =====
    "uname -a": "Display kernel version, architecture, and hostname",
    "lscpu": "Show detailed CPU architecture information",
    "free -h": "Display memory usage in human-readable format",
    "df -h": "Show disk space usage",
    "uptime": "Display system uptime and load average",

    "cat /etc/passwd": "List all user accounts on the system",
    "cat /etc/shadow 2>/dev/null || echo 'Access denied (requires root)'": "View password hashes (requires root)",
    "cat /etc/group": "Display all groups",
    "who": "Show currently logged-in users",
    "w": "Display detailed user session information",
    "last -n 20": "Show last 20 login records",
    "lastlog": "Display last login time for all users",

    "ps aux": "List all running processes with CPU and memory usage",
    "ps -ef": "Display full process list with parent-child relationships",
    "top -b -n 1 | head -n 30": "Snapshot of top processes by resource usage",
    "pstree -p": "Show process tree with PIDs",
    "lsof | head -n 100": "List open files and network connections",

    "ip addr show || ifconfig -a": "Display network interface configuration",
    "ss -tunapl || netstat -tunapl": "Show all TCP/UDP connections with process info",
    "ss -antup || netstat -antup": "Display active network connections",
    "ip route || route -n": "Show routing table",
    "arp -a || ip neigh": "Display ARP cache",
    "lsof -i -n -P": "List network connections with processes",

    "systemctl list-units --type=service || service --status-all": "List all services (systemd or SysV)",
    "systemctl list-unit-files --type=service": "Show service unit files and their states",
    "chkconfig --list 2>/dev/null || echo 'chkconfig not available'": "List services (RHEL/CentOS legacy)",

    "lsusb": "List all USB devices",
    "lsusb -v 2>/dev/null | head -n 100": "Detailed USB device information",
    "dmesg | grep -i usb | tail -n 50": "Show USB-related kernel messages",

    "journalctl -n 100 || echo 'journalctl not available'": "Display last 100 system log entries",
    "journalctl --since '1 hour ago' || echo 'journalctl not available'": "Show logs from the last hour",
    "tail -n 100 /var/log/syslog 2>/dev/null || echo '/var/log/syslog not accessible'": "Recent system log entries",
    "tail -n 100 /var/log/auth.log 2>/dev/null || tail -n 100 /var/log/secure 2>/dev/null || echo 'auth logs not accessible'": "Authentication and authorization logs",

    "nmcli device wifi list 2>/dev/null || echo 'nmcli not available'": "List available WiFi networks",

    # ===== macOS =====
    "system_profiler SPSoftwareDataType": "Display macOS version and system software information",
    "system_profiler SPHardwareDataType": "Show hardware specifications",
    "sw_vers": "Display macOS version details",
    "sysctl -a | head -n 50": "Show system parameters and configuration",
    "vm_stat": "Display virtual memory statistics",

    "dscl . list /Users": "List all user accounts",
    "dscacheutil -q user": "Query user account information from directory services",

    "launchctl list": "List all running launch agents and daemons",
    "sudo launchctl list 2>/dev/null || echo 'Run with sudo for system services'": "List system-wide services",

    "system_profiler SPUSBDataType": "Display all USB devices and controllers",
    "ioreg -p IOUSB -w0 | head -n 100": "Show USB device registry information",

    "system_profiler SPNetworkDataType": "Display network hardware and configuration",
    "networksetup -listallhardwareports": "List all network hardware ports",

    "log show --last 1h --style syslog 2>/dev/null | head -n 100 || echo 'Requires admin access'": "Show system logs from the last hour",
    "mdfind 'kMDItemFSContentChangeDate >= $time.now(-86400)' 2>/dev/null | head -n 50 || echo 'Spotlight search unavailable'": "Find files modified in the last 24 hours using Spotlight",

    # Analysis placeholders (all OSes)
    "ANALYZE_ALL_OUTPUTS_FOR_IOCS": "Scan all collected data for Indicators of Compromise (suspicious patterns)",
    "HASH_SYSTEM_FILES": "Calculate cryptographic hashes of system files",
    "HASH_TEMP_EXECUTABLES": "Hash files in temporary directories",
    "HASH_STARTUP_PROGRAMS": "Hash programs in startup folders"
}


# ========================================
# SHELL INDICATORS
# ========================================

# PowerShell cmdlets and keywords (Windows)
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

# Bash/Linux shell indicators
BASH_INDICATORS = [
    'cat', 'grep', 'awk', 'sed', 'find', 'ls', 'ps', 'netstat', 'ss',
    'ip', 'ifconfig', 'route', 'arp', 'lsof', 'systemctl', 'journalctl',
    'uname', 'free', 'df', 'lscpu', 'dmesg', 'lsusb', 'who', 'last',
    'tail', 'head', 'echo', 'command -v', 'readlink', 'for', 'while',
    '|', '&&', '||', '>', '>>', '<', '$(', '2>/dev/null', '/dev/null'
]

# macOS-specific shell indicators
MACOS_INDICATORS = [
    'system_profiler', 'dscl', 'launchctl', 'sw_vers', 'sysctl',
    'networksetup', 'security', 'mdfind', 'log show', 'ioreg',
    'dscacheutil', 'vm_stat'
]
