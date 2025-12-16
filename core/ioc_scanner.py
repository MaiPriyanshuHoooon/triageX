"""
Comprehensive IOC Scanner Module
=================================
Advanced Indicator of Compromise (IOC) detection for forensic investigations
Includes network IOCs, file IOCs, malware signatures, C2 patterns, persistence mechanisms
"""

import re
from collections import defaultdict
from typing import Dict, List, Tuple


class IOCScanner:
    """
    Advanced IOC scanner for law enforcement investigations
    Detects malware, C2 communication, persistence mechanisms, and threat indicators
    """

    # ========== NETWORK IOCs ==========
    NETWORK_IOCS = {
        'ipv4_address': {
            'pattern': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'description': 'IPv4 address detected',
            'severity': 'LOW',
            'category': 'Network IOC'
        },
        'ipv6_address': {
            'pattern': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'description': 'IPv6 address detected',
            'severity': 'LOW',
            'category': 'Network IOC'
        },
        'private_ip': {
            'pattern': r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
            'description': 'Private/Internal IP address',
            'severity': 'LOW',
            'category': 'Network IOC'
        },
        'suspicious_domain': {
            'pattern': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:tk|ml|ga|cf|gq|pw|cc|ws|top|xyz|club|online|site|website|space|live)\b',
            'description': 'Suspicious TLD domain (commonly used for malware)',
            'severity': 'HIGH',
            'category': 'Network IOC'
        },
        'dga_domain': {
            'pattern': r'\b[a-z]{10,}\.(?:com|net|org|ru|cn)\b',
            'description': 'Potential Domain Generation Algorithm (DGA) domain',
            'severity': 'MEDIUM',
            'category': 'Network IOC'
        },
        'c2_port': {
            'pattern': r'\b(?:4444|8080|31337|12345|54321|1337|6667|6666|9999)\b',
            'description': 'Common C2/backdoor port number',
            'severity': 'HIGH',
            'category': 'Network IOC'
        },
        'url_shortener': {
            'pattern': r'https?://(?:bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|is\.gd|buff\.ly|adf\.ly)/[^\s]+',
            'description': 'URL shortener (potential phishing/malware distribution)',
            'severity': 'MEDIUM',
            'category': 'Network IOC'
        },
        'tor_onion': {
            'pattern': r'\b[a-z2-7]{16,56}\.onion\b',
            'description': 'Tor onion address (anonymity network)',
            'severity': 'HIGH',
            'category': 'Network IOC'
        },
    }

    # ========== MALWARE SIGNATURES ==========
    MALWARE_SIGNATURES = {
        'backdoor_keyword': {
            'pattern': r'\b(?:backdoor|trojan|rootkit|rat|remote[_\s-]?access|metasploit|meterpreter|cobaltstrike|empire)\b',
            'description': 'Backdoor/RAT keyword detected',
            'severity': 'CRITICAL',
            'category': 'Malware'
        },
        'ransomware_keyword': {
            'pattern': r'\b(?:ransomware|wannacry|cryptolocker|locky|cerber|petya|notpetya|ryuk|maze|sodinokibi|revil|darkside|conti)\b',
            'description': 'Ransomware-related keyword',
            'severity': 'CRITICAL',
            'category': 'Malware'
        },
        'ransomware_extension': {
            'pattern': r'\.(?:encrypted|locked|crypto|cerber|locky|zepto|osiris|thor|aesir|zzzzz)\b',
            'description': 'Ransomware file extension',
            'severity': 'CRITICAL',
            'category': 'Malware'
        },
        'ransomware_note': {
            'pattern': r'(?:your files have been encrypted|decrypt|ransom|bitcoin|payment|restore|recovery)/i',
            'description': 'Ransomware note language',
            'severity': 'CRITICAL',
            'category': 'Malware'
        },
        'keylogger_keyword': {
            'pattern': r'\b(?:keylog|keystroke|key[_-]?press|keyboard[_-]?hook|GetAsyncKeyState|SetWindowsHookEx)\b',
            'description': 'Keylogger-related pattern',
            'severity': 'HIGH',
            'category': 'Malware'
        },
        'screen_capture': {
            'pattern': r'\b(?:screenshot|screen[_-]?capture|BitBlt|GdipCreateBitmapFromHBITMAP)\b',
            'description': 'Screen capture functionality',
            'severity': 'MEDIUM',
            'category': 'Malware'
        },
        'credential_theft': {
            'pattern': r'\b(?:mimikatz|lsass|sam\.hive|ntds\.dit|secretsdump|lazagne|dumpcreds)\b',
            'description': 'Credential dumping tool/technique',
            'severity': 'CRITICAL',
            'category': 'Malware'
        },
        'process_injection': {
            'pattern': r'\b(?:CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|SetThreadContext|QueueUserAPC|process[_-]?hollow)\b',
            'description': 'Process injection technique',
            'severity': 'HIGH',
            'category': 'Malware'
        },
        'anti_analysis': {
            'pattern': r'\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|anti[_-]?vm|sandbox[_-]?detect|debugger[_-]?detect)\b',
            'description': 'Anti-analysis/anti-debugging technique',
            'severity': 'HIGH',
            'category': 'Malware'
        },
        'packer_signature': {
            'pattern': r'\b(?:UPX|Themida|VMProtect|Armadillo|Enigma|ASPack|PECompact|Molebox)\b',
            'description': 'Software packer (potential malware obfuscation)',
            'severity': 'MEDIUM',
            'category': 'Malware'
        },
    }

    # ========== FILE SYSTEM IOCs ==========
    FILE_IOCS = {
        'suspicious_filename': {
            'pattern': r'\b(?:svchost32|csrss32|lsass32|winlogon32|explorer32|system32\.exe|notepad32)\b',
            'description': 'Suspicious filename mimicking Windows process',
            'severity': 'HIGH',
            'category': 'File IOC'
        },
        'suspicious_location': {
            'pattern': r'(?:C:\\Windows\\Temp|C:\\Windows\\Tasks|C:\\ProgramData\\[^\\]+\.exe|%APPDATA%\\[^\\]+\.exe|%TEMP%\\[^\\]+\.exe)',
            'description': 'Suspicious file location',
            'severity': 'MEDIUM',
            'category': 'File IOC'
        },
        'double_extension': {
            'pattern': r'\.[a-z]{2,4}\.(?:exe|scr|com|bat|cmd|vbs|ps1|js)',
            'description': 'Double file extension (potential malware)',
            'severity': 'HIGH',
            'category': 'File IOC'
        },
        'executable_disguise': {
            'pattern': r'\.(?:pdf|doc|xls|txt|jpg|png)\.(?:exe|scr|com|bat|vbs)',
            'description': 'Executable disguised as document',
            'severity': 'HIGH',
            'category': 'File IOC'
        },
        'suspicious_script': {
            'pattern': r'\.(?:vbs|vbe|js|jse|wsf|wsh|hta|bat|cmd|ps1)$',
            'description': 'Script file (potential malware)',
            'severity': 'MEDIUM',
            'category': 'File IOC'
        },
    }

    # ========== PERSISTENCE MECHANISMS ==========
    PERSISTENCE_IOCS = {
        'registry_autorun': {
            'pattern': r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|RunServices)',
            'description': 'Registry autorun key',
            'severity': 'HIGH',
            'category': 'Persistence'
        },
        'startup_folder': {
            'pattern': r'(?:C:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup|%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup)',
            'description': 'Startup folder modification',
            'severity': 'MEDIUM',
            'category': 'Persistence'
        },
        'scheduled_task': {
            'pattern': r'\b(?:schtasks|at\s+\d|New-ScheduledTask|Register-ScheduledTask)\b',
            'description': 'Scheduled task creation',
            'severity': 'MEDIUM',
            'category': 'Persistence'
        },
        'service_creation': {
            'pattern': r'\b(?:sc\.exe\s+create|New-Service|CreateService)\b',
            'description': 'Windows service creation',
            'severity': 'HIGH',
            'category': 'Persistence'
        },
        'wmi_persistence': {
            'pattern': r'\b(?:wmic.*call\s+create|__EventFilter|__EventConsumer|ActiveScriptEventConsumer)\b',
            'description': 'WMI persistence technique',
            'severity': 'HIGH',
            'category': 'Persistence'
        },
        'dll_hijacking': {
            'pattern': r'\b(?:AppInit_DLLs|AppCertDLLs|IFEO|Image File Execution Options)\b',
            'description': 'DLL hijacking technique',
            'severity': 'HIGH',
            'category': 'Persistence'
        },
    }

    # ========== POWERSHELL OBFUSCATION ==========
    POWERSHELL_IOCS = {
        'powershell_download': {
            'pattern': r'\b(?:Invoke-WebRequest|IWR|wget|curl|DownloadString|DownloadFile|Net\.WebClient|System\.Net\.WebClient)\b',
            'description': 'PowerShell download command',
            'severity': 'HIGH',
            'category': 'PowerShell'
        },
        'powershell_execution': {
            'pattern': r'\b(?:Invoke-Expression|IEX|Invoke-Command|ICM|Start-Process)\b',
            'description': 'PowerShell execution command',
            'severity': 'MEDIUM',
            'category': 'PowerShell'
        },
        'powershell_bypass': {
            'pattern': r'-(?:ExecutionPolicy|Exec|EP)\s+(?:Bypass|Unrestricted|RemoteSigned)',
            'description': 'PowerShell execution policy bypass',
            'severity': 'HIGH',
            'category': 'PowerShell'
        },
        'powershell_hidden': {
            'pattern': r'-(?:WindowStyle|W)\s+Hidden',
            'description': 'Hidden PowerShell window',
            'severity': 'MEDIUM',
            'category': 'PowerShell'
        },
        'powershell_encoded': {
            'pattern': r'-(?:EncodedCommand|Enc|EC)\s+[A-Za-z0-9+/=]{50,}',
            'description': 'Base64 encoded PowerShell command',
            'severity': 'HIGH',
            'category': 'PowerShell'
        },
        'powershell_reflective': {
            'pattern': r'\b(?:\[System\.Reflection\.Assembly\]::Load|\[Reflection\.Assembly\]::Load|Load\([^)]*byte\[\])',
            'description': 'Reflective assembly loading (in-memory execution)',
            'severity': 'HIGH',
            'category': 'PowerShell'
        },
    }

    # ========== OBFUSCATION TECHNIQUES ==========
    OBFUSCATION_IOCS = {
        'base64_encoded': {
            'pattern': r'\b(?:[A-Za-z0-9+/]{40,}={0,2})\b',
            'description': 'Base64 encoded data',
            'severity': 'LOW',
            'category': 'Obfuscation'
        },
        'hex_encoded': {
            'pattern': r'(?:0x[0-9a-fA-F]{2,}|\\x[0-9a-fA-F]{2})',
            'description': 'Hex encoded data',
            'severity': 'LOW',
            'category': 'Obfuscation'
        },
        'javascript_eval': {
            'pattern': r'\beval\s*\(|Function\s*\(|setTimeout\s*\(|setInterval\s*\(',
            'description': 'JavaScript eval/dynamic execution',
            'severity': 'MEDIUM',
            'category': 'Obfuscation'
        },
        'string_concat': {
            'pattern': r'(?:\+\s*["\'][a-z]\s*\+\s*["\']){3,}',
            'description': 'Excessive string concatenation (obfuscation)',
            'severity': 'LOW',
            'category': 'Obfuscation'
        },
        'char_code': {
            'pattern': r'(?:String\.fromCharCode|chr\(|char\()',
            'description': 'Character code conversion (obfuscation)',
            'severity': 'MEDIUM',
            'category': 'Obfuscation'
        },
    }

    # ========== CREDENTIAL/SENSITIVE DATA IOCs ==========
    CREDENTIAL_IOCS = {
        'hardcoded_password': {
            'pattern': r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{3,}["\']',
            'description': 'Hardcoded password',
            'severity': 'HIGH',
            'category': 'Credentials'
        },
        'api_key_generic': {
            'pattern': r'(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{20,}',
            'description': 'API key/token',
            'severity': 'HIGH',
            'category': 'Credentials'
        },
        'aws_access_key': {
            'pattern': r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b',
            'description': 'AWS access key',
            'severity': 'CRITICAL',
            'category': 'Credentials'
        },
        'aws_secret_key': {
            'pattern': r'\b[A-Za-z0-9/+=]{40}\b',
            'description': 'Potential AWS secret key',
            'severity': 'HIGH',
            'category': 'Credentials'
        },
        'github_token': {
            'pattern': r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b',
            'description': 'GitHub personal access token',
            'severity': 'HIGH',
            'category': 'Credentials'
        },
        'slack_token': {
            'pattern': r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b',
            'description': 'Slack API token',
            'severity': 'HIGH',
            'category': 'Credentials'
        },
        'jwt_token': {
            'pattern': r'\bey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b',
            'description': 'JWT token',
            'severity': 'MEDIUM',
            'category': 'Credentials'
        },
        'private_key': {
            'pattern': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            'description': 'Private key material',
            'severity': 'CRITICAL',
            'category': 'Credentials'
        },
        'ssh_key': {
            'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'description': 'SSH private key',
            'severity': 'CRITICAL',
            'category': 'Credentials'
        },
        'connection_string': {
            'pattern': r'(?:Server|Data Source|Initial Catalog|User ID|Password|Uid|Pwd)\s*=',
            'description': 'Database connection string',
            'severity': 'HIGH',
            'category': 'Credentials'
        },
    }

    # ========== CRYPTOCURRENCY IOCs ==========
    CRYPTO_IOCS = {
        'bitcoin_address': {
            'pattern': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'description': 'Bitcoin address',
            'severity': 'MEDIUM',
            'category': 'Cryptocurrency'
        },
        'ethereum_address': {
            'pattern': r'\b0x[a-fA-F0-9]{40}\b',
            'description': 'Ethereum address',
            'severity': 'MEDIUM',
            'category': 'Cryptocurrency'
        },
        'monero_address': {
            'pattern': r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
            'description': 'Monero address',
            'severity': 'MEDIUM',
            'category': 'Cryptocurrency'
        },
        'crypto_miner': {
            'pattern': r'\b(?:xmrig|cpuminer|cgminer|bfgminer|ethminer|phoenixminer|teamredminer|cryptonight)\b',
            'description': 'Cryptocurrency miner',
            'severity': 'HIGH',
            'category': 'Cryptocurrency'
        },
    }

    # ========== ATTACK PATTERNS ==========
    ATTACK_PATTERNS = {
        'sql_injection': {
            'pattern': r'(?:union\s+select|or\s+1\s*=\s*1|drop\s+table|exec\s*\(|;--)',
            'description': 'SQL injection pattern',
            'severity': 'HIGH',
            'category': 'Attack'
        },
        'xss_pattern': {
            'pattern': r'(?:<script|javascript:|onerror\s*=|onclick\s*=|<iframe)',
            'description': 'Cross-Site Scripting (XSS) pattern',
            'severity': 'HIGH',
            'category': 'Attack'
        },
        'command_injection': {
            'pattern': r'(?:;|\||&|`)\s*(?:cat|ls|dir|whoami|wget|curl|nc|netcat|bash|sh|cmd|powershell)',
            'description': 'Command injection pattern',
            'severity': 'HIGH',
            'category': 'Attack'
        },
        'path_traversal': {
            'pattern': r'\.\.[\\/]|\.\.%2[fF]|%252e%252e',
            'description': 'Path traversal attack',
            'severity': 'MEDIUM',
            'category': 'Attack'
        },
        'ldap_injection': {
            'pattern': r'\*\)\(\w+=\*',
            'description': 'LDAP injection pattern',
            'severity': 'MEDIUM',
            'category': 'Attack'
        },
    }

    def __init__(self):
        """Initialize IOC Scanner"""
        self.all_patterns = {
            **self.NETWORK_IOCS,
            **self.MALWARE_SIGNATURES,
            **self.FILE_IOCS,
            **self.PERSISTENCE_IOCS,
            **self.POWERSHELL_IOCS,
            **self.OBFUSCATION_IOCS,
            **self.CREDENTIAL_IOCS,
            **self.CRYPTO_IOCS,
            **self.ATTACK_PATTERNS,
        }
        self.results = []

    def scan_text(self, text: str) -> Dict:
        """
        Comprehensive IOC scan of text content

        Args:
            text: Text content to scan

        Returns:
            Dictionary with scan results, threat scores, and findings
        """
        results = {
            'iocs_found': {},
            'threat_score': 0,
            'threat_level': 'Low',
            'findings_by_category': defaultdict(list),
            'severity_counts': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'total_iocs': 0
        }

        # Scan for all IOC patterns
        for ioc_name, ioc_data in self.all_patterns.items():
            try:
                matches = re.findall(ioc_data['pattern'], text, re.IGNORECASE | re.MULTILINE)

                if matches:
                    # Remove duplicates
                    unique_matches = list(dict.fromkeys(matches))
                    count = len(unique_matches)

                    # Store IOC findings
                    ioc_finding = {
                        'name': ioc_name,
                        'description': ioc_data['description'],
                        'severity': ioc_data['severity'],
                        'category': ioc_data['category'],
                        'count': count,
                        'matches': unique_matches[:10]  # Limit to 10 examples
                    }

                    results['iocs_found'][ioc_name] = ioc_finding
                    results['findings_by_category'][ioc_data['category']].append(ioc_finding)
                    results['severity_counts'][ioc_data['severity']] += count
                    results['total_iocs'] += count

                    # Calculate threat score
                    severity_weights = {'CRITICAL': 50, 'HIGH': 25, 'MEDIUM': 10, 'LOW': 2}
                    results['threat_score'] += count * severity_weights.get(ioc_data['severity'], 1)

            except re.error as e:
                print(f"    ⚠️  Regex error for {ioc_name}: {str(e)}")
                continue

        # Determine threat level
        if results['threat_score'] >= 200:
            results['threat_level'] = '🔴 CRITICAL'
        elif results['threat_score'] >= 100:
            results['threat_level'] = '🟠 HIGH'
        elif results['threat_score'] >= 30:
            results['threat_level'] = '🟡 MEDIUM'
        else:
            results['threat_level'] = '🟢 LOW'

        return results

    def generate_report_html(self, scan_results: Dict) -> str:
        """
        Generate HTML report for IOC scan results

        Args:
            scan_results: Results from scan_text()

        Returns:
            HTML string with formatted IOC report
        """
        html = '<div class="ioc-scanner-report">\n'

        # Threat Summary
        html += '<div class="threat-summary" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; padding: 25px; border-radius: 12px; margin-bottom: 25px; box-shadow: 0 4px 15px rgba(0,0,0,0.2);">\n'
        html += '<h2 style="margin-top: 0; font-size: 28px;">🛡️ IOC Scanner Results</h2>\n'
        html += f'<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px;">\n'
        html += f'  <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;">\n'
        html += f'    <div style="font-size: 32px; font-weight: bold;">{scan_results["total_iocs"]}</div>\n'
        html += f'    <div style="font-size: 14px; opacity: 0.9;">Total IOCs</div>\n'
        html += f'  </div>\n'
        html += f'  <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;">\n'
        html += f'    <div style="font-size: 32px; font-weight: bold;">{scan_results["threat_level"]}</div>\n'
        html += f'    <div style="font-size: 14px; opacity: 0.9;">Threat Level</div>\n'
        html += f'  </div>\n'
        html += f'  <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;">\n'
        html += f'    <div style="font-size: 32px; font-weight: bold;">{scan_results["threat_score"]}</div>\n'
        html += f'    <div style="font-size: 14px; opacity: 0.9;">Threat Score</div>\n'
        html += f'  </div>\n'
        html += f'</div>\n'
        html += '</div>\n\n'

        # Severity Breakdown
        if scan_results['total_iocs'] > 0:
            html += '<div style="margin-bottom: 25px;">\n'
            html += '<h3 style="color: #2c3e50;">📊 Severity Breakdown</h3>\n'
            html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">\n'

            severity_colors = {
                'CRITICAL': '#e74c3c',
                'HIGH': '#e67e22',
                'MEDIUM': '#f39c12',
                'LOW': '#3498db'
            }

            for severity, count in scan_results['severity_counts'].items():
                if count > 0:
                    html += f'  <div style="background: {severity_colors[severity]}; color: white; padding: 15px; border-radius: 8px; text-align: center;">\n'
                    html += f'    <div style="font-size: 28px; font-weight: bold;">{count}</div>\n'
                    html += f'    <div style="font-size: 14px;">{severity}</div>\n'
                    html += f'  </div>\n'

            html += '</div>\n'
            html += '</div>\n\n'

        # IOCs by Category
        if scan_results['findings_by_category']:
            html += '<h3 style="color: #2c3e50;">🔍 IOCs by Category</h3>\n'

            for category, findings in sorted(scan_results['findings_by_category'].items()):
                html += f'<div class="ioc-category" style="margin-bottom: 30px;">\n'
                html += f'<h4 style="background: #34495e; color: white; padding: 12px; border-radius: 8px; margin-bottom: 15px;">📌 {category} ({len(findings)} types)</h4>\n'
                html += '<table class="forensic-table" style="width: 100%; border-collapse: collapse;">\n'
                html += '<thead style="background: #ecf0f1;"><tr><th>IOC Type</th><th>Description</th><th>Severity</th><th>Count</th><th>Examples</th></tr></thead>\n'
                html += '<tbody>\n'

                for finding in sorted(findings, key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}[x['severity']]):
                    # Severity badge color
                    severity_colors = {
                        'CRITICAL': 'background: #e74c3c;',
                        'HIGH': 'background: #e67e22;',
                        'MEDIUM': 'background: #f39c12;',
                        'LOW': 'background: #3498db;'
                    }

                    html += f'<tr>\n'
                    html += f'  <td><strong>{finding["name"].replace("_", " ").title()}</strong></td>\n'
                    html += f'  <td>{finding["description"]}</td>\n'
                    html += f'  <td><span style="{severity_colors[finding["severity"]]} color: white; padding: 4px 12px; border-radius: 12px; font-weight: bold; font-size: 11px;">{finding["severity"]}</span></td>\n'
                    html += f'  <td><strong>{finding["count"]}</strong></td>\n'
                    html += f'  <td style="font-family: monospace; font-size: 11px; word-break: break-all; max-width: 300px;">\n'

                    # Show first 3 examples
                    for i, match in enumerate(finding['matches'][:3]):
                        html += f'    • {str(match)[:100]}<br>\n'

                    if finding['count'] > 3:
                        html += f'    <em style="color: #7f8c8d;">... +{finding["count"] - 3} more</em>\n'

                    html += f'  </td>\n'
                    html += f'</tr>\n'

                html += '</tbody></table>\n'
                html += '</div>\n\n'

        else:
            html += '<div style="background: #d5f4e6; border-left: 4px solid #27ae60; padding: 20px; border-radius: 8px; margin: 20px 0;">\n'
            html += '<p style="margin: 0; color: #27ae60; font-weight: bold; font-size: 16px;">✅ No IOCs detected. System appears clean.</p>\n'
            html += '</div>\n\n'

        # Recommendations
        html += '<div style="background: #ecf0f1; padding: 20px; border-radius: 8px; margin-top: 30px;">\n'
        html += '<h3 style="color: #2c3e50; margin-top: 0;">💡 Investigation Recommendations</h3>\n'
        html += '<ul style="margin: 10px 0; padding-left: 25px; line-height: 1.8;">\n'

        if scan_results['severity_counts']['CRITICAL'] > 0:
            html += '<li style="color: #e74c3c; font-weight: bold;">🚨 CRITICAL threats detected! Immediate isolation and forensic analysis required.</li>\n'
            html += '<li>Capture memory dump for analysis before shutdown.</li>\n'
            html += '<li>Preserve all evidence and maintain chain of custody.</li>\n'
            html += '<li>Analyze all detected IOCs against threat intelligence databases.</li>\n'

        if scan_results['severity_counts']['HIGH'] > 0:
            html += '<li>High severity IOCs found - deep investigation recommended.</li>\n'
            html += '<li>Check detected patterns against MITRE ATT&CK framework.</li>\n'
            html += '<li>Review network logs for communication with detected IPs/domains.</li>\n'

        if scan_results['findings_by_category'].get('Credentials'):
            html += '<li style="color: #e67e22;">⚠️ Credentials detected - assume compromised and rotate immediately.</li>\n'

        if scan_results['findings_by_category'].get('Persistence'):
            html += '<li>Persistence mechanisms detected - check autorun locations and scheduled tasks.</li>\n'

        if scan_results['findings_by_category'].get('Cryptocurrency'):
            html += '<li>Cryptocurrency indicators found - potential cryptojacking activity.</li>\n'

        html += '<li>Document all findings for incident response report.</li>\n'
        html += '<li>Cross-reference IOCs with VirusTotal, AlienVault OTX, and other threat feeds.</li>\n'
        html += '<li>Consider sandbox analysis for suspicious executables.</li>\n'
        html += '</ul>\n'
        html += '</div>\n'

        html += '</div>\n'

        return html


# Convenience function
def scan_for_iocs(text: str) -> Dict:
    """
    Scan text for Indicators of Compromise

    Args:
        text: Text content to scan

    Returns:
        Dictionary with IOC scan results
    """
    scanner = IOCScanner()
    return scanner.scan_text(text)
