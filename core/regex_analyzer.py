"""
Regex Analyzer Module - ENHANCED
====================
Extract patterns and Indicators of Compromise (IOCs) from forensic data
NOW WITH 100+ PATTERNS FOR COMPREHENSIVE THREAT DETECTION
"""

import re
from collections import defaultdict


class RegexAnalyzer:
    """Analyzes forensic data for patterns and Indicators of Compromise (IOCs)"""

    # Regex patterns for various IOCs - EXPANDED
    PATTERNS = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
        'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'phone': r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        'file_path': r'(?:[A-Za-z]:\\|/)(?:[^\\\/:*?"<>|\r\n]+[\\\/])*[^\\\/:*?"<>|\r\n]*',
        'registry_key': r'HKEY_[A-Z_]+\\[^\s\r\n]+',
        'creditcard': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
        'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        'ethereum': r'\b0x[a-fA-F0-9]{40}\b',
        'monero': r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'md5_hash': r'\b[a-fA-F0-9]{32}\b',
        'sha1_hash': r'\b[a-fA-F0-9]{40}\b',
        'sha256_hash': r'\b[a-fA-F0-9]{64}\b',
        'sha512_hash': r'\b[a-fA-F0-9]{128}\b',
        'mac_address': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
        'uuid': r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
        'jwt_token': r'\bey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b',
        'base64': r'\b(?:[A-Za-z0-9+/]{40,}={0,2})\b',
        'hex_string': r'(?:0x[0-9a-fA-F]{2,}|\\x[0-9a-fA-F]{2})',
        'tor_onion': r'\b[a-z2-7]{16,56}\.onion\b',
        'temp_email': r'\b[A-Za-z0-9._%+-]+@(?:temp-mail\.org|guerrillamail\.com|10minutemail\.com|throwaway\.email|mailinator\.com|maildrop\.cc)\b',
        'suspicious_tld': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:tk|ml|ga|cf|gq|pw|cc|ws|top|xyz|club|online|site|website|space|live)\b',
        'url_shortener': r'https?://(?:bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|is\.gd|buff\.ly|adf\.ly)/[^\s]+',
        'suspicious_extension': r'\.(?:exe|scr|com|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|ps1|pif|msi|dll)$',
        'double_extension': r'\.[a-z]{2,4}\.(?:exe|scr|com|bat|cmd|vbs|ps1|js)',
    }

    # Suspicious patterns for threat detection - MASSIVELY EXPANDED
    SUSPICIOUS_PATTERNS = {
        'credentials': {
            'password_in_code': r'(?:password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\';]{3,}',
            'api_key': r'(?:api[_-]?key|apikey|access[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{20,}',
            'private_key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
            'ssh_key': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'connection_string': r'(?:Server|Data Source|Initial Catalog|User ID|Password)\s*=',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret': r'\b[A-Za-z0-9/+=]{40}\b',
            'github_token': r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b',
            'slack_token': r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b',
            'google_api': r'AIza[0-9A-Za-z\-_]{35}',
            'stripe_key': r'\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}\b',
            'twilio_key': r'SK[a-z0-9]{32}',
            'mailgun_key': r'key-[0-9a-zA-Z]{32}',
        },
        'malware_indicators': {
            'backdoor_pattern': r'\b(?:backdoor|trojan|rootkit|rat|remote[_\s-]?access|metasploit|meterpreter|cobaltstrike|empire)\b',
            'ransomware_pattern': r'\b(?:ransomware|wannacry|cryptolocker|locky|cerber|petya|notpetya|ryuk|maze|sodinokibi|revil|darkside|conti)\b',
            'keylogger_pattern': r'\b(?:keylog|keystroke|key[_-]?press|GetAsyncKeyState|SetWindowsHookEx)\b',
            'rootkit_pattern': r'\b(?:rootkit|kernel[_-]?module|driver[_-]?inject)\b',
            'credential_dumper': r'\b(?:mimikatz|lsass|sam\.hive|ntds\.dit|secretsdump|lazagne|dumpcreds)\b',
            'screen_capture': r'\b(?:screenshot|screen[_-]?capture|BitBlt|GdipCreateBitmapFromHBITMAP)\b',
            'process_injection': r'\b(?:CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|SetThreadContext|QueueUserAPC|process[_-]?hollow)\b',
            'anti_analysis': r'\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|anti[_-]?vm|sandbox[_-]?detect|debugger[_-]?detect)\b',
            'packer': r'\b(?:UPX|Themida|VMProtect|Armadillo|Enigma|ASPack|PECompact|Molebox)\b',
            'crypto_miner': r'\b(?:xmrig|cpuminer|cgminer|bfgminer|ethminer|phoenixminer|teamredminer|cryptonight)\b',
        },
        'injection_attacks': {
            'sql_injection': r'(?:union\s+select|or\s+1\s*=\s*1|drop\s+table|exec\s*\(|;--)',
            'xss_pattern': r'(?:<script|javascript:|onerror\s*=|onclick\s*=|<iframe)',
            'command_injection': r'(?:;|\||&|`)\s*(?:cat|ls|dir|whoami|wget|curl|nc|netcat|bash|sh|cmd|powershell)',
            'path_traversal': r'\.\.[\\/]|\.\.%2[fF]|%252e%252e',
            'ldap_injection': r'\*\)\(\w+=\*',
            'xml_injection': r'<!\[CDATA\[|<!ENTITY|<!DOCTYPE',
            'template_injection': r'\{\{.*\}\}|\${.*}|<%.*%>',
        },
        'suspicious_commands': {
            'base64_encoded': r'(?:[A-Za-z0-9+/]{40,}={0,2})',
            'powershell_download': r'(?:Invoke-WebRequest|DownloadString|DownloadFile|IWR|iex)',
            'powershell_bypass': r'-(?:ExecutionPolicy|Exec|EP)\s+(?:Bypass|Unrestricted|RemoteSigned)',
            'powershell_hidden': r'-(?:WindowStyle|W)\s+Hidden',
            'powershell_encoded': r'-(?:EncodedCommand|Enc|EC)\s+[A-Za-z0-9+/=]{50,}',
            'scheduled_task': r'(?:schtasks|at\s+\d|New-ScheduledTask|Register-ScheduledTask)',
            'registry_persistence': r'(?:CurrentVersion\\Run|Startup|AppInit_DLLs)',
            'service_creation': r'\b(?:sc\.exe\s+create|New-Service|CreateService)\b',
            'wmi_persistence': r'\b(?:wmic.*call\s+create|__EventFilter|__EventConsumer|ActiveScriptEventConsumer)\b',
            'reflective_load': r'\b(?:\[System\.Reflection\.Assembly\]::Load|\[Reflection\.Assembly\]::Load|Load\([^)]*byte\[\])',
            'disable_av': r'\b(?:Set-MpPreference\s+-DisableRealtimeMonitoring|Disable-WindowsDefender|Stop-Service.*WinDefend)\b',
            'bypass_amsi': r'\b(?:AMSI|AmsiScanBuffer|AmsiInitFailed)\b',
        },
        'obfuscation': {
            'javascript_eval': r'\beval\s*\(|Function\s*\(|setTimeout\s*\(|setInterval\s*\(',
            'string_concat': r'(?:\+\s*["\'][a-z]\s*\+\s*["\']){3,}',
            'char_code': r'(?:String\.fromCharCode|chr\(|char\()',
            'hex_obfuscation': r'\\x[0-9a-fA-F]{2}',
            'unicode_escape': r'\\u[0-9a-fA-F]{4}',
            'rot13': r'\b[n-za-m]{4,}\b',
            'reverse_string': r'(?:strrev|split\([\'\"]\[\'\"]\)\.reverse\(\))',
        },
        'persistence_mechanisms': {
            'startup_folder': r'(?:C:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup|%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup)',
            'dll_hijacking': r'\b(?:AppInit_DLLs|AppCertDLLs|IFEO|Image File Execution Options)\b',
            'autorun_key': r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|RunServices)',
            'task_scheduler': r'\\Microsoft\\Windows\\CurrentVersion\\Schedule\\TaskCache',
            'browser_extension': r'(?:Chrome\\User Data\\Default\\Extensions|Firefox\\Profiles|Edge\\Extensions)',
        },
        'file_indicators': {
            'suspicious_filename': r'\b(?:svchost32|csrss32|lsass32|winlogon32|explorer32|system32\.exe|notepad32)\b',
            'suspicious_location': r'(?:C:\\Windows\\Temp|C:\\Windows\\Tasks|C:\\ProgramData\\[^\\]+\.exe|%APPDATA%\\[^\\]+\.exe|%TEMP%\\[^\\]+\.exe)',
            'executable_disguise': r'\.(?:pdf|doc|xls|txt|jpg|png)\.(?:exe|scr|com|bat|vbs)',
            'script_extension': r'\.(?:vbs|vbe|js|jse|wsf|wsh|hta)$',
        },
        'network_indicators': {
            'c2_port': r'\b(?:4444|8080|31337|12345|54321|1337|6667|6666|9999)\b',
            'reverse_shell': r'\b(?:nc\s+-[el]+|netcat\s+-[el]+|/bin/bash\s+-i|/bin/sh\s+-i)\b',
            'remote_desktop': r'\b(?:3389|5900|5901)\b',
            'smb_share': r'\\\\[a-zA-Z0-9\-\.]+\\[a-zA-Z0-9$\-\._]+',
            'ftp_credentials': r'ftp://[^:]+:[^@]+@',
        },
        'data_exfiltration': {
            'cloud_storage': r'\b(?:dropbox\.com|drive\.google\.com|onedrive\.live\.com|mega\.nz|wetransfer\.com)\b',
            'pastebin': r'\b(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.com)\b',
            'file_sharing': r'\b(?:filebin\.net|sendspace\.com|zippyshare\.com|mediafire\.com)\b',
            'dns_tunneling': r'\b[a-zA-Z0-9]{32,}\.[a-zA-Z0-9-]+\.(?:com|net|org)\b',
        },
    }

    def __init__(self):
        self.results = defaultdict(list)
        self.threat_score = 0

    def extract_all_patterns(self, text):
        """
        Extract all patterns from text

        Args:
            text: Text to analyze

        Returns:
            Dictionary with all extracted patterns
        """
        results = {}

        for pattern_name, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Remove duplicates while preserving order
                unique_matches = list(dict.fromkeys(matches))
                results[pattern_name] = {
                    'count': len(unique_matches),
                    'matches': unique_matches
                }

        return results

    def extract_iocs(self, text, pattern_types=None):
        """
        Extract specific Indicators of Compromise

        Args:
            text: Text to analyze
            pattern_types: List of pattern types to extract (None = all)

        Returns:
            Dictionary of IOCs by type
        """
        if pattern_types is None:
            pattern_types = list(self.PATTERNS.keys())

        iocs = {}

        for pattern_type in pattern_types:
            if pattern_type in self.PATTERNS:
                pattern = self.PATTERNS[pattern_type]
                matches = re.findall(pattern, text, re.IGNORECASE)

                if matches:
                    unique_matches = list(dict.fromkeys(matches))
                    iocs[pattern_type] = unique_matches

        return iocs

    def analyze_text(self, text):
        """
        Analyze text for suspicious patterns and IOCs

        Returns:
            Analysis results with threat scoring
        """
        results = {
            'iocs': self.extract_all_patterns(text),
            'suspicious_patterns': {},
            'threat_score': 0,
            'threat_level': 'Low',
            'findings': []
        }

        # Check for suspicious patterns
        for category, patterns in self.SUSPICIOUS_PATTERNS.items():
            for pattern_name, pattern in patterns.items():
                matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                if matches:
                    unique_matches = list(dict.fromkeys(matches))

                    if category not in results['suspicious_patterns']:
                        results['suspicious_patterns'][category] = {}

                    results['suspicious_patterns'][category][pattern_name] = {
                        'count': len(unique_matches),
                        'matches': unique_matches[:5]  # Limit to 5 examples
                    }

                    # Increase threat score
                    threat_weight = self._get_threat_weight(category)
                    results['threat_score'] += len(unique_matches) * threat_weight

                    # Add finding
                    results['findings'].append({
                        'category': category,
                        'type': pattern_name,
                        'severity': self._get_severity(category),
                        'count': len(unique_matches),
                        'description': self._get_description(category, pattern_name)
                    })

        # Determine threat level based on score
        if results['threat_score'] >= 100:
            results['threat_level'] = '🔴 Critical'
        elif results['threat_score'] >= 50:
            results['threat_level'] = '🟠 High'
        elif results['threat_score'] >= 20:
            results['threat_level'] = '🟡 Medium'
        else:
            results['threat_level'] = '🟢 Low'

        return results

    def _get_threat_weight(self, category):
        """Get threat weight multiplier for scoring"""
        weights = {
            'credentials': 15,
            'malware_indicators': 20,
            'injection_attacks': 12,
            'suspicious_commands': 10,
            'obfuscation': 8,
            'persistence_mechanisms': 15,
            'file_indicators': 12,
            'network_indicators': 10,
            'data_exfiltration': 18
        }
        return weights.get(category, 5)

    def _get_severity(self, category):
        """Get severity level for a suspicious pattern category"""
        severity_map = {
            'credentials': '🔴 Critical',
            'malware_indicators': '🔴 Critical',
            'injection_attacks': '🟠 High',
            'suspicious_commands': '🟠 High',
            'obfuscation': '🟡 Medium',
            'persistence_mechanisms': '🟠 High',
            'file_indicators': '🟠 High',
            'network_indicators': '🟡 Medium',
            'data_exfiltration': '🔴 Critical'
        }
        return severity_map.get(category, '🟢 Low')

    def _get_description(self, category, pattern_name):
        """Get description for a suspicious pattern"""
        descriptions = {
            'credentials': {
                'password_in_code': 'Hardcoded password detected in source code',
                'api_key': 'API key or token detected - potential credential exposure',
                'private_key': 'Private key material detected - serious security risk',
                'ssh_key': 'SSH private key detected - critical security risk',
                'connection_string': 'Database connection string detected',
                'aws_key': 'AWS access key detected - potential credential leak',
                'aws_secret': 'Potential AWS secret key detected',
                'github_token': 'GitHub personal access token detected',
                'slack_token': 'Slack API token detected',
                'google_api': 'Google API key detected',
                'stripe_key': 'Stripe API key detected',
                'twilio_key': 'Twilio API key detected',
                'mailgun_key': 'Mailgun API key detected',
            },
            'malware_indicators': {
                'backdoor_pattern': 'Potential backdoor code pattern detected',
                'ransomware_pattern': 'Ransomware-related keywords detected',
                'keylogger_pattern': 'Keylogger-related code detected',
                'rootkit_pattern': 'Rootkit indicators detected',
                'credential_dumper': 'Credential dumping tool detected',
                'screen_capture': 'Screen capture functionality detected',
                'process_injection': 'Process injection technique detected',
                'anti_analysis': 'Anti-analysis/anti-debugging technique detected',
                'packer': 'Software packer detected (potential malware obfuscation)',
                'crypto_miner': 'Cryptocurrency miner detected',
            },
            'injection_attacks': {
                'sql_injection': 'Potential SQL injection pattern detected',
                'xss_pattern': 'Cross-Site Scripting (XSS) pattern detected',
                'command_injection': 'Command injection pattern detected',
                'path_traversal': 'Path traversal attack detected',
                'ldap_injection': 'LDAP injection pattern detected',
                'xml_injection': 'XML injection pattern detected',
                'template_injection': 'Template injection pattern detected',
            },
            'suspicious_commands': {
                'base64_encoded': 'Base64 encoded data detected - may be obfuscated malware',
                'powershell_download': 'PowerShell download command detected',
                'powershell_bypass': 'PowerShell execution policy bypass detected',
                'powershell_hidden': 'Hidden PowerShell window detected',
                'powershell_encoded': 'Base64 encoded PowerShell command detected',
                'scheduled_task': 'Scheduled task creation detected - persistence mechanism',
                'registry_persistence': 'Registry persistence mechanism detected',
                'service_creation': 'Windows service creation detected',
                'wmi_persistence': 'WMI persistence technique detected',
                'reflective_load': 'Reflective assembly loading detected (in-memory execution)',
                'disable_av': 'Antivirus disabling command detected',
                'bypass_amsi': 'AMSI bypass technique detected',
            },
            'obfuscation': {
                'javascript_eval': 'JavaScript eval/dynamic execution detected',
                'string_concat': 'Excessive string concatenation (obfuscation technique)',
                'char_code': 'Character code conversion (obfuscation)',
                'hex_obfuscation': 'Hex encoding detected (potential obfuscation)',
                'unicode_escape': 'Unicode escape sequences detected',
                'rot13': 'Potential ROT13 encoded data',
                'reverse_string': 'String reversal technique detected',
            },
            'persistence_mechanisms': {
                'startup_folder': 'Startup folder modification detected',
                'dll_hijacking': 'DLL hijacking technique detected',
                'autorun_key': 'Registry autorun key detected',
                'task_scheduler': 'Task scheduler modification detected',
                'browser_extension': 'Browser extension installation detected',
            },
            'file_indicators': {
                'suspicious_filename': 'Suspicious filename mimicking Windows process',
                'suspicious_location': 'Suspicious file location detected',
                'executable_disguise': 'Executable disguised as document',
                'script_extension': 'Script file detected (potential malware)',
            },
            'network_indicators': {
                'c2_port': 'Common C2/backdoor port number detected',
                'reverse_shell': 'Reverse shell command detected',
                'remote_desktop': 'Remote desktop port detected',
                'smb_share': 'SMB share access detected',
                'ftp_credentials': 'FTP credentials in URL',
            },
            'data_exfiltration': {
                'cloud_storage': 'Cloud storage service detected (potential data exfiltration)',
                'pastebin': 'Pastebin service detected (potential data exfiltration)',
                'file_sharing': 'File sharing service detected',
                'dns_tunneling': 'Potential DNS tunneling detected',
            },
        }

        return descriptions.get(category, {}).get(pattern_name, 'Suspicious pattern detected')

    def generate_report(self, analysis_results):
        """
        Generate HTML table report of findings

        Args:
            analysis_results: Results from analyze_text()

        Returns:
            HTML string with formatted results
        """
        html = '<div class="regex-analysis-report">\n'

        # Threat Summary
        html += '<div class="threat-summary" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px;">\n'
        html += f'<h3 style="margin-top: 0;">🔍 Threat Analysis Summary</h3>\n'
        html += f'<p style="font-size: 18px;"><strong>Threat Level:</strong> {analysis_results["threat_level"]}</p>\n'
        html += f'<p style="font-size: 16px;"><strong>Threat Score:</strong> {analysis_results["threat_score"]}/100</p>\n'
        html += '</div>\n\n'

        # IOCs Table with expandable sections
        if analysis_results['iocs']:
            html += '<h3>📊 Indicators of Compromise (IOCs)</h3>\n'
            html += '<table class="forensic-table">\n'
            html += '<thead><tr><th>Type</th><th>Count</th><th>Examples</th><th>Action</th></tr></thead>\n'
            html += '<tbody>\n'

            ioc_id = 0
            for ioc_type, data in sorted(analysis_results['iocs'].items()):
                ioc_id += 1
                total_matches = len(data['matches'])

                # Show first 5 examples
                examples_preview = ', '.join(str(m) for m in data['matches'][:5])

                # All matches for expandable section
                all_matches = '\n'.join(f'• {m}' for m in data['matches'])

                html += f'<tr>'
                html += f'<td><strong>{ioc_type.replace("_", " ").title()}</strong></td>'
                html += f'<td><span style="background: #3498db; color: white; padding: 3px 10px; border-radius: 12px; font-weight: bold;">{data["count"]}</span></td>'

                if total_matches > 5:
                    html += f'<td style="word-break: break-all; font-family: monospace; font-size: 12px;">'
                    html += f'{examples_preview} <em>(+{total_matches - 5} more)</em>'
                    html += f'</td>'
                    html += f'<td><button onclick="toggleIOCList(\'ioc_{ioc_id}\')" style="background: #3498db; color: white; border: none; padding: 5px 15px; border-radius: 5px; cursor: pointer; font-size: 12px;">📋 Show All</button></td>'
                else:
                    html += f'<td style="word-break: break-all; font-family: monospace; font-size: 12px;">{examples_preview}</td>'
                    html += f'<td>-</td>'

                html += f'</tr>\n'

                # Hidden expandable section
                if total_matches > 5:
                    html += f'<tr id="ioc_{ioc_id}" style="display: none;">'
                    html += f'<td colspan="4" style="background: #f8f9fa; padding: 15px;">'
                    html += f'<h4 style="margin-top: 0;">All {ioc_type.replace("_", " ").title()} ({total_matches} total)</h4>'
                    html += f'<pre style="white-space: pre-wrap; font-size: 11px; max-height: 400px; overflow-y: auto; background: white; padding: 10px; border-radius: 5px;">{all_matches}</pre>'
                    html += f'<button onclick="toggleIOCList(\'ioc_{ioc_id}\')" style="background: #e74c3c; color: white; border: none; padding: 5px 15px; border-radius: 5px; cursor: pointer; font-size: 12px; margin-top: 10px;">❌ Hide</button>'
                    html += f'</td>'
                    html += f'</tr>\n'

            html += '</tbody></table>\n\n'
        else:
            html += '<p style="color: #27ae60; font-weight: bold;">✅ No IOCs detected in this category</p>\n\n'

        # Suspicious Patterns Table
        if analysis_results['suspicious_patterns']:
            html += '<h3>⚠️ Suspicious Patterns Detected</h3>\n'
            html += '<table class="forensic-table">\n'
            html += '<thead><tr><th>Category</th><th>Pattern Type</th><th>Severity</th><th>Count</th><th>Description</th></tr></thead>\n'
            html += '<tbody>\n'

            for finding in analysis_results['findings']:
                # Color-code by severity
                if '🔴' in finding['severity']:
                    row_style = ' style="background-color: #ffe6e6;"'
                elif '🟠' in finding['severity']:
                    row_style = ' style="background-color: #fff4e6;"'
                elif '🟡' in finding['severity']:
                    row_style = ' style="background-color: #fffde6;"'
                else:
                    row_style = ''

                html += f'<tr{row_style}>'
                html += f'<td><strong>{finding["category"].replace("_", " ").title()}</strong></td>'
                html += f'<td>{finding["type"].replace("_", " ").title()}</td>'
                html += f'<td><strong>{finding["severity"]}</strong></td>'
                html += f'<td>{finding["count"]}</td>'
                html += f'<td>{finding["description"]}</td>'
                html += '</tr>\n'

            html += '</tbody></table>\n\n'
        else:
            html += '<p style="color: #27ae60; font-weight: bold;">✅ No suspicious patterns detected</p>\n\n'

        # Recommendations
        html += '<h3>💡 Recommendations</h3>\n'
        html += '<div style="background: #f8f9fa; padding: 15px; border-left: 4px solid #3498db; border-radius: 5px;">\n'
        html += '<ul style="margin: 0; padding-left: 20px;">\n'

        if analysis_results['threat_score'] >= 100:
            html += '<li style="margin-bottom: 10px;">🔴 <strong>IMMEDIATE ACTION REQUIRED:</strong> Critical threats detected. Isolate system and conduct deep forensic analysis.</li>\n'
            html += '<li style="margin-bottom: 10px;">Scan all detected IOCs against threat intelligence databases (VirusTotal, AlientVault OTX).</li>\n'
            html += '<li style="margin-bottom: 10px;">Review all credentials and API keys found - assume compromised and rotate immediately.</li>\n'
            html += '<li style="margin-bottom: 10px;">Capture memory dump for advanced malware analysis.</li>\n'
            html += '<li style="margin-bottom: 10px;">Document all findings and initiate incident response procedures.</li>\n'
        elif analysis_results['threat_score'] >= 50:
            html += '<li style="margin-bottom: 10px;">🟠 <strong>HIGH PRIORITY:</strong> Multiple suspicious indicators found. Investigation recommended.</li>\n'
            html += '<li style="margin-bottom: 10px;">Review detected patterns for false positives.</li>\n'
            html += '<li style="margin-bottom: 10px;">Verify file integrity using hash comparison tools.</li>\n'
            html += '<li style="margin-bottom: 10px;">Check detected IPs and domains against threat intelligence feeds.</li>\n'
            html += '<li style="margin-bottom: 10px;">Monitor network traffic for suspicious connections.</li>\n'
        elif analysis_results['threat_score'] >= 20:
            html += '<li style="margin-bottom: 10px;">🟡 <strong>MEDIUM PRIORITY:</strong> Some suspicious patterns detected. Further review recommended.</li>\n'
            html += '<li style="margin-bottom: 10px;">Monitor systems for unusual activity.</li>\n'
            html += '<li style="margin-bottom: 10px;">Verify detected patterns are legitimate.</li>\n'
            html += '<li style="margin-bottom: 10px;">Update antivirus signatures and scan affected systems.</li>\n'
        else:
            html += '<li style="margin-bottom: 10px;">🟢 <strong>LOW RISK:</strong> Minimal or no suspicious indicators detected.</li>\n'
            html += '<li style="margin-bottom: 10px;">Continue normal security monitoring procedures.</li>\n'
            html += '<li style="margin-bottom: 10px;">Maintain regular backups and system updates.</li>\n'

        html += '<li style="margin-bottom: 10px;">Document all findings for incident response records.</li>\n'
        html += '<li style="margin-bottom: 10px;">Consider using hash comparison to identify known malware.</li>\n'
        html += '<li style="margin-bottom: 10px;">Review system logs for correlating events.</li>\n'
        html += '</ul>\n'
        html += '</div>\n'

        html += '</div>\n'

        return html

    def search_pattern(self, text, custom_pattern):
        """
        Search for custom regex pattern in text

        Args:
            text: Text to search
            custom_pattern: Custom regex pattern

        Returns:
            List of matches
        """
        try:
            matches = re.findall(custom_pattern, text, re.IGNORECASE | re.MULTILINE)
            return list(dict.fromkeys(matches))  # Remove duplicates
        except re.error as e:
            return [f"❌ Invalid regex pattern: {str(e)}"]


def analyze_forensic_output(forensic_text):
    """
    Convenience function to analyze forensic command output

    Args:
        forensic_text: Output from forensic commands

    Returns:
        Analysis results dictionary
    """
    analyzer = RegexAnalyzer()
    return analyzer.analyze_text(forensic_text)
