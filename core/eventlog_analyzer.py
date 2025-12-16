"""
Windows Event Log Analysis Module
==================================
Forensic analysis of Windows Event Logs
Extracts and analyzes Security, System, Application, PowerShell, and WMI logs

Event IDs Tracked:
- Security: 4624 (Logon), 4625 (Failed Logon), 4634 (Logoff), 4648 (Explicit Credentials),
            4672 (Special Privileges), 4720 (User Created), 4732 (User Added to Group)
- System: 7045 (Service Installed), 6005 (Event Log Started), 6006 (Event Log Stopped),
          1074 (System Shutdown), 20001/20003 (USB Device)
- PowerShell: 4103/4104 (Script Block Logging), 400/403 (Engine Lifecycle)
- Application: 1000/1001 (Application Errors), WMI Activity
- RDP: 1149 (Remote Desktop), 21/22/24/25 (RemoteDesktopServices)

Anomaly Detection:
- Brute force login attempts
- Suspicious PowerShell commands
- Unusual logon times
- Unexpected service installations
- Remote access patterns
- Privilege escalation
"""

import sys
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter


class EventLogAnalyzer:
    """
    Analyzes Windows Event Logs for forensic artifacts
    Uses Python's win32evtlog module on Windows
    On non-Windows systems, provides guidance
    """

    def __init__(self):
        self.is_windows = sys.platform == 'win32'

        # Event storage
        self.events = {
            'security': [],
            'system': [],
            'application': [],
            'powershell': [],
            'rdp': []
        }

        # Anomaly storage
        self.anomalies = {
            'brute_force': [],
            'suspicious_powershell': [],
            'unusual_logons': [],
            'suspicious_services': [],
            'remote_access': [],
            'privilege_escalation': [],
            'usb_activity': []
        }

        # Statistics
        self.stats = {
            'total_events': 0,
            'security_events': 0,
            'system_events': 0,
            'application_events': 0,
            'powershell_events': 0,
            'failed_logons': 0,
            'successful_logons': 0,
            'service_installations': 0,
            'rdp_connections': 0,
            'anomalies_detected': 0
        }

        # Forensic Event IDs to track
        self.forensic_event_ids = {
            # Security Log
            4624: 'Successful Logon',
            4625: 'Failed Logon',
            4634: 'Logoff',
            4648: 'Explicit Credentials Logon',
            4672: 'Special Privileges Assigned',
            4720: 'User Account Created',
            4722: 'User Account Enabled',
            4732: 'User Added to Security Group',
            4756: 'User Added to Universal Security Group',
            4776: 'Domain Controller Authentication',

            # System Log
            7045: 'Service Installed',
            7040: 'Service Start Type Changed',
            6005: 'Event Log Service Started',
            6006: 'Event Log Service Stopped',
            1074: 'System Shutdown/Restart',
            20001: 'USB Device Plugged In',
            20003: 'USB Device Removed',
            6416: 'External Device Recognized',

            # PowerShell
            4103: 'PowerShell Module Logging',
            4104: 'PowerShell Script Block Logging',
            400: 'PowerShell Engine Started',
            403: 'PowerShell Engine Stopped',

            # RDP
            1149: 'Remote Desktop Connection',
            21: 'Remote Desktop Services: Session Logon',
            22: 'Remote Desktop Services: Shell Start',
            24: 'Remote Desktop Services: Session Disconnect',
            25: 'Remote Desktop Services: Session Reconnection',

            # Application
            1000: 'Application Error',
            1001: 'Application Hang'
        }

        # Suspicious PowerShell indicators
        self.suspicious_ps_patterns = [
            r'invoke-expression',
            r'iex\s',
            r'downloadstring',
            r'downloadfile',
            r'invoke-webrequest',
            r'invoke-restmethod',
            r'net\.webclient',
            r'bitstransfer',
            r'bypass',
            r'-enc\s',
            r'-encodedcommand',
            r'frombase64',
            r'invoke-mimikatz',
            r'invoke-shellcode',
            r'invoke-wmimethod',
            r'get-process.*\|\s*stop-process',
            r'remove-item.*-recurse.*-force',
            r'hidden'
        ]

    def analyze_event_logs(self, days_back=7, max_events_per_log=5000):
        """
        Analyze Windows Event Logs

        Args:
            days_back: Number of days to look back (default 7)
            max_events_per_log: Maximum events to retrieve per log (default 5000)
        """
        if not self.is_windows:
            print("    ⚠️  Not running on Windows - event log analysis not available")
            print("    💡 Use Windows Event Viewer or dedicated tools for offline analysis")
            return self.events

        try:
            import win32evtlog
            import win32evtlogutil
            import win32con

            print(f"[+] 📊 Analyzing Windows Event Logs (Last {days_back} days)...")

            # Calculate cutoff time
            cutoff_time = datetime.now() - timedelta(days=days_back)

            # Analyze Security Log
            self._analyze_security_log(win32evtlog, cutoff_time, max_events_per_log)

            # Analyze System Log
            self._analyze_system_log(win32evtlog, cutoff_time, max_events_per_log)

            # Analyze Application Log
            self._analyze_application_log(win32evtlog, cutoff_time, max_events_per_log)

            # Analyze PowerShell Logs
            self._analyze_powershell_log(win32evtlog, cutoff_time, max_events_per_log)

            # Perform anomaly detection
            self._detect_anomalies()

            print(f"    ✅ Event log analysis complete")

        except ImportError:
            print("    ⚠️  win32evtlog module not available")
            print("    💡 Install: pip install pywin32")
        except Exception as e:
            print(f"    ⚠️  Event log analysis error: {str(e)}")

        return self.events

    def _analyze_security_log(self, win32evtlog, cutoff_time, max_events):
        """Analyze Security event log"""
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            events_read = 0
            while events_read < max_events:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break

                for event in events:
                    # Check event time
                    event_time = event.TimeGenerated
                    if event_time < cutoff_time:
                        break

                    event_id = event.EventID & 0xFFFF  # Mask to get actual ID

                    # Track forensically relevant events
                    if event_id in self.forensic_event_ids:
                        event_data = {
                            'timestamp': str(event_time),
                            'event_id': event_id,
                            'event_type': self.forensic_event_ids[event_id],
                            'source': event.SourceName,
                            'category': event.EventCategory,
                            'computer': event.ComputerName,
                            'sid': event.Sid,
                            'strings': event.StringInserts if event.StringInserts else []
                        }

                        self.events['security'].append(event_data)
                        self.stats['security_events'] += 1

                        # Track specific event types
                        if event_id == 4624:
                            self.stats['successful_logons'] += 1
                        elif event_id == 4625:
                            self.stats['failed_logons'] += 1

                    events_read += 1

                if events_read >= max_events:
                    break

            win32evtlog.CloseEventLog(hand)
            print(f"    └─ Security Log: {len(self.events['security'])} events")

        except Exception as e:
            print(f"    └─ Security Log: Error - {str(e)}")

    def _analyze_system_log(self, win32evtlog, cutoff_time, max_events):
        """Analyze System event log"""
        try:
            hand = win32evtlog.OpenEventLog(None, "System")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            events_read = 0
            while events_read < max_events:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break

                for event in events:
                    event_time = event.TimeGenerated
                    if event_time < cutoff_time:
                        break

                    event_id = event.EventID & 0xFFFF

                    if event_id in self.forensic_event_ids:
                        event_data = {
                            'timestamp': str(event_time),
                            'event_id': event_id,
                            'event_type': self.forensic_event_ids[event_id],
                            'source': event.SourceName,
                            'computer': event.ComputerName,
                            'strings': event.StringInserts if event.StringInserts else []
                        }

                        self.events['system'].append(event_data)
                        self.stats['system_events'] += 1

                        # Track service installations
                        if event_id == 7045:
                            self.stats['service_installations'] += 1

                    events_read += 1

                if events_read >= max_events:
                    break

            win32evtlog.CloseEventLog(hand)
            print(f"    └─ System Log: {len(self.events['system'])} events")

        except Exception as e:
            print(f"    └─ System Log: Error - {str(e)}")

    def _analyze_application_log(self, win32evtlog, cutoff_time, max_events):
        """Analyze Application event log"""
        try:
            hand = win32evtlog.OpenEventLog(None, "Application")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            events_read = 0
            while events_read < max_events:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break

                for event in events:
                    event_time = event.TimeGenerated
                    if event_time < cutoff_time:
                        break

                    event_id = event.EventID & 0xFFFF

                    if event_id in self.forensic_event_ids:
                        event_data = {
                            'timestamp': str(event_time),
                            'event_id': event_id,
                            'event_type': self.forensic_event_ids[event_id],
                            'source': event.SourceName,
                            'computer': event.ComputerName,
                            'strings': event.StringInserts if event.StringInserts else []
                        }

                        self.events['application'].append(event_data)
                        self.stats['application_events'] += 1

                    events_read += 1

                if events_read >= max_events:
                    break

            win32evtlog.CloseEventLog(hand)
            print(f"    └─ Application Log: {len(self.events['application'])} events")

        except Exception as e:
            print(f"    └─ Application Log: Error - {str(e)}")

    def _analyze_powershell_log(self, win32evtlog, cutoff_time, max_events):
        """Analyze PowerShell Operational log"""
        try:
            # PowerShell Operational log path
            hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-PowerShell/Operational")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            events_read = 0
            while events_read < max_events:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break

                for event in events:
                    event_time = event.TimeGenerated
                    if event_time < cutoff_time:
                        break

                    event_id = event.EventID & 0xFFFF

                    if event_id in self.forensic_event_ids:
                        # Extract script block text for analysis
                        script_text = ""
                        if event.StringInserts:
                            script_text = " ".join([str(s) for s in event.StringInserts if s])

                        event_data = {
                            'timestamp': str(event_time),
                            'event_id': event_id,
                            'event_type': self.forensic_event_ids[event_id],
                            'source': event.SourceName,
                            'computer': event.ComputerName,
                            'script': script_text[:1000],  # Limit script length
                            'strings': event.StringInserts if event.StringInserts else []
                        }

                        self.events['powershell'].append(event_data)
                        self.stats['powershell_events'] += 1

                    events_read += 1

                if events_read >= max_events:
                    break

            win32evtlog.CloseEventLog(hand)
            print(f"    └─ PowerShell Log: {len(self.events['powershell'])} events")

        except Exception as e:
            print(f"    └─ PowerShell Log: Error - {str(e)}")

    def _detect_anomalies(self):
        """Detect anomalies in collected events"""
        print(f"    🔍 Detecting anomalies...")

        # Detect brute force attempts
        self._detect_brute_force()

        # Detect suspicious PowerShell
        self._detect_suspicious_powershell()

        # Detect unusual logon times
        self._detect_unusual_logons()

        # Detect suspicious services
        self._detect_suspicious_services()

        # Detect remote access patterns
        self._detect_remote_access()

        # Detect privilege escalation
        self._detect_privilege_escalation()

        # Detect USB activity
        self._detect_usb_activity()

        # Update anomaly count
        self.stats['anomalies_detected'] = sum([
            len(self.anomalies['brute_force']),
            len(self.anomalies['suspicious_powershell']),
            len(self.anomalies['unusual_logons']),
            len(self.anomalies['suspicious_services']),
            len(self.anomalies['remote_access']),
            len(self.anomalies['privilege_escalation']),
            len(self.anomalies['usb_activity'])
        ])

        print(f"    └─ Anomalies: {self.stats['anomalies_detected']} detected")

    def _detect_brute_force(self):
        """Detect brute force login attempts (multiple failed logins)"""
        # Group failed logons by username and IP
        failed_logons = [e for e in self.events['security'] if e['event_id'] == 4625]

        # Count failures per user/IP within 5-minute windows
        time_windows = defaultdict(lambda: defaultdict(int))

        for event in failed_logons:
            timestamp = datetime.strptime(event['timestamp'].split('.')[0], '%Y-%m-%d %H:%M:%S')
            window = timestamp.replace(minute=(timestamp.minute // 5) * 5, second=0, microsecond=0)

            # Extract username (usually in strings[5])
            username = event['strings'][5] if len(event['strings']) > 5 else 'Unknown'

            time_windows[str(window)][username] += 1

        # Flag windows with >5 failures
        for window, users in time_windows.items():
            for username, count in users.items():
                if count > 5:
                    self.anomalies['brute_force'].append({
                        'timestamp': window,
                        'username': username,
                        'attempts': count,
                        'severity': 'HIGH' if count > 10 else 'MEDIUM'
                    })

    def _detect_suspicious_powershell(self):
        """Detect suspicious PowerShell commands"""
        for event in self.events['powershell']:
            script = event.get('script', '').lower()

            # Check for suspicious patterns
            matches = []
            for pattern in self.suspicious_ps_patterns:
                if re.search(pattern, script, re.IGNORECASE):
                    matches.append(pattern)

            if matches:
                self.anomalies['suspicious_powershell'].append({
                    'timestamp': event['timestamp'],
                    'event_id': event['event_id'],
                    'script_preview': script[:200],
                    'indicators': matches,
                    'severity': 'HIGH' if len(matches) > 2 else 'MEDIUM'
                })

    def _detect_unusual_logons(self):
        """Detect logons at unusual times (night/early morning)"""
        for event in self.events['security']:
            if event['event_id'] == 4624:
                timestamp = datetime.strptime(event['timestamp'].split('.')[0], '%Y-%m-%d %H:%M:%S')
                hour = timestamp.hour

                # Flag logons between 11 PM and 6 AM
                if hour >= 23 or hour <= 6:
                    username = event['strings'][5] if len(event['strings']) > 5 else 'Unknown'

                    self.anomalies['unusual_logons'].append({
                        'timestamp': event['timestamp'],
                        'username': username,
                        'hour': hour,
                        'severity': 'MEDIUM'
                    })

    def _detect_suspicious_services(self):
        """Detect suspicious service installations"""
        suspicious_service_paths = [
            'temp',
            'appdata',
            'programdata',
            'users\\public',
            'windows\\temp',
            'perflogs'
        ]

        for event in self.events['system']:
            if event['event_id'] == 7045:
                # Service path usually in strings[1]
                service_path = event['strings'][1].lower() if len(event['strings']) > 1 else ''
                service_name = event['strings'][0] if len(event['strings']) > 0 else 'Unknown'

                # Check for suspicious paths
                if any(sus_path in service_path for sus_path in suspicious_service_paths):
                    self.anomalies['suspicious_services'].append({
                        'timestamp': event['timestamp'],
                        'service_name': service_name,
                        'service_path': service_path,
                        'severity': 'HIGH'
                    })

    def _detect_remote_access(self):
        """Detect RDP and remote access activity"""
        rdp_events = [1149, 21, 22, 24, 25]

        for event in self.events['security']:
            if event['event_id'] in rdp_events:
                self.anomalies['remote_access'].append({
                    'timestamp': event['timestamp'],
                    'event_type': self.forensic_event_ids.get(event['event_id'], 'Remote Access'),
                    'source_ip': event['strings'][2] if len(event['strings']) > 2 else 'Unknown',
                    'severity': 'MEDIUM'
                })

    def _detect_privilege_escalation(self):
        """Detect privilege escalation attempts"""
        for event in self.events['security']:
            if event['event_id'] in [4672, 4720, 4732]:
                username = event['strings'][1] if len(event['strings']) > 1 else 'Unknown'

                self.anomalies['privilege_escalation'].append({
                    'timestamp': event['timestamp'],
                    'event_type': self.forensic_event_ids[event['event_id']],
                    'username': username,
                    'severity': 'HIGH'
                })

    def _detect_usb_activity(self):
        """Detect USB device activity"""
        usb_events = [20001, 20003, 6416]

        for event in self.events['system']:
            if event['event_id'] in usb_events:
                device_name = event['strings'][0] if event['strings'] else 'Unknown'

                self.anomalies['usb_activity'].append({
                    'timestamp': event['timestamp'],
                    'event_type': self.forensic_event_ids[event['event_id']],
                    'device': device_name,
                    'severity': 'MEDIUM'
                })

    def generate_timeline(self):
        """Generate unified timeline of all events"""
        timeline = []

        # Combine all events
        for log_type, events in self.events.items():
            for event in events:
                timeline.append({
                    'timestamp': event['timestamp'],
                    'log_type': log_type,
                    'event_id': event['event_id'],
                    'event_type': event['event_type'],
                    'details': event
                })

        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'], reverse=True)

        return timeline

    def get_statistics(self):
        """Generate statistics about event log analysis"""
        self.stats['total_events'] = sum([
            self.stats['security_events'],
            self.stats['system_events'],
            self.stats['application_events'],
            self.stats['powershell_events']
        ])

        return self.stats

    def generate_report_data(self):
        """Generate report data for HTML generator"""
        return {
            'events': self.events,
            'anomalies': self.anomalies,
            'statistics': self.get_statistics(),
            'timeline': self.generate_timeline()[:500],  # Limit to 500 most recent
            'is_windows': self.is_windows
        }


# Standalone test
if __name__ == "__main__":
    print("="*70)
    print("EVENT LOG ANALYZER - STANDALONE TEST")
    print("="*70)

    analyzer = EventLogAnalyzer()

    if analyzer.is_windows:
        analyzer.analyze_event_logs(days_back=7, max_events_per_log=1000)
        stats = analyzer.get_statistics()

        print("\n" + "="*70)
        print("EVENT LOG ANALYSIS SUMMARY")
        print("="*70)
        print(f"Total Events: {stats['total_events']}")
        print(f"  Security Events: {stats['security_events']}")
        print(f"  System Events: {stats['system_events']}")
        print(f"  Application Events: {stats['application_events']}")
        print(f"  PowerShell Events: {stats['powershell_events']}")
        print(f"\nForensic Findings:")
        print(f"  Successful Logons: {stats['successful_logons']}")
        print(f"  Failed Logons: {stats['failed_logons']}")
        print(f"  Service Installations: {stats['service_installations']}")
        print(f"  Anomalies Detected: {stats['anomalies_detected']}")
    else:
        print("\n⚠️  Not running on Windows - event log analysis requires Windows OS")
