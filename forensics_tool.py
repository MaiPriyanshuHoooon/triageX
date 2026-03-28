"""
Cross-Platform Forensics Tool - Modular Version
=================================================

Main entry point for the forensic data collection tool.
Supports Windows, Linux, and macOS with automatic OS detection.

This version uses a modular structure with separated components:
- config/commands.py: Command definitions (Windows, Linux, macOS)
- core/os_detector.py: OS detection and privilege checking
- core/executor.py: Cross-platform command execution
- core/parsers.py: Output parsing and table generation
- templates/html_generator.py: HTML template generation
- assets/styles.css: Stylesheet
- assets/script.js: JavaScript functions

Author: Forensics Tool Team
Date: November 2025
"""

import os
import sys
from datetime import datetime

from config.commands import COMMANDS, COMMAND_DESCRIPTIONS, LINUX_COMMANDS, MACOS_COMMANDS, WINDOWS_COMMANDS, get_commands_for_os
from core.os_detector import detect_os, is_admin, run_as_admin, is_windows, is_linux, is_macos, get_os_info, get_shell_type, OS_WINDOWS, OS_LINUX, OS_MACOS
from core.executor import execute
from core.parsers import parse_to_table, escape_html, parse_regex_analysis_output, parse_hash_analysis_output
from templates.html_generator import (
    generate_html_header,
    generate_html_footer,
    generate_threat_dashboard,
    generate_dashboard_tab,
    generate_activity_items,
    generate_os_commands_tab,
    generate_os_command_sections,
    generate_hash_tab_interactive,
    generate_ioc_scanner_tab,
    generate_pii_tab,
    generate_encrypted_files_tab
)
from templates.browser_history_tab import generate_browser_history_tab
from templates.registry_tab import generate_registry_tab
from templates.eventlog_tab import generate_eventlog_tab
from templates.mft_tab import generate_mft_tab
from templates.pagefile_tab import generate_pagefile_tab
from core.regex_analyzer import RegexAnalyzer
from core.hash_analyzer import HashAnalyzer
from core.file_scanner import FileScanner
from core.ioc_scanner import IOCScanner
from core.encrypted_file_scanner import EncryptedFileScanner
from core.browser_analyzer import BrowserHistoryAnalyzer
from core.registry_analyzer import RegistryAnalyzer
from core.eventlog_analyzer import EventLogAnalyzer
from core.mft_analyzer import MFTAnalyzer
from core.pagefile_analyzer import PagefileAnalyzer


def build_os_command_display(commands_dict, descriptions_dict, os_name="Linux"):
    """
    Build command display data for HTML report (without executing commands).
    This creates the display structure showing what commands would run on each OS.

    Args:
        commands_dict: Dictionary of commands organized by category (e.g., LINUX_COMMANDS)
        descriptions_dict: Dictionary of command descriptions (COMMAND_DESCRIPTIONS)
        os_name: Name of the OS for display purposes

    Returns:
        Dictionary organized by category with command display data
    """
    os_results = {}

    for category, cmds in commands_dict.items():
        # Skip analysis categories
        if category in ['regex_analysis', 'hash_analysis']:
            continue

        os_results[category] = []

        for cmd in cmds:
            # Get user-friendly description or use a truncated command
            cmd_description = descriptions_dict.get(cmd, cmd[:100] if len(cmd) > 100 else cmd)

            # Create display-only output (command reference, not execution)
            cmd_preview = cmd[:200] + "..." if len(cmd) > 200 else cmd
            output_html = f'''
            <div class="command-reference">
                <div class="command-info">
                    <strong>Command:</strong>
                    <pre class="command-code">{cmd_preview}</pre>
                </div>
                <div class="command-note">
                    <em>This command would be executed on a {os_name} system.</em>
                </div>
            </div>
            '''

            # Determine shell type based on command
            if os_name == "Linux":
                shell_type = "BASH"
            elif os_name == "macOS":
                shell_type = "ZSH"
            else:
                shell_type = "CMD"

            os_results[category].append({
                'description': cmd_description,
                'output': output_html,
                'type': shell_type,
                'success': True
            })

    return os_results


class ForensicCollector:
    """
    Forensic data collection class for GUI integration.
    Wraps the forensic collection functionality into a reusable class.
    Cross-platform: auto-detects OS and runs appropriate commands.
    """

    def __init__(self, output_dir):
        """
        Initialize the forensic collector.

        Args:
            output_dir (str): Directory to store forensic output and reports
        """
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        # Detect OS at init time
        self.current_os = detect_os()
        self.os_info = get_os_info()
        self.shell_type = get_shell_type()

        # Get the correct command set for this OS
        self.commands, self.os_name = get_commands_for_os(self.current_os)

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Initialize analyzers
        self.regex_analyzer = RegexAnalyzer()
        self.hash_analyzer = HashAnalyzer()
        self.ioc_scanner = IOCScanner()
        self.browser_analyzer = BrowserHistoryAnalyzer()
        self.eventlog_analyzer = EventLogAnalyzer()

        # Storage for collected data
        self.all_forensic_data = []
        self.os_results = {}
        self.activity_log = []

    def execute_all_commands(self):
        """
        Execute all forensic commands for the detected OS and collect results.

        Returns:
            dict: Dictionary of command results organized by category
        """
        # Use OS-specific commands (auto-detected in __init__)
        commands_to_run = self.commands

        # Collect command results organized by category
        for category, cmds in commands_to_run.items():
            # Skip analysis categories - we'll process them separately
            if category in ['regex_analysis', 'hash_analysis']:
                continue

            self.os_results[category] = []

            # Process each command in the category
            for cmd in cmds:
                # Auto-detect and execute
                output, cmd_type = execute(cmd)

                # Collect data for regex analysis
                if output and output.strip() and not output.startswith("❌"):
                    self.all_forensic_data.append(f"\n=== {category.upper()} - {cmd[:80]} ===\n{output}\n")

                # Get user-friendly description or fallback to command
                cmd_description = COMMAND_DESCRIPTIONS.get(cmd, cmd[:100])

                # Parse output to HTML table
                if output and output.strip():
                    table_html = parse_to_table(output, cmd)
                else:
                    table_html = '<p class="empty-output">No output or command failed</p>'

                # Map command type to display label
                type_labels = {
                    'powershell': 'PS', 'cmd': 'CMD',
                    'bash': 'BASH', 'zsh': 'ZSH'
                }

                # Store result
                self.os_results[category].append({
                    'description': cmd_description,
                    'output': table_html,
                    'type': type_labels.get(cmd_type, self.shell_type),
                    'success': bool(output and output.strip() and not output.startswith("❌"))
                })

        # Perform Regex Analysis
        combined_forensic_text = "\n".join(self.all_forensic_data)
        regex_results = self.regex_analyzer.analyze_text(combined_forensic_text)

        # Add to activity log
        self.activity_log.append({
            'type': 'regex analysis',
            'matches': len(regex_results['iocs'])
        })

        # Perform Hash Analysis
        file_hashes = []
        evidence_dirs = self.hash_analyzer.get_common_evidence_directories()

        if evidence_dirs:
            file_hashes = self.hash_analyzer.scan_multiple_directories(
                evidence_dirs,
                max_files_per_dir=30,
                extensions=None
            )
        else:
            # Fallback to current directory
            current_dir = os.path.dirname(os.path.abspath(__file__))
            file_hashes = self.hash_analyzer.scan_evidence_directory(
                current_dir,
                max_files=20,
                extensions=['.py', '.txt', '.log', '.json']
            )

        # Add to activity log
        self.activity_log.append({
            'type': 'hash analysis',
            'matches': len(file_hashes) if file_hashes else 0
        })

        # Store results for report generation
        self.file_hashes = file_hashes
        self.regex_results = regex_results

        return self.os_results

    def scan_iocs(self):
        """
        Perform IOC (Indicators of Compromise) scanning.

        Returns:
            dict: IOC scan results with threat assessment

        Note: This method should be called after execute_all_commands() to scan collected data.
        """
        # Perform IOC Scan Analysis
        if not self.all_forensic_data:
            print("⚠️  Warning: No forensic data collected yet. Call execute_all_commands() first.")

        combined_forensic_text = "\n".join(self.all_forensic_data)
        ioc_results = self.ioc_scanner.scan_text(combined_forensic_text)

        # Add to activity log
        self.activity_log.append({
            'type': 'ioc scan analysis',
            'matches': ioc_results['total_iocs']
        })

        # Store for report
        self.ioc_results = ioc_results

        return ioc_results

    def analyze_browser_history(self):
        """
        Analyze browser history from all detected browsers.

        Returns:
            dict: Browser history data organized by browser
        """
        browser_history = {}

        try:
            # Get 1 YEAR of history with NO LIMIT on entries
            browser_history = self.browser_analyzer.analyze_all_browsers(
                limit=None,      # No limit - get ALL entries
                days_back=365    # Last 1 year
            )
            browser_stats = self.browser_analyzer.get_statistics(browser_history)

            # Add to activity log
            self.activity_log.append({
                'type': 'browser history',
                'matches': browser_stats.get('total_entries', 0)
            })

            # Store for report
            self.browser_history = browser_history
            self.browser_stats = browser_stats

        except Exception as e:
            # Log error and return empty structure
            print(f"⚠️  Browser history analysis error: {str(e)}")
            self.browser_history = {}
            self.browser_stats = {}

        return browser_history

    def analyze_event_logs(self):
        """
        Analyze Windows event logs for security events.

        Returns:
            dict: Event log analysis data
        """
        eventlog_data = {}

        try:
            # Analyze Windows event logs (last 7 days)
            events = self.eventlog_analyzer.analyze_event_logs(days_back=7, max_events_per_log=5000)
            eventlog_stats = self.eventlog_analyzer.get_statistics()
            eventlog_data = self.eventlog_analyzer.generate_report_data()

            # Add to activity log
            self.activity_log.append({
                'type': 'event log analysis',
                'matches': eventlog_stats.get('total_events', 0)
            })

            # Store for report
            self.eventlog_data = eventlog_data
            self.eventlog_stats = eventlog_stats

        except Exception as e:
            # Log error and return empty structure
            print(f"⚠️  Event log analysis error: {str(e)}")
            self.eventlog_data = self.eventlog_analyzer.generate_report_data()
            self.eventlog_stats = self.eventlog_analyzer.get_statistics()

        return eventlog_data

    def generate_html_report(self, results, ioc_results, browser_results, eventlog_results):
        """
        Generate comprehensive HTML forensic report.

        Args:
            results (dict): Command execution results
            ioc_results (dict): IOC scan results
            browser_results (dict): Browser history analysis
            eventlog_results (dict): Event log analysis

        Returns:
            str: Path to generated HTML report
        """
        html_file = os.path.join(self.output_dir, f"forensic_report_{self.timestamp}.html")

        # Ensure we have all required data - set defaults if methods weren't called
        if not hasattr(self, 'file_hashes'):
            print("⚠️  Warning: execute_all_commands() not called. Using empty hash results.")
            self.file_hashes = []
        if not hasattr(self, 'regex_results'):
            print("⚠️  Warning: Regex analysis not performed. Using empty results.")
            self.regex_results = {'iocs': [], 'threat_score': 0, 'threat_level': 'LOW', 'suspicious_patterns': {}}
        if not hasattr(self, 'browser_stats'):
            self.browser_stats = {}
        if not hasattr(self, 'eventlog_stats'):
            self.eventlog_stats = {}

        # Perform additional analyses for comprehensive report
        # PII Detection
        pii_scanner = FileScanner()
        pii_results = []
        try:
            from pathlib import Path
            scan_dirs = []
            for dir_name in ['Downloads', 'Desktop', 'Documents']:
                dir_path = str(Path.home() / dir_name)
                if os.path.exists(dir_path):
                    scan_dirs.append(dir_path)

            if scan_dirs:
                pii_results = pii_scanner.scan_specific_directories(scan_dirs, max_files_per_dir=25)
        except Exception:
            pass

        # Encrypted Files Detection
        encrypted_scanner = EncryptedFileScanner()
        encrypted_data = {}
        try:
            encrypted_files = encrypted_scanner.scan_user_directories(max_files_per_dir=250)
            encrypted_data = encrypted_scanner.generate_report_data()
        except Exception:
            encrypted_data = encrypted_scanner.generate_report_data()

        # Registry Analysis
        registry_analyzer = RegistryAnalyzer()
        registry_data = {}
        registry_stats = {}
        try:
            artifacts = registry_analyzer.analyze_live_registry()
            registry_stats = registry_analyzer.get_statistics()
            registry_data = registry_analyzer.generate_report_data()
        except Exception:
            registry_data = registry_analyzer.generate_report_data()
            registry_stats = registry_analyzer.get_statistics()

        # MFT Analysis
        mft_analyzer = MFTAnalyzer(volume_path="C:", scan_all_volumes=True)
        mft_data = {}
        mft_stats = {}
        try:
            mft_data = mft_analyzer.analyze()
            mft_stats = mft_analyzer.get_statistics()
        except Exception:
            mft_data = mft_analyzer._get_unavailable_data()
            mft_stats = mft_analyzer.get_statistics()

        # Pagefile Analysis
        pagefile_analyzer = PagefileAnalyzer()
        pagefile_data = {}
        try:
            pagefile_data = pagefile_analyzer.analyze()
        except Exception:
            pagefile_data = pagefile_analyzer._get_unavailable_data()

        # Generate HTML report
        assets_path = ""  # Embedded inline

        with open(html_file, "w", encoding="utf-8") as f:
            # Write HTML header with detected OS type
            f.write(generate_html_header(self.timestamp, assets_path, os_type=self.current_os))

            # Generate Dashboard Tab
            # Calculate actual statistics from collected data
            file_hashes = getattr(self, 'file_hashes', [])
            total_evidence = len(self.os_results) + len(file_hashes) + len(browser_results)
            stats = {
                'total_cases': len(self.os_results),  # Number of command categories processed
                'active_cases': len(self.os_results),  # Same as total for live analysis
                'evidence_items': total_evidence,
                'analysis_logs': len(self.activity_log),
                'timestamp': self.timestamp
            }
            f.write(generate_dashboard_tab(stats, self.activity_log, {}))

            # Build command display data for all OSes:
            # - Current OS: real executed results (self.os_results)
            # - Other OSes: reference-only display
            if self.current_os == OS_WINDOWS:
                windows_results = self.os_results
                linux_results = build_os_command_display(LINUX_COMMANDS, COMMAND_DESCRIPTIONS, "Linux")
                macos_results = build_os_command_display(MACOS_COMMANDS, COMMAND_DESCRIPTIONS, "macOS")
            elif self.current_os == OS_LINUX:
                windows_results = build_os_command_display(WINDOWS_COMMANDS, COMMAND_DESCRIPTIONS, "Windows")
                linux_results = self.os_results
                macos_results = build_os_command_display(MACOS_COMMANDS, COMMAND_DESCRIPTIONS, "macOS")
            elif self.current_os == OS_MACOS:
                windows_results = build_os_command_display(WINDOWS_COMMANDS, COMMAND_DESCRIPTIONS, "Windows")
                linux_results = build_os_command_display(LINUX_COMMANDS, COMMAND_DESCRIPTIONS, "Linux")
                macos_results = self.os_results
            else:
                windows_results = self.os_results
                linux_results = build_os_command_display(LINUX_COMMANDS, COMMAND_DESCRIPTIONS, "Linux")
                macos_results = build_os_command_display(MACOS_COMMANDS, COMMAND_DESCRIPTIONS, "macOS")

            # Generate OS Commands Tab — auto-highlights current OS
            f.write(generate_os_commands_tab(
                windows_results,
                self.current_os,
                linux_results=linux_results,
                macos_results=macos_results
            ))

            # Generate Hash Analysis Tab
            f.write(generate_hash_tab_interactive(file_hashes))

            # Generate PII Detection Tab
            f.write(generate_pii_tab(pii_results))

            # Generate Browser History Tab
            browser_stats = getattr(self, 'browser_stats', {})
            f.write(generate_browser_history_tab(browser_results, browser_stats))

            # Generate Registry Analysis Tab
            f.write(generate_registry_tab(registry_data, registry_stats))

            # Generate Event Log Analysis Tab
            eventlog_stats = getattr(self, 'eventlog_stats', {})
            f.write(generate_eventlog_tab(eventlog_results, eventlog_stats))

            # Generate MFT Analysis Tab
            f.write(generate_mft_tab(mft_data, mft_stats))

            # Generate Pagefile Analysis Tab
            f.write(generate_pagefile_tab(pagefile_data))

            # Generate Encrypted Files Tab
            f.write(generate_encrypted_files_tab(encrypted_data))

            # Generate Regex Analysis Tab
            f.write(f'    <div id="tab-regex" class="tab-content">\n')
            f.write(f'        <div class="tab-header">\n')
            f.write(f'            <h1>Regex Pattern Analysis</h1>\n')
            f.write(f'        </div>\n')
            f.write(f'        <div class="card">\n')

            # Generate threat dashboard if critical threats found
            if self.regex_results['threat_score'] > 50:
                threat_data = {
                    'threat_level': self.regex_results['threat_level'],
                    'threat_score': self.regex_results['threat_score'],
                    'total_iocs': len(self.regex_results['iocs']),
                    'critical_findings': len(self.regex_results['suspicious_patterns'].get('CREDENTIALS', [])) +
                                       len(self.regex_results['suspicious_patterns'].get('MALWARE', [])),
                    'total_commands': len(self.all_forensic_data),
                    'files_hashed': len(self.file_hashes) if self.file_hashes else 0
                }
                f.write(generate_threat_dashboard(threat_data))

            regex_html = self.regex_analyzer.generate_report(self.regex_results)
            f.write(regex_html)
            f.write(f'        </div>\n')
            f.write(f'    </div>\n\n')

            # Generate IOC Scanner Tab
            f.write(generate_ioc_scanner_tab(ioc_results))

            # Write HTML footer
            f.write(generate_html_footer(assets_path))

        return html_file


def run_forensic_collection():
    """Main function to collect forensic data and generate HTML report — cross-platform"""

    # Detect OS
    current_os = detect_os()
    os_info = get_os_info()
    shell_type = get_shell_type()
    native_commands, os_name = get_commands_for_os(current_os)

    print(f"🖥️  Detected OS: {current_os}")
    print(f"🐚 Shell type: {shell_type}")

    # Check admin/root status (cross-platform)
    if is_admin():
        print("✅ Running with elevated privileges")
    else:
        print("⚠️  WARNING: Not running with elevated privileges")
        if is_windows():
            print("   Run as Administrator for full forensic data.")
        else:
            print(f"   Run with: sudo python3 {sys.argv[0]}")
        print("   Some commands may fail or produce incomplete results.\n")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    html_file = f"forensic_report_{timestamp}.html"

    print(f"\n📊 Generating HTML forensic report...")
    print(f"📁 Saving to: {html_file}")
    print(f"🤖 Auto-detecting command types...\n")

    # Assets are embedded inline - no external files needed
    assets_path = ""  # Not used anymore, kept for compatibility

    # Initialize analyzers and data collectors
    regex_analyzer = RegexAnalyzer()
    hash_analyzer = HashAnalyzer()
    ioc_scanner = IOCScanner()
    all_forensic_data = []  # Collect all output for regex analysis

    # Collect command results organized by category for the new UI
    os_results = {}
    activity_log = []

    # Execute commands for the DETECTED OS
    for category, cmds in native_commands.items():
        # Skip analysis categories - we'll process them separately
        if category in ['regex_analysis', 'hash_analysis']:
            continue

        print(f"[+] Collecting {category} information...")
        os_results[category] = []

        # Process each command in the category
        for idx, cmd in enumerate(cmds):
            # Auto-detect and execute
            output, cmd_type = execute(cmd)

            # Collect data for regex analysis
            if output and output.strip() and not output.startswith("❌"):
                all_forensic_data.append(f"\n=== {category.upper()} - {cmd[:80]} ===\n{output}\n")

            # Display detected type
            print(f"    └─ Detected: {cmd_type.upper()} - {cmd[:50]}...")

            # Get user-friendly description or fallback to command
            cmd_description = COMMAND_DESCRIPTIONS.get(cmd, cmd[:100])

            # Parse output to HTML table
            if output and output.strip():
                table_html = parse_to_table(output, cmd)
            else:
                table_html = '<p class="empty-output">No output or command failed</p>'

            # Map command type to display label
            type_labels = {
                'powershell': 'PS', 'cmd': 'CMD',
                'bash': 'BASH', 'zsh': 'ZSH'
            }

            # Store result for new UI
            os_results[category].append({
                'description': cmd_description,
                'output': table_html,
                'type': type_labels.get(cmd_type, shell_type),
                'success': bool(output and output.strip() and not output.startswith("❌"))
            })

    # Perform Regex Analysis
    print(f"\n[+] 🔍 Performing Regex Analysis on collected data...")
    combined_forensic_text = "\n".join(all_forensic_data)
    regex_results = regex_analyzer.analyze_text(combined_forensic_text)

    print(f"    ✅ Found {len(regex_results['iocs'])} IOCs")
    print(f"    ⚠️  Threat Level: {regex_results['threat_level']} (Score: {regex_results['threat_score']})")

    # Add to activity log
    activity_log.append({
        'type': 'regex analysis',
        'matches': len(regex_results['iocs'])
    })

    # Perform Hash Analysis (OS-agnostic)
    print(f"\n[+] 🔐 Performing Hash Analysis...")
    file_hashes = []
    evidence_dirs = hash_analyzer.get_common_evidence_directories()

    if evidence_dirs:
        print(f"    └─ Detected {len(evidence_dirs)} evidence directories on {sys.platform}")
        file_hashes = hash_analyzer.scan_multiple_directories(
            evidence_dirs,
            max_files_per_dir=30,
            extensions=None
        )

        for dir_path in hash_analyzer.scanned_paths:
            print(f"    └─ Scanned: {dir_path}")

        valid_hashes = [f for f in file_hashes if not f.get('error') and not f.get('info')]
        print(f"    ✅ Analyzed {len(valid_hashes)} files")

        if hash_analyzer.malware_detections:
            print(f"    🚨 MALWARE DETECTED: {len(hash_analyzer.malware_detections)} known malicious files!")
        if hash_analyzer.suspicious_files:
            print(f"    ⚠️  Suspicious files: {len(hash_analyzer.suspicious_files)}")
    else:
        print(f"    ⚠️  No standard evidence directories found")
        print(f"    └─ Scanning current directory as example...")
        current_dir = os.path.dirname(os.path.abspath(__file__))
        file_hashes = hash_analyzer.scan_evidence_directory(
            current_dir,
            max_files=20,
            extensions=['.py', '.txt', '.log', '.json']
        )
        valid_hashes = [f for f in file_hashes if not f.get('error') and not f.get('info')]
        print(f"    ✅ Analyzed {len(valid_hashes)} files (demo mode)")

    # Add to activity log
    activity_log.append({
        'type': 'hash analysis',
        'matches': len(file_hashes) if file_hashes else 0
    })

    # Perform PII Detection Scan
    print(f"\n[+] 🔍 Performing PII Detection Analysis...")
    pii_scanner = FileScanner()
    pii_results = []

    try:
        # Focus on key directories that likely contain PII
        from pathlib import Path
        scan_dirs = []

        # Add Downloads directory (most likely to contain PII documents)
        downloads_path = str(Path.home() / 'Downloads')
        if os.path.exists(downloads_path):
            scan_dirs.append(downloads_path)

        # Add Desktop directory
        desktop_path = str(Path.home() / 'Desktop')
        if os.path.exists(desktop_path):
            scan_dirs.append(desktop_path)

        # Add Documents directory
        documents_path = str(Path.home() / 'Documents')
        if os.path.exists(documents_path):
            scan_dirs.append(documents_path)

        if scan_dirs:
            print(f"    └─ Scanning {len(scan_dirs)} high-value directories for PII")
            pii_results = pii_scanner.scan_specific_directories(scan_dirs, max_files_per_dir=25)

            pii_files = len(pii_results)
            total_pii_items = sum(len(result.get('analysis_results', {}).get('pii_findings', [])) for result in pii_results)
            high_risk_files = len([r for r in pii_results if r.get('analysis_results', {}).get('privacy_risk_score', 0) >= 8])

            print(f"    ✅ Found {pii_files} files containing PII")
            print(f"    📊 Total PII items: {total_pii_items}")
            if high_risk_files > 0:
                print(f"    🚨 High-risk files: {high_risk_files}")
        else:
            print(f"    ⚠️  No standard user directories found for PII scanning")

    except Exception as e:
        print(f"    ❌ PII scanning error: {str(e)}")
        pii_results = []

    # Add to activity log
    activity_log.append({
        'type': 'pii detection',
        'matches': len(pii_results)
    })

    # Perform IOC Scan Analysis
    print(f"\n[+] 🛡️  Performing IOC (Indicators of Compromise) Scan...")
    ioc_results = ioc_scanner.scan_text(combined_forensic_text)

    print(f"    ✅ Threat Level: {ioc_results['threat_level']} (Score: {ioc_results['threat_score']})")
    print(f"    📊 Total IOCs Found: {ioc_results['total_iocs']}")
    print(f"    🔴 Critical: {ioc_results['severity_counts']['CRITICAL']}")
    print(f"    🟠 High: {ioc_results['severity_counts']['HIGH']}")
    print(f"    🟡 Medium: {ioc_results['severity_counts']['MEDIUM']}")
    print(f"    🟢 Low: {ioc_results['severity_counts']['LOW']}")

    if ioc_results['total_iocs'] > 0:
        print(f"    ⚠️  Categories detected: {', '.join(ioc_results['findings_by_category'].keys())}")

    # Add to activity log
    activity_log.append({
        'type': 'ioc scan analysis',
        'matches': ioc_results['total_iocs']
    })

    # IOC scan activity
    activity_log.append({
        'type': 'threat intelligence',
        'matches': 2  # Placeholder
    })

    # Perform Encrypted Files Detection
    print(f"\n[+] 🔐 Performing Encrypted Files Detection...")
    encrypted_scanner = EncryptedFileScanner()
    encrypted_files = []

    try:
        print(f"    └─ Platform: {sys.platform}")
        print(f"    └─ Scanning user directories (excluding system files)...")

        encrypted_files = encrypted_scanner.scan_user_directories(max_files_per_dir=250)

        print(f"    ✅ Scanned {encrypted_scanner.stats['total_scanned']} files")
        print(f"    🔒 Found {encrypted_scanner.stats['encrypted_found']} encrypted files")

        if encrypted_scanner.stats['efs_files'] > 0:
            print(f"    🔐 Windows EFS: {encrypted_scanner.stats['efs_files']}")
        if encrypted_scanner.stats['password_protected'] > 0:
            print(f"    🔑 Password-Protected: {encrypted_scanner.stats['password_protected']}")
        if encrypted_scanner.stats['encrypted_containers'] > 0:
            print(f"    💾 Encrypted Containers: {encrypted_scanner.stats['encrypted_containers']}")
        if encrypted_scanner.stats['filevault_files'] > 0:
            print(f"    🍎 macOS Encrypted: {encrypted_scanner.stats['filevault_files']}")

    except Exception as e:
        print(f"    ❌ Encrypted file scanning error: {str(e)}")

    encrypted_data = encrypted_scanner.generate_report_data()

    # Add to activity log
    activity_log.append({
        'type': 'encrypted file scan',
        'matches': len(encrypted_files)
    })

    # Perform Browser History Analysis
    print(f"\n{'='*70}")
    print(f"🌐 BROWSER HISTORY ANALYSIS")
    print(f"{'='*70}")
    browser_analyzer = BrowserHistoryAnalyzer()
    browser_history = {}
    browser_stats = {}

    try:
        # Get 1 YEAR of history with NO LIMIT on entries
        # This retrieves ALL available history from the past 365 days
        browser_history = browser_analyzer.analyze_all_browsers(
            limit=None,      # No limit - get ALL entries
            days_back=365    # Last 1 year
        )
        browser_stats = browser_analyzer.get_statistics(browser_history)

        print(f"{'='*70}")
        print(f"✅ BROWSER HISTORY SUMMARY:")
        print(f"   Browsers analyzed: {browser_stats['browsers_found']}")
        print(f"   Total entries: {browser_stats['total_entries']}")
        print(f"   Total visits: {browser_stats['total_visits']}")
        print(f"{'='*70}\n")

    except Exception as e:
        print(f"    ❌ Browser history error: {str(e)}")

    # Add to activity log
    activity_log.append({
        'type': 'browser history',
        'matches': browser_stats.get('total_entries', 0)
    })

    # Perform Registry Analysis
    print(f"\n{'='*70}")
    print(f"📋 REGISTRY ANALYSIS")
    print(f"{'='*70}")
    registry_analyzer = RegistryAnalyzer()
    registry_data = {}
    registry_stats = {}

    try:
        # Analyze live Windows registry
        artifacts = registry_analyzer.analyze_live_registry()
        registry_stats = registry_analyzer.get_statistics()
        registry_data = registry_analyzer.generate_report_data()

        print(f"{'='*70}")
        print(f"✅ REGISTRY ANALYSIS SUMMARY:")
        print(f"   Total artifacts: {registry_stats['total_artifacts']}")
        print(f"   UserAssist entries: {registry_stats['userassist_count']}")
        print(f"   Run keys: {registry_stats['run_keys_count']}")
        print(f"   USB devices: {registry_stats['usb_devices_count']}")
        print(f"   Installed programs: {registry_stats['installed_programs_count']}")
        print(f"{'='*70}\n")

    except Exception as e:
        print(f"    ❌ Registry analysis error: {str(e)}")
        # Provide empty data structure if analysis fails
        registry_data = registry_analyzer.generate_report_data()
        registry_stats = registry_analyzer.get_statistics()

    # Add to activity log
    activity_log.append({
        'type': 'registry analysis',
        'matches': registry_stats.get('total_artifacts', 0)
    })

    # Perform Event Log Analysis
    print(f"\n{'='*70}")
    print(f"📊 EVENT LOG ANALYSIS")
    print(f"{'='*70}")
    eventlog_analyzer = EventLogAnalyzer()
    eventlog_data = {}
    eventlog_stats = {}

    try:
        # Analyze Windows event logs (last 7 days)
        events = eventlog_analyzer.analyze_event_logs(days_back=7, max_events_per_log=5000)
        eventlog_stats = eventlog_analyzer.get_statistics()
        eventlog_data = eventlog_analyzer.generate_report_data()

        print(f"{'='*70}")
        print(f"✅ EVENT LOG ANALYSIS SUMMARY:")
        print(f"   Total events: {eventlog_stats['total_events']}")
        print(f"   Security events: {eventlog_stats['security_events']}")
        print(f"   System events: {eventlog_stats['system_events']}")
        print(f"   Successful logons: {eventlog_stats['successful_logons']}")
        print(f"   Failed logons: {eventlog_stats['failed_logons']}")
        print(f"   Anomalies detected: {eventlog_stats['anomalies_detected']}")
        print(f"{'='*70}\n")

    except Exception as e:
        print(f"    ❌ Event log analysis error: {str(e)}")
        # Provide empty data structure if analysis fails
        eventlog_data = eventlog_analyzer.generate_report_data()
        eventlog_stats = eventlog_analyzer.get_statistics()

    # Add to activity log
    activity_log.append({
        'type': 'event log analysis',
        'matches': eventlog_stats.get('total_events', 0)
    })

    # Perform MFT (Master File Table) Analysis
    print(f"\n{'='*70}")
    print(f"💾 MFT ANALYSIS - DELETED FILES & RECOVERY")
    print(f"{'='*70}")
    # ⚠️ CRITICAL: Enable scan_all_volumes=True to detect deleted files across ALL drives
    # This ensures files deleted from D:, E:, etc. are found (not just C: drive)
    mft_analyzer = MFTAnalyzer(volume_path="C:", scan_all_volumes=True)
    mft_data = {}
    mft_stats = {}

    try:
        # Analyze MFT for deleted files and recovery potential
        mft_data = mft_analyzer.analyze()
        mft_stats = mft_analyzer.get_statistics()

        print(f"{'='*70}")
        print(f"✅ MFT ANALYSIS SUMMARY:")
        print(f"   Total MFT entries: {mft_stats['total_entries']:,}")
        print(f"   Active entries: {mft_stats['active_entries']:,}")
        print(f"   Deleted files: {mft_stats['deleted_entries']:,}")
        print(f"   Fully recoverable: {mft_stats['recoverable_files']:,}")
        print(f"   Partially recoverable: {mft_stats['partially_recoverable']:,}")
        print(f"   Non-recoverable: {mft_stats['non_recoverable']:,}")
        print(f"   ADS streams detected: {mft_stats['ads_detected']:,}")
        print(f"   Timestomped files: {mft_stats['timestomped_files']:,}")
        print(f"   Anomalies detected: {mft_stats['anomalies_detected']:,}")
        print(f"{'='*70}\n")

    except Exception as e:
        print(f"    ❌ MFT analysis error: {str(e)}")
        # Provide empty data structure if analysis fails
        mft_data = mft_analyzer._get_unavailable_data()
        mft_stats = mft_analyzer.get_statistics()

    # Add to activity log
    activity_log.append({
        'type': 'mft analysis',
        'matches': mft_stats.get('deleted_entries', 0)
    })

    # Save MFT analyzer for file recovery operations
    # This allows users to recover files later using command-line tools
    try:
        import pickle
        analyzer_path = f'mft_analyzer_state_{timestamp}.pkl'
        with open(analyzer_path, 'wb') as f:
            pickle.dump(mft_analyzer, f)
        print(f"💾 MFT analyzer state saved to: {analyzer_path}")
        print(f"   Use 'python mft_recovery_tool.py {analyzer_path}' to recover files\n")
    except Exception as e:
        print(f"⚠️  Could not save MFT analyzer state: {str(e)}\n")

    # Perform Pagefile.sys Analysis
    print(f"\n{'='*70}")
    print(f"💾 PAGEFILE.SYS ANALYSIS - VIRTUAL MEMORY FORENSICS")
    print(f"{'='*70}")
    pagefile_analyzer = PagefileAnalyzer()
    pagefile_data = {}
    pagefile_stats = {}

    try:
        # Analyze pagefile for memory artifacts
        pagefile_data = pagefile_analyzer.analyze()
        pagefile_stats = pagefile_analyzer.get_statistics()

        print(f"{'='*70}")
        print(f"✅ PAGEFILE ANALYSIS SUMMARY:")
        print(f"   Strings extracted: {pagefile_stats['strings_extracted']:,}")
        print(f"   URLs found: {pagefile_stats['urls_found']:,}")
        print(f"   Email addresses: {pagefile_stats['emails_found']:,}")
        print(f"   File paths: {pagefile_stats['paths_found']:,}")
        print(f"   IP addresses: {pagefile_stats['ips_found']:,}")
        print(f"   🔐 Sensitive items: {pagefile_stats['sensitive_items']:,}")
        print(f"{'='*70}\n")

    except Exception as e:
        print(f"    ❌ Pagefile analysis error: {str(e)}")
        # Provide empty data structure if analysis fails
        pagefile_data = pagefile_analyzer._get_unavailable_data()
        pagefile_stats = pagefile_analyzer.get_statistics()

    # Add to activity log
    activity_log.append({
        'type': 'pagefile analysis',
        'matches': pagefile_stats.get('total_artifacts', 0)
    })

    # Now generate the modern HTML report
    with open(html_file, "w", encoding="utf-8") as f:
        # Write HTML header with modern UI — pass detected OS
        f.write(generate_html_header(timestamp, assets_path, os_type=current_os))

        # Generate Dashboard Tab
        stats = {
            'total_cases': len(os_results),
            'active_cases': len(os_results),
            'evidence_items': 0,
            'analysis_logs': len(activity_log),
            'timestamp': timestamp
        }
        f.write(generate_dashboard_tab(stats, activity_log, {}))

        # Build command display data for all OSes:
        # - Current OS: real executed results
        # - Other OSes: reference-only display
        if current_os == OS_WINDOWS:
            windows_results = os_results
            linux_results = build_os_command_display(LINUX_COMMANDS, COMMAND_DESCRIPTIONS, "Linux")
            macos_results = build_os_command_display(MACOS_COMMANDS, COMMAND_DESCRIPTIONS, "macOS")
        elif current_os == OS_LINUX:
            windows_results = build_os_command_display(WINDOWS_COMMANDS, COMMAND_DESCRIPTIONS, "Windows")
            linux_results = os_results
            macos_results = build_os_command_display(MACOS_COMMANDS, COMMAND_DESCRIPTIONS, "macOS")
        elif current_os == OS_MACOS:
            windows_results = build_os_command_display(WINDOWS_COMMANDS, COMMAND_DESCRIPTIONS, "Windows")
            linux_results = build_os_command_display(LINUX_COMMANDS, COMMAND_DESCRIPTIONS, "Linux")
            macos_results = os_results
        else:
            windows_results = os_results
            linux_results = build_os_command_display(LINUX_COMMANDS, COMMAND_DESCRIPTIONS, "Linux")
            macos_results = build_os_command_display(MACOS_COMMANDS, COMMAND_DESCRIPTIONS, "macOS")

        # Generate OS Commands Tab — auto-highlights current OS
        f.write(generate_os_commands_tab(
            windows_results,
            current_os,
            linux_results=linux_results,
            macos_results=macos_results
        ))

        # Generate Hash Analysis Tab (NEW INTERACTIVE VERSION)
        f.write(generate_hash_tab_interactive(file_hashes if file_hashes else []))

        # Generate PII Detection Tab (NEW)
        f.write(generate_pii_tab(pii_results))

        # Generate Browser History Tab (NEW)
        f.write(generate_browser_history_tab(browser_history, browser_stats))

        # Generate Registry Analysis Tab (NEW)
        f.write(generate_registry_tab(registry_data, registry_stats))

        # Generate Event Log Analysis Tab (NEW)
        f.write(generate_eventlog_tab(eventlog_data, eventlog_stats))

        # Generate MFT Analysis Tab (NEW)
        f.write(generate_mft_tab(mft_data, mft_stats))

        # Generate Pagefile Analysis Tab (NEW)
        f.write(generate_pagefile_tab(pagefile_data))

        # Generate Encrypted Files Tab (NEW)
        f.write(generate_encrypted_files_tab(encrypted_data))

        # Generate Regex Analysis Tab
        f.write(f'    <div id="tab-regex" class="tab-content">\n')
        f.write(f'        <div class="tab-header">\n')
        f.write(f'            <h1>Regex Pattern Analysis</h1>\n')
        f.write(f'        </div>\n')
        f.write(f'        <div class="card">\n')

        # Generate threat dashboard if critical threats found
        if regex_results['threat_score'] > 50:
            threat_data = {
                'threat_level': regex_results['threat_level'],
                'threat_score': regex_results['threat_score'],
                'total_iocs': len(regex_results['iocs']),
                'critical_findings': len(regex_results['suspicious_patterns'].get('CREDENTIALS', [])) +
                                   len(regex_results['suspicious_patterns'].get('MALWARE', [])),
                'total_commands': len(all_forensic_data),
                'files_hashed': len(file_hashes) if file_hashes else 0
            }
            f.write(generate_threat_dashboard(threat_data))

        regex_html = regex_analyzer.generate_report(regex_results)
        f.write(regex_html)
        f.write(f'        </div>\n')
        f.write(f'    </div>\n\n')

        # Generate IOC Scanner Tab (NEW FUNCTIONAL VERSION WITH RESULTS)
        f.write(generate_ioc_scanner_tab(ioc_results))

        # Write HTML footer
        f.write(generate_html_footer(assets_path))

    print(f"\n✅ Done! Open the HTML report:")
    print(f"📄 {html_file}")
    print(f"\n💡 Modern LEA Triage Dashboard Generated!")
    print(f"🎨 Features:")
    print(f"   • Dark professional theme")
    print(f"   • Tab-based navigation (Dashboard/Commands/Hash/PII/Regex/IOC)")
    print(f"   • OS selector (Windows/Linux/macOS) — {current_os} auto-selected")
    print(f"   • Interactive cards and search")
    print(f"   • Real-time stats and activity feed")
    print(f"\n📋 Report includes:")
    print(f"   • {len(all_forensic_data)} forensic command results")
    print(f"   • {len(regex_results['iocs'])} IOCs detected")
    print(f"   • {len(file_hashes) if file_hashes else 0} files analyzed")
    print(f"   • Threat Score: {regex_results['threat_score']}/100")


if __name__ == "__main__":
    detected = detect_os()

    if detected == OS_WINDOWS:
        # Windows: offer UAC elevation
        if not is_admin():
            print("=" * 60)
            print("🔒 ADMINISTRATOR PRIVILEGES REQUIRED")
            print("=" * 60)
            print("\nThis forensic tool needs Administrator privileges for:")
            print("  • netstat -naob (process-to-connection mapping)")
            print("  • USB device history and events")
            print("  • System event logs")
            print("  • Complete process information")
            print("\nOptions:")
            print("  1. Restart with Administrator privileges (Recommended)")
            print("  2. Continue without admin (Limited data)")
            print("=" * 60)

            choice = input("\nYour choice (1 or 2): ").strip()

            if choice == "1":
                print("\n🔄 Restarting with Administrator privileges...")
                print("   (You may see a UAC prompt - click 'Yes')\n")
                run_as_admin()
            else:
                print("\n⚠️  Continuing without Administrator privileges...")
                print("   Some commands may fail.\n")
    else:
        # Linux / macOS
        if not is_admin():
            print("=" * 60)
            print(f"🔒 ROOT PRIVILEGES RECOMMENDED ({detected})")
            print("=" * 60)
            print("\nSome forensic commands require root/sudo for:")
            print("  • Full process listing")
            print("  • Network connection details")
            print("  • USB device history")
            print("  • System log access")
            print(f"\nRe-run with: sudo python3 {sys.argv[0]}")
            print("=" * 60)
            print("\n⚠️  Continuing without root privileges...")
            print("   Some commands may produce incomplete results.\n")

    run_forensic_collection()
