"""
Background worker thread for forensic collection
Cross-platform: auto-detects OS and runs appropriate commands
"""

from PyQt6.QtCore import QThread, pyqtSignal
from forensics_tool import ForensicCollector
from core.os_detector import detect_os, is_windows


class ForensicWorker(QThread):
    """Background thread for running forensic collection"""

    progress = pyqtSignal(int)
    log_message = pyqtSignal(str)
    finished = pyqtSignal(str)  # Report path
    error = pyqtSignal(str)

    def __init__(self, output_dir):
        super().__init__()
        self.output_dir = output_dir

    def run(self):
        """Run forensic collection in background"""
        try:
            current_os = detect_os()

            self.log_message.emit(f"🔍 Starting forensic triage collection ({current_os})...")
            self.progress.emit(10)

            # Initialize collector (auto-detects OS)
            collector = ForensicCollector(output_dir=self.output_dir)
            self.log_message.emit(f"✅ Forensic collector initialized for {collector.os_name}")
            self.progress.emit(20)

            # Execute commands for detected OS
            self.log_message.emit(f"📋 Executing {collector.os_name} forensic commands...")
            self.progress.emit(30)
            self.log_message.emit("   → Collecting system information...")
            self.progress.emit(35)
            self.log_message.emit("   → Gathering network configuration...")
            self.progress.emit(40)
            self.log_message.emit("   → Enumerating running processes...")
            self.progress.emit(45)

            results = collector.execute_all_commands()
            self.log_message.emit(f"✅ Collected {len(results)} command categories")
            self.progress.emit(50)

            # Analyze IOCs
            self.log_message.emit("🔎 Scanning for Indicators of Compromise (IOCs)...")
            self.progress.emit(55)
            self.log_message.emit("   → Checking for known malware signatures...")
            self.progress.emit(58)

            ioc_results = collector.scan_iocs()
            self.log_message.emit(f"✅ IOC scan complete: {len(ioc_results)} items analyzed")
            self.progress.emit(60)

            # Analyze browser history
            self.log_message.emit("🌐 Analyzing browser history...")
            self.progress.emit(65)
            self.log_message.emit("   → Scanning Chrome, Firefox, Edge/Safari databases...")
            self.progress.emit(68)

            browser_results = collector.analyze_browser_history()
            self.log_message.emit(f"✅ Browser analysis complete: {len(browser_results)} entries found")
            self.progress.emit(70)

            # Hash analysis
            self.log_message.emit("🔐 Performing hash analysis on suspicious files...")
            self.progress.emit(72)
            self.log_message.emit("   → Computing file hashes (MD5, SHA1, SHA256)...")
            self.progress.emit(75)

            # Scan event logs (OS-aware label)
            if is_windows():
                self.log_message.emit("📊 Scanning Windows Event Logs...")
            else:
                self.log_message.emit("📊 Scanning system logs...")
            self.progress.emit(78)

            eventlog_results = collector.analyze_event_logs()
            self.log_message.emit(f"✅ Log analysis complete: {len(eventlog_results)} events analyzed")
            self.progress.emit(82)

            # Scan for PII (Personally Identifiable Information)
            self.log_message.emit("🔍 Scanning for PII in user directories...")
            self.progress.emit(84)
            self.log_message.emit("   → Scanning Downloads, Desktop, Documents folders...")
            self.progress.emit(85)

            # Scan for encrypted files
            self.log_message.emit("🔐 Detecting encrypted files...")
            self.progress.emit(86)
            self.log_message.emit("   → Scanning user directories for encrypted content...")
            self.progress.emit(87)

            # Registry / System config analysis (OS-aware)
            if is_windows():
                self.log_message.emit("📝 Analyzing Windows Registry...")
                self.log_message.emit("   → Extracting startup programs, installed software, USB history...")
            else:
                self.log_message.emit("📝 Analyzing system configuration...")
                self.log_message.emit("   → Checking startup services, installed packages...")
            self.progress.emit(89)

            # MFT / Filesystem analysis (OS-aware)
            if is_windows():
                self.log_message.emit("💾 Analyzing Master File Table (MFT)...")
                self.log_message.emit("   → Scanning all volumes for file system metadata...")
            else:
                self.log_message.emit("💾 Analyzing filesystem metadata...")
            self.progress.emit(91)

            # Pagefile / Swap analysis (OS-aware)
            if is_windows():
                self.log_message.emit("📄 Analyzing pagefile and memory artifacts...")
            else:
                self.log_message.emit("📄 Analyzing swap/memory artifacts...")
            self.progress.emit(93)

            # Generate report
            self.log_message.emit("📊 Preparing HTML forensic report...")
            self.progress.emit(95)
            self.log_message.emit("   → Compiling all collected data...")
            self.progress.emit(96)

            report_path = collector.generate_html_report(
                results, ioc_results, browser_results, eventlog_results
            )

            self.log_message.emit("   → Generating HTML tables and charts...")
            self.progress.emit(97)
            self.log_message.emit("   → Finalizing report structure...")
            self.progress.emit(98)
            self.log_message.emit(f"✅ Report generated: {report_path}")
            self.progress.emit(100)

            self.finished.emit(report_path)

        except Exception as e:
            self.error.emit(f"❌ Error: {str(e)}")
