"""
Background worker thread for forensic collection
"""

from PyQt6.QtCore import QThread, pyqtSignal
from forensics_tool import ForensicCollector


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
            self.log_message.emit("🔍 Starting forensic triage collection...")
            self.progress.emit(10)

            # Initialize collector
            collector = ForensicCollector(output_dir=self.output_dir)
            self.log_message.emit("✅ Forensic collector initialized")
            self.progress.emit(20)

            # Execute commands
            self.log_message.emit("📋 Executing Windows forensic commands...")
            self.progress.emit(30)
            self.log_message.emit("   → Collecting system information...")
            self.progress.emit(35)
            self.log_message.emit("   → Gathering network configuration...")
            self.progress.emit(40)
            self.log_message.emit("   → Enumerating running processes...")
            self.progress.emit(45)

            results = collector.execute_all_commands()
            self.log_message.emit(f"✅ Collected {len(results)} command results")
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
            self.log_message.emit("   → Scanning Chrome, Firefox, Edge databases...")
            self.progress.emit(68)

            browser_results = collector.analyze_browser_history()
            self.log_message.emit(f"✅ Browser analysis complete: {len(browser_results)} entries found")
            self.progress.emit(70)

            # Hash analysis
            self.log_message.emit("🔐 Performing hash analysis on suspicious files...")
            self.progress.emit(72)
            self.log_message.emit("   → Computing file hashes (MD5, SHA1, SHA256)...")
            self.progress.emit(75)

            # Scan event logs
            self.log_message.emit("📊 Scanning Windows Event Logs...")
            self.progress.emit(78)

            eventlog_results = collector.analyze_event_logs()
            self.log_message.emit(f"✅ Event log analysis complete: {len(eventlog_results)} events analyzed")
            self.progress.emit(82)

            # Scan for PII (Personally Identifiable Information)
            self.log_message.emit("🔍 Scanning for PII in user directories...")
            self.progress.emit(84)
            self.log_message.emit("   → Scanning Downloads, Desktop, Documents folders...")
            self.progress.emit(85)

            # Scan for encrypted files
            self.log_message.emit("🔐 Detecting encrypted files across drives...")
            self.progress.emit(86)
            self.log_message.emit("   → Scanning user directories for encrypted content...")
            self.progress.emit(87)

            # Registry analysis
            self.log_message.emit("📝 Analyzing Windows Registry...")
            self.progress.emit(88)
            self.log_message.emit("   → Extracting startup programs, installed software, USB history...")
            self.progress.emit(89)

            # MFT analysis
            self.log_message.emit("💾 Analyzing Master File Table (MFT)...")
            self.progress.emit(90)
            self.log_message.emit("   → Scanning all volumes for file system metadata...")
            self.progress.emit(91)

            # Pagefile analysis
            self.log_message.emit("📄 Analyzing pagefile and memory artifacts...")
            self.progress.emit(92)
            self.log_message.emit("   → Extracting data from pagefile.sys...")
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
