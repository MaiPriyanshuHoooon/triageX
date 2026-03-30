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

            self.log_message.emit(f"Starting triage ({current_os})...")
            self.progress.emit(10)

            collector = ForensicCollector(output_dir=self.output_dir)
            self.progress.emit(20)

            # OS commands
            self.log_message.emit(f"Running {collector.os_name} forensic commands...")
            self.progress.emit(30)
            results = collector.execute_all_commands()
            self.log_message.emit(f"  {len(results)} command categories collected")
            self.progress.emit(50)

            # IOC scan
            self.log_message.emit("Scanning for IOCs...")
            self.progress.emit(55)
            ioc_results = collector.scan_iocs()
            self.log_message.emit(f"  {len(ioc_results)} items analyzed")
            self.progress.emit(60)

            # Browser history
            self.log_message.emit("Analyzing browser history...")
            self.progress.emit(65)
            browser_results = collector.analyze_browser_history()
            self.log_message.emit(f"  {len(browser_results)} entries found")
            self.progress.emit(70)

            # Hash analysis
            self.log_message.emit("Hashing suspicious files...")
            self.progress.emit(75)

            # Event / system logs
            self.log_message.emit("Scanning system logs...")
            self.progress.emit(78)
            eventlog_results = collector.analyze_event_logs()
            self.log_message.emit(f"  {len(eventlog_results)} events analyzed")
            self.progress.emit(82)

            # PII detection
            self.log_message.emit("Scanning for PII...")
            self.progress.emit(84)

            # Encrypted files
            self.log_message.emit("Detecting encrypted files...")
            self.progress.emit(86)

            # Memory analysis
            self.log_message.emit("Analyzing memory...")
            self.progress.emit(88)
            collector.analyze_memory()
            self.progress.emit(89)

            # Registry / system config
            if is_windows():
                self.log_message.emit("Analyzing registry...")
            else:
                self.log_message.emit("Analyzing system config...")
            self.progress.emit(89)

            # Filesystem metadata
            if is_windows():
                self.log_message.emit("Analyzing MFT...")
            else:
                self.log_message.emit("Analyzing filesystem metadata...")
            self.progress.emit(91)

            # Swap / pagefile
            if is_windows():
                self.log_message.emit("Analyzing pagefile...")
            else:
                self.log_message.emit("Analyzing swap artifacts...")
            self.progress.emit(93)

            # Generate report
            self.log_message.emit("Generating report...")
            self.progress.emit(95)
            report_path = collector.generate_html_report(
                results, ioc_results, browser_results, eventlog_results
            )
            self.log_message.emit(f"Report saved: {report_path}")
            self.progress.emit(100)

            self.finished.emit(report_path)

        except Exception as e:
            self.error.emit(f"Error: {str(e)}")
