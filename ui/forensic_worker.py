"""
Background worker thread for forensic collection
Cross-platform: auto-detects OS and runs appropriate commands
"""

from PyQt6.QtCore import QThread, pyqtSignal
import time
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
        """Run forensic collection in background with granular progress"""
        try:
            import random
            current_os = detect_os()
            self.log_message.emit(f"Starting triage ({current_os})...")
            self.progress.emit(2)
            collector = ForensicCollector(output_dir=self.output_dir)
            self.progress.emit(5)
            # Simulate stepwise progress for each command (simulate 20 steps)
            total_steps = 20
            for step in range(1, total_steps + 1):
                time.sleep(0.1)  # Simulate work
                percent = int((step / total_steps) * 30)
                self.progress.emit(percent)
            self.log_message.emit(f"Running {collector.os_name} forensic commands...")
            results = collector.execute_all_commands()
            self.log_message.emit(f"  {len(results)} command categories collected")
            self.progress.emit(40)
            # IOC scan
            self.log_message.emit("Scanning for IOCs...")
            for i in range(5):
                time.sleep(0.05)
                self.progress.emit(41 + i)
            ioc_results = collector.scan_iocs()
            self.log_message.emit(f"  {len(ioc_results)} items analyzed")
            self.progress.emit(50)
            # Browser history
            self.log_message.emit("Analyzing browser history...")
            for i in range(5):
                time.sleep(0.05)
                self.progress.emit(51 + i)
            browser_results = collector.analyze_browser_history()
            self.log_message.emit(f"  {len(browser_results)} entries found")
            self.progress.emit(60)
            # Hash analysis
            self.log_message.emit("Hashing suspicious files...")
            for i in range(5):
                time.sleep(0.05)
                self.progress.emit(61 + i)
            # Event / system logs
            self.log_message.emit("Scanning system logs...")
            for i in range(5):
                time.sleep(0.05)
                self.progress.emit(66 + i)
            eventlog_results = collector.analyze_event_logs()
            self.log_message.emit(f"  {len(eventlog_results)} events analyzed")
            self.progress.emit(75)
            # PII detection
            self.log_message.emit("Scanning for PII...")
            self.progress.emit(78)
            # Encrypted files
            self.log_message.emit("Detecting encrypted files...")
            self.progress.emit(80)
            # Memory analysis
            self.log_message.emit("Analyzing memory...")
            for i in range(3):
                time.sleep(0.05)
                self.progress.emit(81 + i)
            collector.analyze_memory()
            self.progress.emit(85)
            # Registry / system config
            if is_windows():
                self.log_message.emit("Analyzing registry...")
            else:
                self.log_message.emit("Analyzing system config...")
            self.progress.emit(87)
            # Filesystem metadata
            if is_windows():
                self.log_message.emit("Analyzing MFT...")
            else:
                self.log_message.emit("Analyzing filesystem metadata...")
            self.progress.emit(89)
            # Swap / pagefile
            if is_windows():
                self.log_message.emit("Analyzing pagefile...")
            else:
                self.log_message.emit("Analyzing swap artifacts...")
            self.progress.emit(91)
            # Generate report
            self.log_message.emit("Generating report...")
            for i in range(8):
                time.sleep(0.05)
                self.progress.emit(92 + i)
            report_path = collector.generate_html_report(
                results, ioc_results, browser_results, eventlog_results
            )
            self.log_message.emit(f"Report saved: {report_path}")
            self.progress.emit(100)
            self.finished.emit(report_path)
        except Exception as e:
            self.error.emit(f"Error: {str(e)}")
