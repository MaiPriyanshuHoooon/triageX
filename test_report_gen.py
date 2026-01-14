import os
import sys

# Add current dir to path to ensure imports work
sys.path.append(os.getcwd())

from forensics_tool import ForensicCollector, build_os_command_display
from config.commands import WINDOWS_COMMANDS, LINUX_COMMANDS, MACOS_COMMANDS, COMMAND_DESCRIPTIONS

print("[*] Starting quick report generation test...")

# 1. Setup minimal collector
output_dir = "test_verification_report"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

collector = ForensicCollector(output_dir)

# 2. Mock some Windows data (simulating what happens after a scan)
print("[*] Mocking Windows data...")
collector.os_results = {
    "system": [
        {
            "description": "Display system info (MOCKED RESULT)",
            "output": "<table class='output-table'><tr><th>Property</th><th>Value</th></tr><tr><td>OS</td><td>Windows 11</td></tr></table>",
            "type": "CMD",
            "success": True
        }
    ],
    "users": [
        {
            "description": "List users (MOCKED RESULT)",
            "output": "Administrator, Guest, User",
            "type": "PS",
            "success": True
        }
    ]
}

# 3. set empty attributes for other scanners to avoid errors
collector.file_hashes = []
collector.regex_results = {'iocs': [], 'threat_score': 0, 'threat_level': 'LOW', 'suspicious_patterns': {}}
collector.browser_stats = {}
collector.eventlog_stats = {}
collector.activity_log = [{'type': 'test', 'matches': 1}]

# 4. Generate the report
# This calls your UPDATED logic which pulls LINUX_COMMANDS and MACOS_COMMANDS
print("[*] Generating HTML report...")
report_path = collector.generate_html_report(
    results=collector.os_results,
    ioc_results={'total_iocs': 0, 'threat_level': 'LOW', 'threat_score': 0, 'severity_counts': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}},
    browser_results={},
    eventlog_results={}
)

print(f"\n[+] DONE! Open this file to verify tabs:")
print(f"-> {os.path.abspath(report_path)}")
