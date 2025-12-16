"""
Enhanced IOC Scanner for Law Enforcement Investigations
========================================================
Provides granular control for investigators to:
- Scan specific evidence directories
- Track which files contain IOCs
- Generate court-ready reports
- Add case notes and tags
- Export findings for legal proceedings
"""

import os
import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from core.ioc_scanner import IOCScanner


class InvestigativeIOCScanner:
    """
    Law Enforcement focused IOC scanner with evidence tracking
    """

    def __init__(self, case_id: str = None):
        """
        Initialize scanner with optional case ID

        Args:
            case_id: Case number for tracking (e.g., "CASE-2025-1234")
        """
        self.scanner = IOCScanner()
        self.case_id = case_id or f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.evidence_findings = []
        self.scan_metadata = {
            'case_id': self.case_id,
            'scan_timestamp': datetime.now().isoformat(),
            'investigator': os.environ.get('USER', 'Unknown'),
            'total_files_scanned': 0,
            'files_with_iocs': 0,
            'total_iocs': 0
        }

    def scan_evidence_directory(self,
                                evidence_path: str,
                                evidence_label: str = None,
                                recursive: bool = True,
                                file_extensions: List[str] = None,
                                severity_filter: List[str] = None) -> Dict:
        """
        Scan specific evidence directory with full file tracking

        Args:
            evidence_path: Path to evidence (e.g., "/Volumes/Evidence_USB")
            evidence_label: Label for this evidence (e.g., "Suspect's Laptop")
            recursive: Scan subdirectories
            file_extensions: Filter by extensions (e.g., ['.txt', '.log', '.ps1'])
            severity_filter: Only report specific severities ['CRITICAL', 'HIGH']

        Returns:
            Dictionary with detailed findings per file
        """

        print(f"\n{'='*80}")
        print(f"🔍 EVIDENCE SCAN - {self.case_id}")
        print(f"{'='*80}")
        print(f"Evidence Location: {evidence_path}")
        print(f"Evidence Label: {evidence_label or 'Unlabeled'}")
        print(f"Scan Mode: {'Recursive' if recursive else 'Top-level only'}")
        print(f"{'='*80}\n")

        if not os.path.exists(evidence_path):
            print(f"❌ ERROR: Evidence path not found: {evidence_path}")
            return {'error': 'Path not found'}

        # Collect files to scan
        files_to_scan = []

        if os.path.isfile(evidence_path):
            # Single file
            files_to_scan.append(evidence_path)
        else:
            # Directory
            if recursive:
                for root, dirs, files in os.walk(evidence_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if file_extensions:
                            if any(file.lower().endswith(ext.lower()) for ext in file_extensions):
                                files_to_scan.append(file_path)
                        else:
                            # Skip binary files
                            if not file.lower().endswith(('.exe', '.dll', '.bin', '.jpg', '.png', '.mp4', '.zip')):
                                files_to_scan.append(file_path)
            else:
                for item in os.listdir(evidence_path):
                    item_path = os.path.join(evidence_path, item)
                    if os.path.isfile(item_path):
                        if file_extensions:
                            if any(item.lower().endswith(ext.lower()) for ext in file_extensions):
                                files_to_scan.append(item_path)
                        else:
                            if not item.lower().endswith(('.exe', '.dll', '.bin', '.jpg', '.png', '.mp4', '.zip')):
                                files_to_scan.append(item_path)

        print(f"📂 Found {len(files_to_scan)} files to analyze\n")

        # Scan each file
        files_with_iocs = 0
        total_iocs = 0

        for idx, file_path in enumerate(files_to_scan, 1):
            print(f"[{idx}/{len(files_to_scan)}] Scanning: {os.path.basename(file_path)[:50]}...", end=' ')

            try:
                # Read file content
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1024 * 1024)  # Read up to 1MB

                # Scan for IOCs
                results = self.scanner.scan_text(content)

                # Apply severity filter if specified
                if severity_filter:
                    filtered_findings = {}
                    for category, findings in results['findings_by_category'].items():
                        filtered = [f for f in findings if f['severity'] in severity_filter]
                        if filtered:
                            filtered_findings[category] = filtered
                    results['findings_by_category'] = filtered_findings
                    results['total_iocs'] = sum(len(f) for f in filtered_findings.values())

                if results['total_iocs'] > 0:
                    files_with_iocs += 1
                    total_iocs += results['total_iocs']

                    # Get file metadata
                    file_stat = os.stat(file_path)

                    # Store finding
                    finding = {
                        'case_id': self.case_id,
                        'evidence_label': evidence_label or 'Unlabeled',
                        'file_path': file_path,
                        'file_name': os.path.basename(file_path),
                        'file_size': file_stat.st_size,
                        'file_modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                        'file_accessed': datetime.fromtimestamp(file_stat.st_atime).isoformat(),
                        'scan_timestamp': datetime.now().isoformat(),
                        'threat_level': results['threat_level'],
                        'threat_score': results['threat_score'],
                        'total_iocs': results['total_iocs'],
                        'severity_counts': results['severity_counts'],
                        'findings_by_category': results['findings_by_category'],
                        'investigator_notes': ''
                    }

                    self.evidence_findings.append(finding)

                    print(f"🚨 {results['threat_level']} - {results['total_iocs']} IOCs")
                else:
                    print("✅ Clean")

            except Exception as e:
                print(f"⚠️  Error: {str(e)[:30]}")

        # Update metadata
        self.scan_metadata['total_files_scanned'] += len(files_to_scan)
        self.scan_metadata['files_with_iocs'] += files_with_iocs
        self.scan_metadata['total_iocs'] += total_iocs

        # Summary
        print(f"\n{'='*80}")
        print(f"📊 SCAN SUMMARY")
        print(f"{'='*80}")
        print(f"Total Files Scanned: {len(files_to_scan)}")
        print(f"Files with IOCs: {files_with_iocs}")
        print(f"Total IOCs Found: {total_iocs}")
        print(f"{'='*80}\n")

        return {
            'evidence_path': evidence_path,
            'evidence_label': evidence_label,
            'files_scanned': len(files_to_scan),
            'files_with_iocs': files_with_iocs,
            'total_iocs': total_iocs,
            'findings': [f for f in self.evidence_findings if f['evidence_label'] == (evidence_label or 'Unlabeled')]
        }

    def add_investigator_note(self, file_path: str, note: str):
        """
        Add investigator notes to specific finding

        Args:
            file_path: Path to the file
            note: Investigator's note (e.g., "Matches suspect's known TTP")
        """
        for finding in self.evidence_findings:
            if finding['file_path'] == file_path:
                finding['investigator_notes'] = note
                print(f"✅ Note added to: {os.path.basename(file_path)}")
                return
        print(f"⚠️  File not found in findings: {file_path}")

    def filter_by_severity(self, severity: List[str]) -> List[Dict]:
        """
        Get findings by severity level

        Args:
            severity: List of severities ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

        Returns:
            Filtered findings
        """
        filtered = []
        for finding in self.evidence_findings:
            for sev in severity:
                if finding['severity_counts'].get(sev, 0) > 0:
                    filtered.append(finding)
                    break
        return filtered

    def export_for_court(self, output_dir: str, format: str = 'all'):
        """
        Export findings in court-ready formats

        Args:
            output_dir: Directory to save reports
            format: 'json', 'csv', 'txt', or 'all'
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        print(f"\n{'='*80}")
        print(f"📄 GENERATING COURT REPORTS - {self.case_id}")
        print(f"{'='*80}\n")

        # JSON Report (complete data)
        if format in ['json', 'all']:
            json_file = os.path.join(output_dir, f"{self.case_id}_IOC_Report_{timestamp}.json")
            report_data = {
                'case_metadata': self.scan_metadata,
                'findings': self.evidence_findings
            }
            with open(json_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            print(f"✅ JSON Report: {json_file}")

        # CSV Report (for spreadsheet analysis)
        if format in ['csv', 'all']:
            csv_file = os.path.join(output_dir, f"{self.case_id}_IOC_Summary_{timestamp}.csv")
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'Case ID', 'Evidence Label', 'File Name', 'File Path',
                    'File Size', 'Modified Date', 'Threat Level', 'Threat Score',
                    'Total IOCs', 'Critical', 'High', 'Medium', 'Low',
                    'Categories', 'Investigator Notes'
                ])

                for finding in self.evidence_findings:
                    writer.writerow([
                        finding['case_id'],
                        finding['evidence_label'],
                        finding['file_name'],
                        finding['file_path'],
                        finding['file_size'],
                        finding['file_modified'],
                        finding['threat_level'],
                        finding['threat_score'],
                        finding['total_iocs'],
                        finding['severity_counts'].get('CRITICAL', 0),
                        finding['severity_counts'].get('HIGH', 0),
                        finding['severity_counts'].get('MEDIUM', 0),
                        finding['severity_counts'].get('LOW', 0),
                        ', '.join(finding['findings_by_category'].keys()),
                        finding['investigator_notes']
                    ])
            print(f"✅ CSV Report: {csv_file}")

        # Text Report (human-readable for court documents)
        if format in ['txt', 'all']:
            txt_file = os.path.join(output_dir, f"{self.case_id}_IOC_Detailed_{timestamp}.txt")
            with open(txt_file, 'w') as f:
                f.write("="*80 + "\n")
                f.write(f"IOC ANALYSIS REPORT - CASE {self.case_id}\n")
                f.write("="*80 + "\n\n")

                f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Investigator: {self.scan_metadata['investigator']}\n")
                f.write(f"Total Files Scanned: {self.scan_metadata['total_files_scanned']}\n")
                f.write(f"Files with IOCs: {self.scan_metadata['files_with_iocs']}\n")
                f.write(f"Total IOCs Detected: {self.scan_metadata['total_iocs']}\n\n")

                f.write("="*80 + "\n")
                f.write("DETAILED FINDINGS\n")
                f.write("="*80 + "\n\n")

                for idx, finding in enumerate(self.evidence_findings, 1):
                    f.write(f"Finding #{idx}\n")
                    f.write(f"{'-'*80}\n")
                    f.write(f"Evidence: {finding['evidence_label']}\n")
                    f.write(f"File: {finding['file_name']}\n")
                    f.write(f"Path: {finding['file_path']}\n")
                    f.write(f"Size: {finding['file_size']} bytes\n")
                    f.write(f"Modified: {finding['file_modified']}\n")
                    f.write(f"Threat Level: {finding['threat_level']}\n")
                    f.write(f"Threat Score: {finding['threat_score']}\n")
                    f.write(f"Total IOCs: {finding['total_iocs']}\n\n")

                    f.write(f"Severity Breakdown:\n")
                    f.write(f"  Critical: {finding['severity_counts'].get('CRITICAL', 0)}\n")
                    f.write(f"  High: {finding['severity_counts'].get('HIGH', 0)}\n")
                    f.write(f"  Medium: {finding['severity_counts'].get('MEDIUM', 0)}\n")
                    f.write(f"  Low: {finding['severity_counts'].get('LOW', 0)}\n\n")

                    f.write(f"IOCs Detected:\n")
                    for category, iocs in finding['findings_by_category'].items():
                        f.write(f"\n  {category} ({len(iocs)} findings):\n")
                        for ioc in iocs[:10]:  # Limit to 10 per category
                            f.write(f"    - [{ioc['severity']}] {ioc['pattern_name']}: {ioc['match'][:80]}\n")

                    if finding['investigator_notes']:
                        f.write(f"\nInvestigator Notes:\n")
                        f.write(f"  {finding['investigator_notes']}\n")

                    f.write(f"\n{'='*80}\n\n")

            print(f"✅ Text Report: {txt_file}")

        print(f"\n{'='*80}")
        print(f"✅ Reports exported to: {output_dir}")
        print(f"{'='*80}\n")

    def generate_timeline(self) -> List[Dict]:
        """
        Generate timeline of IOC findings based on file timestamps

        Returns:
            List of events sorted by timestamp
        """
        timeline = []
        for finding in self.evidence_findings:
            timeline.append({
                'timestamp': finding['file_modified'],
                'event_type': 'File Modified',
                'file': finding['file_name'],
                'evidence': finding['evidence_label'],
                'threat_level': finding['threat_level'],
                'iocs': finding['total_iocs']
            })

        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        return timeline

    def get_summary_statistics(self) -> Dict:
        """
        Get summary statistics for the case

        Returns:
            Dictionary with case statistics
        """
        total_critical = sum(f['severity_counts'].get('CRITICAL', 0) for f in self.evidence_findings)
        total_high = sum(f['severity_counts'].get('HIGH', 0) for f in self.evidence_findings)
        total_medium = sum(f['severity_counts'].get('MEDIUM', 0) for f in self.evidence_findings)
        total_low = sum(f['severity_counts'].get('LOW', 0) for f in self.evidence_findings)

        # Get most common IOC categories
        category_counts = {}
        for finding in self.evidence_findings:
            for category in finding['findings_by_category'].keys():
                category_counts[category] = category_counts.get(category, 0) + 1

        return {
            'case_id': self.case_id,
            'total_files_scanned': self.scan_metadata['total_files_scanned'],
            'files_with_iocs': self.scan_metadata['files_with_iocs'],
            'total_iocs': self.scan_metadata['total_iocs'],
            'severity_totals': {
                'CRITICAL': total_critical,
                'HIGH': total_high,
                'MEDIUM': total_medium,
                'LOW': total_low
            },
            'top_categories': sorted(category_counts.items(), key=lambda x: x[1], reverse=True),
            'evidence_sources': list(set(f['evidence_label'] for f in self.evidence_findings))
        }


# Example usage for investigators
if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║              INVESTIGATIVE IOC SCANNER - LAW ENFORCEMENT TOOL                 ║
╚═══════════════════════════════════════════════════════════════════════════════╝

This tool provides investigators with granular control over IOC scanning:

1. Scan specific evidence directories (seized devices, USB drives, folders)
2. Track which files contain threats
3. Add investigator notes to findings
4. Export court-ready reports (JSON, CSV, TXT)
5. Generate timelines of suspicious activity
6. Filter by severity level

Example Usage:
--------------

# Initialize scanner with case ID
scanner = InvestigativeIOCScanner(case_id="CASE-2025-1234")

# Scan suspect's laptop Documents folder
scanner.scan_evidence_directory(
    evidence_path="/path/to/suspect/Documents",
    evidence_label="Suspect's Laptop - Documents",
    recursive=True,
    severity_filter=['CRITICAL', 'HIGH']  # Only critical/high threats
)

# Scan seized USB drive (PowerShell scripts only)
scanner.scan_evidence_directory(
    evidence_path="/Volumes/Evidence_USB",
    evidence_label="Seized USB Drive",
    file_extensions=['.ps1', '.bat', '.cmd']
)

# Add investigator notes
scanner.add_investigator_note(
    file_path="/path/to/suspicious/file.txt",
    note="Matches suspect's known malware patterns from previous case"
)

# Export for court
scanner.export_for_court(
    output_dir="./Case_Reports",
    format='all'  # JSON, CSV, and TXT
)

# Get summary
stats = scanner.get_summary_statistics()
print(f"Total Critical IOCs: {stats['severity_totals']['CRITICAL']}")

""")
