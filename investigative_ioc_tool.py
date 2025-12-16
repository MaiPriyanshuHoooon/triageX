#!/usr/bin/env python3
"""
Interactive IOC Scanner for Law Enforcement
============================================
User-friendly interface for investigators to scan evidence
"""

import os
import sys
from datetime import datetime
from core.investigative_ioc_scanner import InvestigativeIOCScanner


def clear_screen():
    """Clear terminal screen"""
    os.system('clear' if os.name != 'nt' else 'cls')


def print_banner():
    """Print application banner"""
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║         🔍 INVESTIGATIVE IOC SCANNER - LAW ENFORCEMENT EDITION 🔍            ║
║                                                                               ║
║                     Digital Evidence Analysis Tool                            ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
""")


def get_case_id():
    """Get or create case ID"""
    print("\n📋 CASE IDENTIFICATION")
    print("="*80)
    case_id = input("Enter Case ID (or press Enter for auto-generate): ").strip()
    if not case_id:
        case_id = f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        print(f"✅ Auto-generated Case ID: {case_id}")
    else:
        print(f"✅ Using Case ID: {case_id}")
    return case_id


def select_evidence():
    """Interactive evidence selection"""
    print("\n📂 EVIDENCE SELECTION")
    print("="*80)
    print("1. Enter evidence path manually")
    print("2. Select from common locations")
    print("3. Browse current directory")

    choice = input("\nYour choice (1-3): ").strip()

    if choice == "1":
        evidence_path = input("Enter full path to evidence: ").strip()
        evidence_label = input("Enter evidence label (e.g., 'Suspect's Laptop'): ").strip()
        return evidence_path, evidence_label

    elif choice == "2":
        print("\n📍 Common Locations:")
        home = os.path.expanduser("~")
        locations = {
            '1': (f"{home}/Desktop", "User Desktop"),
            '2': (f"{home}/Downloads", "User Downloads"),
            '3': (f"{home}/Documents", "User Documents"),
            '4': ("/Volumes", "External Drives (macOS)"),
            '5': ("/media", "External Drives (Linux)"),
        }

        for key, (path, label) in locations.items():
            exists = "✅" if os.path.exists(path) else "❌"
            print(f"  {key}. {exists} {label} - {path}")

        loc_choice = input("\nSelect location (1-5): ").strip()
        if loc_choice in locations:
            evidence_path = locations[loc_choice][0]
            evidence_label = input(f"Evidence label [{locations[loc_choice][1]}]: ").strip()
            if not evidence_label:
                evidence_label = locations[loc_choice][1]
            return evidence_path, evidence_label

    elif choice == "3":
        print("\n📂 Current Directory Contents:")
        items = []
        for item in os.listdir('.'):
            if os.path.isdir(item):
                items.append((item, 'DIR'))
            else:
                items.append((item, 'FILE'))

        for idx, (item, item_type) in enumerate(items[:20], 1):
            print(f"  {idx}. [{item_type}] {item}")

        if len(items) > 20:
            print(f"  ... and {len(items) - 20} more")

        idx = input("\nSelect item number: ").strip()
        try:
            selected = items[int(idx) - 1][0]
            evidence_path = os.path.abspath(selected)
            evidence_label = input(f"Evidence label [{selected}]: ").strip() or selected
            return evidence_path, evidence_label
        except:
            print("❌ Invalid selection")

    return None, None


def configure_scan_options():
    """Configure scan options"""
    print("\n⚙️  SCAN CONFIGURATION")
    print("="*80)

    # Recursive
    recursive = input("Scan subdirectories? (Y/n): ").strip().lower() != 'n'

    # File extensions
    print("\nFile type filter:")
    print("  1. All text files (default)")
    print("  2. Scripts only (.ps1, .bat, .cmd, .sh)")
    print("  3. Logs only (.log, .txt)")
    print("  4. Custom extensions")

    ext_choice = input("Choose filter (1-4) [1]: ").strip() or "1"

    file_extensions = None
    if ext_choice == "2":
        file_extensions = ['.ps1', '.bat', '.cmd', '.sh', '.py']
    elif ext_choice == "3":
        file_extensions = ['.log', '.txt']
    elif ext_choice == "4":
        exts = input("Enter extensions (comma-separated, e.g., .ps1,.log): ").strip()
        file_extensions = [e.strip() for e in exts.split(',')]

    # Severity filter
    print("\nSeverity filter:")
    print("  1. All severities (default)")
    print("  2. Critical only")
    print("  3. Critical + High")
    print("  4. Medium and above")

    sev_choice = input("Choose filter (1-4) [1]: ").strip() or "1"

    severity_filter = None
    if sev_choice == "2":
        severity_filter = ['CRITICAL']
    elif sev_choice == "3":
        severity_filter = ['CRITICAL', 'HIGH']
    elif sev_choice == "4":
        severity_filter = ['CRITICAL', 'HIGH', 'MEDIUM']

    return recursive, file_extensions, severity_filter


def view_findings(scanner):
    """View current findings"""
    if not scanner.evidence_findings:
        print("\n⚠️  No findings yet. Please scan evidence first.")
        input("\nPress Enter to continue...")
        return

    clear_screen()
    print("\n📊 CURRENT FINDINGS")
    print("="*80)

    print(f"\nFiles with IOCs: {len(scanner.evidence_findings)}")
    print(f"Total IOCs: {scanner.scan_metadata['total_iocs']}\n")

    for idx, finding in enumerate(scanner.evidence_findings, 1):
        print(f"{idx}. {finding['threat_level']}")
        print(f"   File: {finding['file_name']}")
        print(f"   Evidence: {finding['evidence_label']}")
        print(f"   IOCs: {finding['total_iocs']} (Critical: {finding['severity_counts'].get('CRITICAL', 0)}, "
              f"High: {finding['severity_counts'].get('HIGH', 0)})")
        if finding['investigator_notes']:
            print(f"   📝 Note: {finding['investigator_notes']}")
        print()

    input("\nPress Enter to continue...")


def add_notes(scanner):
    """Add investigator notes"""
    if not scanner.evidence_findings:
        print("\n⚠️  No findings yet. Please scan evidence first.")
        input("\nPress Enter to continue...")
        return

    clear_screen()
    print("\n📝 ADD INVESTIGATOR NOTES")
    print("="*80)

    for idx, finding in enumerate(scanner.evidence_findings, 1):
        print(f"{idx}. {finding['file_name']} ({finding['threat_level']})")

    try:
        choice = int(input("\nSelect finding # to add note (0 to cancel): ").strip())
        if choice == 0:
            return

        finding = scanner.evidence_findings[choice - 1]
        print(f"\nFile: {finding['file_name']}")
        if finding['investigator_notes']:
            print(f"Current note: {finding['investigator_notes']}")

        note = input("\nEnter note: ").strip()
        if note:
            scanner.add_investigator_note(finding['file_path'], note)
            print("✅ Note added successfully")
    except (ValueError, IndexError):
        print("❌ Invalid selection")

    input("\nPress Enter to continue...")


def export_reports(scanner):
    """Export reports"""
    if not scanner.evidence_findings:
        print("\n⚠️  No findings yet. Please scan evidence first.")
        input("\nPress Enter to continue...")
        return

    clear_screen()
    print("\n📄 EXPORT REPORTS")
    print("="*80)

    output_dir = input("Enter output directory [./Case_Reports]: ").strip() or "./Case_Reports"

    print("\nExport format:")
    print("  1. All formats (JSON + CSV + TXT)")
    print("  2. JSON only (complete data)")
    print("  3. CSV only (spreadsheet)")
    print("  4. TXT only (court document)")

    format_choice = input("Choose format (1-4) [1]: ").strip() or "1"

    format_map = {'1': 'all', '2': 'json', '3': 'csv', '4': 'txt'}
    export_format = format_map.get(format_choice, 'all')

    scanner.export_for_court(output_dir, format=export_format)

    input("\nPress Enter to continue...")


def show_statistics(scanner):
    """Show case statistics"""
    clear_screen()
    print("\n📊 CASE STATISTICS")
    print("="*80)

    stats = scanner.get_summary_statistics()

    print(f"\nCase ID: {stats['case_id']}")
    print(f"Investigator: {scanner.scan_metadata['investigator']}")
    print(f"\nFiles Scanned: {stats['total_files_scanned']}")
    print(f"Files with IOCs: {stats['files_with_iocs']}")
    print(f"Total IOCs: {stats['total_iocs']}")

    print(f"\nSeverity Breakdown:")
    print(f"  🔴 Critical: {stats['severity_totals']['CRITICAL']}")
    print(f"  🟠 High: {stats['severity_totals']['HIGH']}")
    print(f"  🟡 Medium: {stats['severity_totals']['MEDIUM']}")
    print(f"  🟢 Low: {stats['severity_totals']['LOW']}")

    print(f"\nTop Threat Categories:")
    for category, count in stats['top_categories'][:5]:
        print(f"  • {category}: {count} files")

    print(f"\nEvidence Sources:")
    for source in stats['evidence_sources']:
        print(f"  • {source}")

    input("\nPress Enter to continue...")


def main_menu(scanner):
    """Main menu"""
    while True:
        clear_screen()
        print_banner()

        print(f"📋 Case: {scanner.case_id}")
        print(f"👤 Investigator: {scanner.scan_metadata['investigator']}")
        print(f"📊 Status: {scanner.scan_metadata['files_with_iocs']} files with IOCs, "
              f"{scanner.scan_metadata['total_iocs']} total IOCs")

        print("\n" + "="*80)
        print("MAIN MENU")
        print("="*80)
        print("1. 🔍 Scan Evidence Directory")
        print("2. 📊 View Current Findings")
        print("3. 📝 Add Investigator Notes")
        print("4. 📄 Export Reports (Court-Ready)")
        print("5. 📈 Show Case Statistics")
        print("6. 🔄 Start New Case")
        print("0. ❌ Exit")

        choice = input("\nYour choice (0-6): ").strip()

        if choice == "1":
            evidence_path, evidence_label = select_evidence()
            if evidence_path and os.path.exists(evidence_path):
                recursive, file_extensions, severity_filter = configure_scan_options()
                scanner.scan_evidence_directory(
                    evidence_path=evidence_path,
                    evidence_label=evidence_label,
                    recursive=recursive,
                    file_extensions=file_extensions,
                    severity_filter=severity_filter
                )
                input("\nPress Enter to continue...")
            else:
                print("❌ Invalid evidence path")
                input("\nPress Enter to continue...")

        elif choice == "2":
            view_findings(scanner)

        elif choice == "3":
            add_notes(scanner)

        elif choice == "4":
            export_reports(scanner)

        elif choice == "5":
            show_statistics(scanner)

        elif choice == "6":
            case_id = get_case_id()
            scanner = InvestigativeIOCScanner(case_id=case_id)

        elif choice == "0":
            print("\n✅ Thank you for using Investigative IOC Scanner")
            print("   Remember to export reports before closing!")
            sys.exit(0)


def main():
    """Main application entry point"""
    clear_screen()
    print_banner()

    case_id = get_case_id()
    scanner = InvestigativeIOCScanner(case_id=case_id)

    input("\nPress Enter to continue to main menu...")

    main_menu(scanner)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✅ Exiting... Remember to export your reports!")
        sys.exit(0)
