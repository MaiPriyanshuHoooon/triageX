"""
MFT File Recovery Tool - Interactive CLI
=========================================
Command-line interface for recovering deleted files from MFT analysis

Usage:
    python mft_recovery_tool.py <analyzer_state.pkl>

Example:
    python mft_recovery_tool.py mft_analyzer_state_2025-12-05_16-53-45.pkl

This tool allows you to:
    • List all deleted files from MFT analysis
    • Preview file content (hex dump + text)
    • Recover resident files directly from MFT
    • Export metadata to JSON
    • Filter by recoverability status

Author: Forensics Tool Team
Date: December 2025
"""

import sys
import os
import pickle
import json
from pathlib import Path


def print_banner():
    """Print tool banner"""
    print("=" * 70)
    print(" MFT FILE RECOVERY TOOL")
    print("=" * 70)
    print(" Interactive deleted file recovery from MFT analysis")
    print("=" * 70)
    print()


def list_deleted_files(analyzer, filter_status=None):
    """
    List all deleted files

    Args:
        analyzer: MFTAnalyzer instance
        filter_status: Filter by recoverability (FULL, PARTIAL, etc.)
    """

    deleted = [r for r in analyzer.mft_records.values() if r.is_deleted and not r.is_directory]

    if filter_status:
        deleted = [r for r in deleted if r.recoverability == filter_status]

    if not deleted:
        print("❌ No deleted files found matching criteria")
        return

    print(f"\n📁 DELETED FILES ({len(deleted)} total)\n")
    print(f"{'#':<8} {'Entry':<10} {'Filename':<35} {'Size':<12} {'Recovery':<12}")
    print("-" * 85)

    for idx, record in enumerate(deleted[:50], 1):  # Show first 50
        from core.ntfs_structures import format_filesize

        size_str = format_filesize(record.logical_size)
        filename = record.filename[:33] + ".." if len(record.filename) > 35 else record.filename

        recovery_icon = {
            'FULL': '✅',
            'PARTIAL': '⚠️',
            'METADATA_ONLY': '📋',
            'OVERWRITTEN': '❌'
        }.get(record.recoverability, '❓')

        print(f"{idx:<8} #{record.entry_number:<9} {filename:<35} {size_str:<12} {recovery_icon} {record.recoverability}")

    if len(deleted) > 50:
        print(f"\n... and {len(deleted) - 50} more files")

    print()


def recover_file_interactive(analyzer):
    """
    Interactive file recovery

    Args:
        analyzer: MFTAnalyzer instance
    """

    entry_str = input("Enter MFT entry number to recover: ").strip()

    try:
        entry_number = int(entry_str.replace('#', ''))
    except ValueError:
        print("❌ Invalid entry number")
        return

    if entry_number not in analyzer.mft_records:
        print(f"❌ Entry #{entry_number} not found")
        return

    record = analyzer.mft_records[entry_number]

    print(f"\n📄 File: {record.filename}")
    print(f"   Entry: #{record.entry_number}")
    print(f"   Size: {record.logical_size:,} bytes")
    print(f"   Status: {'Deleted' if record.is_deleted else 'Active'}")
    print(f"   Recoverability: {record.recoverability}")
    print(f"   Resident: {record.is_resident}")
    print()

    if not record.is_deleted:
        print("⚠️  File is still active (not deleted)")
        return

    if record.is_directory:
        print("❌ Cannot recover directory entries")
        return

    # Attempt recovery
    print("🔄 Attempting recovery...")

    success, message, content = analyzer.recover_file(entry_number)

    if success:
        output_file = f"recovered_{record.filename}"
        with open(output_file, 'wb') as f:
            f.write(content)

        print(f"✅ SUCCESS! File recovered:")
        print(f"   📁 Output: {output_file}")
        print(f"   📊 Size: {len(content):,} bytes")
        print()
    else:
        print(f"❌ Recovery failed: {message}")
        print()


def preview_file_interactive(analyzer):
    """
    Preview file content

    Args:
        analyzer: MFTAnalyzer instance
    """

    entry_str = input("Enter MFT entry number to preview: ").strip()

    try:
        entry_number = int(entry_str.replace('#', ''))
    except ValueError:
        print("❌ Invalid entry number")
        return

    print(f"\n🔍 Loading preview for entry #{entry_number}...")

    preview = analyzer.preview_file(entry_number)

    if not preview.get('success'):
        print(f"❌ {preview.get('error', 'Unknown error')}")
        return

    print("\n" + "=" * 70)
    print(f" FILE PREVIEW: {preview.get('filename', 'Unknown')}")
    print("=" * 70)
    print(f" Size: {preview.get('size_formatted', 'Unknown')}")
    print(f" Type: {'Text' if preview.get('is_text') else 'Binary'}")
    print("=" * 70)
    print()

    # Hex dump
    print("HEX DUMP (first 256 bytes):")
    print("-" * 70)
    hex_dump = preview.get('hex_dump', '')
    if hex_dump:
        # Format as 16 bytes per line
        hex_bytes = hex_dump.split()
        for i in range(0, min(len(hex_bytes), 256), 16):
            line = ' '.join(hex_bytes[i:i+16])
            print(f"{i:04x}:  {line}")
    print()

    # Text preview
    if preview.get('is_text'):
        print("TEXT PREVIEW:")
        print("-" * 70)
        text = preview.get('text_preview', '')[:500]  # First 500 chars
        print(text)
        if len(preview.get('text_preview', '')) > 500:
            print("\n... (truncated)")

    print()


def export_metadata_interactive(analyzer):
    """
    Export file metadata to JSON

    Args:
        analyzer: MFTAnalyzer instance
    """

    entry_str = input("Enter MFT entry number to export: ").strip()

    try:
        entry_number = int(entry_str.replace('#', ''))
    except ValueError:
        print("❌ Invalid entry number")
        return

    metadata = analyzer.export_metadata(entry_number)

    if not metadata:
        print(f"❌ Entry #{entry_number} not found")
        return

    output_file = f"mft_entry_{entry_number}_metadata.json"

    with open(output_file, 'w') as f:
        json.dump(metadata, indent=2, fp=f)

    print(f"\n✅ Metadata exported to: {output_file}")
    print(f"   Entry: #{entry_number}")
    print(f"   File: {metadata.get('filename', 'Unknown')}")
    print()


def main():
    """Main interactive loop"""

    print_banner()

    # Check arguments
    if len(sys.argv) < 2:
        print("❌ Error: Missing analyzer state file\n")
        print("Usage:")
        print(f"    python {sys.argv[0]} <analyzer_state.pkl>\n")
        print("Example:")
        print(f"    python {sys.argv[0]} mft_analyzer_state_2025-12-05_16-53-45.pkl\n")
        return

    analyzer_file = sys.argv[1]

    if not os.path.exists(analyzer_file):
        print(f"❌ Error: File not found: {analyzer_file}\n")
        return

    # Load analyzer
    print(f"📂 Loading MFT analyzer from: {analyzer_file}")

    try:
        with open(analyzer_file, 'rb') as f:
            analyzer = pickle.load(f)

        print(f"✅ Loaded successfully!")
        print(f"   Total MFT entries: {len(analyzer.mft_records):,}")
        print(f"   Deleted files: {sum(1 for r in analyzer.mft_records.values() if r.is_deleted and not r.is_directory):,}")
        print()

    except Exception as e:
        print(f"❌ Error loading analyzer: {str(e)}\n")
        return

    # Interactive menu loop
    while True:
        print("=" * 70)
        print(" MENU")
        print("=" * 70)
        print(" 1. List all deleted files")
        print(" 2. List recoverable files only (FULL + PARTIAL)")
        print(" 3. Recover a file")
        print(" 4. Preview file content")
        print(" 5. Export metadata to JSON")
        print(" 6. Exit")
        print("=" * 70)

        choice = input("\nSelect option (1-6): ").strip()

        if choice == '1':
            list_deleted_files(analyzer)

        elif choice == '2':
            deleted = [r for r in analyzer.mft_records.values() if r.is_deleted and not r.is_directory]
            recoverable = [r for r in deleted if r.recoverability in ['FULL', 'PARTIAL']]
            print(f"\n🔧 RECOVERABLE FILES ({len(recoverable)} of {len(deleted)} total deleted)\n")
            list_deleted_files(analyzer, filter_status=None)

        elif choice == '3':
            recover_file_interactive(analyzer)

        elif choice == '4':
            preview_file_interactive(analyzer)

        elif choice == '5':
            export_metadata_interactive(analyzer)

        elif choice == '6':
            print("\n👋 Goodbye!\n")
            break

        else:
            print("\n❌ Invalid option. Please select 1-6.\n")


if __name__ == '__main__':
    main()
