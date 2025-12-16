"""
File Recovery Assessment Module
================================
Evaluates recoverability of deleted files using $Bitmap analysis

This module provides advanced recovery assessment:
- Analyzes NTFS $Bitmap to check cluster allocation
- Determines if data clusters are free or overwritten
- Calculates recovery probability percentage
- Categorizes files: FULL, PARTIAL, METADATA_ONLY, OVERWRITTEN
- Provides guidance for recovery tools

Recovery Categories:
- FULL: All clusters free, 100% recoverable
- PARTIAL: Some clusters free, partial data recoverable
- METADATA_ONLY: All clusters overwritten, only metadata available
- OVERWRITTEN: Clusters reallocated, no recovery possible

Author: Forensics Tool Team
Date: December 2025
"""

from typing import List, Tuple, Optional
from enum import Enum


class RecoveryStatus(Enum):
    """File recovery status categories"""
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    METADATA_ONLY = "METADATA_ONLY"
    OVERWRITTEN = "OVERWRITTEN"
    UNKNOWN = "UNKNOWN"


class RecoveryAssessment:
    """
    Result of file recovery assessment
    """

    def __init__(self):
        self.status = RecoveryStatus.UNKNOWN
        self.recovery_percentage = 0.0
        self.free_clusters = 0
        self.used_clusters = 0
        self.total_clusters = 0
        self.is_resident = False
        self.recommendations = []

    def __str__(self):
        return f"{self.status.value} ({self.recovery_percentage:.1f}%)"


class BitmapAnalyzer:
    """
    Analyzes NTFS $Bitmap to determine cluster allocation status
    """

    def __init__(self):
        self.bitmap = None
        self.cluster_size = 4096  # Default NTFS cluster size (4KB)
        self.total_clusters = 0

    def load_bitmap(self, bitmap_data: bytes):
        """
        Load $Bitmap data

        Args:
            bitmap_data: Raw $Bitmap data (each bit represents cluster status)
        """
        self.bitmap = bitmap_data
        self.total_clusters = len(bitmap_data) * 8

    def is_cluster_allocated(self, cluster_num: int) -> bool:
        """
        Check if a cluster is allocated (in use)

        Args:
            cluster_num: Cluster number to check

        Returns:
            True if cluster is allocated, False if free
        """

        if not self.bitmap or cluster_num < 0:
            return True  # Assume allocated if unknown

        byte_offset = cluster_num // 8
        bit_offset = cluster_num % 8

        if byte_offset >= len(self.bitmap):
            return True  # Out of range, assume allocated

        # Check bit (1 = allocated, 0 = free)
        byte_value = self.bitmap[byte_offset]
        return bool(byte_value & (1 << bit_offset))

    def get_cluster_run_status(self, start_cluster: int, cluster_count: int) -> Tuple[int, int]:
        """
        Check allocation status for a range of clusters

        Args:
            start_cluster: Starting cluster number
            cluster_count: Number of clusters to check

        Returns:
            Tuple of (free_count, allocated_count)
        """

        free_count = 0
        allocated_count = 0

        for i in range(cluster_count):
            cluster = start_cluster + i

            if self.is_cluster_allocated(cluster):
                allocated_count += 1
            else:
                free_count += 1

        return free_count, allocated_count


class FileRecoveryEvaluator:
    """
    Evaluates recoverability of deleted files
    """

    def __init__(self, bitmap_analyzer: Optional[BitmapAnalyzer] = None):
        """
        Initialize recovery evaluator

        Args:
            bitmap_analyzer: Optional BitmapAnalyzer instance
        """
        self.bitmap_analyzer = bitmap_analyzer

    def assess_file(self, is_resident: bool, data_runs: List[Tuple[int, int]],
                   file_size: int = 0) -> RecoveryAssessment:
        """
        Assess recoverability of a deleted file

        Args:
            is_resident: True if file data is stored in MFT record itself
            data_runs: List of (cluster_offset, cluster_count) tuples
            file_size: Logical file size in bytes

        Returns:
            RecoveryAssessment object
        """

        assessment = RecoveryAssessment()

        # Case 1: Resident file (stored in MFT)
        if is_resident:
            assessment.status = RecoveryStatus.FULL
            assessment.recovery_percentage = 100.0
            assessment.is_resident = True
            assessment.recommendations = [
                "File data is resident in MFT record",
                "Fully recoverable by extracting MFT content",
                "Use MFT parser or forensic tools"
            ]
            return assessment

        # Case 2: No data runs (file was deleted and clusters freed)
        if not data_runs or len(data_runs) == 0:
            assessment.status = RecoveryStatus.METADATA_ONLY
            assessment.recovery_percentage = 0.0
            assessment.recommendations = [
                "No cluster allocation information available",
                "Only file metadata can be recovered",
                "File content is not recoverable"
            ]
            return assessment

        # Case 3: Has data runs - check cluster allocation
        if self.bitmap_analyzer and self.bitmap_analyzer.bitmap:
            # Full $Bitmap analysis available
            total_clusters = 0
            free_clusters = 0

            for cluster_offset, cluster_count in data_runs:
                free, allocated = self.bitmap_analyzer.get_cluster_run_status(
                    cluster_offset, cluster_count
                )
                free_clusters += free
                total_clusters += cluster_count

            assessment.free_clusters = free_clusters
            assessment.used_clusters = total_clusters - free_clusters
            assessment.total_clusters = total_clusters

            # Calculate recovery percentage
            if total_clusters > 0:
                assessment.recovery_percentage = (free_clusters / total_clusters) * 100.0

            # Determine recovery status
            if assessment.recovery_percentage == 100.0:
                assessment.status = RecoveryStatus.FULL
                assessment.recommendations = [
                    "All data clusters are free",
                    "File is fully recoverable",
                    "Use file recovery tools (PhotoRec, TestDisk, Recuva)"
                ]

            elif assessment.recovery_percentage > 50.0:
                assessment.status = RecoveryStatus.PARTIAL
                assessment.recommendations = [
                    f"Approximately {assessment.recovery_percentage:.0f}% of data is recoverable",
                    "Some clusters have been overwritten",
                    "Partial file recovery possible",
                    "Recovered file may be incomplete or corrupted"
                ]

            elif assessment.recovery_percentage > 0.0:
                assessment.status = RecoveryStatus.PARTIAL
                assessment.recommendations = [
                    f"Only {assessment.recovery_percentage:.0f}% of data remains",
                    "Most clusters have been overwritten",
                    "Limited recovery possible",
                    "Recovered data likely incomplete"
                ]

            else:
                assessment.status = RecoveryStatus.OVERWRITTEN
                assessment.recommendations = [
                    "All data clusters have been overwritten",
                    "File content is not recoverable",
                    "Only metadata available"
                ]

        else:
            # No $Bitmap analysis - use heuristic
            assessment.status = RecoveryStatus.PARTIAL
            assessment.recovery_percentage = 50.0  # Unknown, assume 50%
            assessment.total_clusters = sum(count for _, count in data_runs)
            assessment.recommendations = [
                "Cluster allocation status unknown ($Bitmap not analyzed)",
                "File has data run information",
                "Recovery may be possible",
                "Run full forensic recovery to assess actual recoverability",
                "Recommended tools: Autopsy, FTK Imager, X-Ways Forensics"
            ]

        return assessment

    def batch_assess(self, files: List[dict]) -> List[RecoveryAssessment]:
        """
        Assess recoverability for multiple files

        Args:
            files: List of file dictionaries with keys:
                   is_resident, data_runs, file_size

        Returns:
            List of RecoveryAssessment objects
        """

        assessments = []

        for file_info in files:
            assessment = self.assess_file(
                is_resident=file_info.get('is_resident', False),
                data_runs=file_info.get('data_runs', []),
                file_size=file_info.get('file_size', 0)
            )
            assessments.append(assessment)

        return assessments

    def get_recovery_statistics(self, assessments: List[RecoveryAssessment]) -> dict:
        """
        Calculate statistics from recovery assessments

        Args:
            assessments: List of RecoveryAssessment objects

        Returns:
            Dictionary of statistics
        """

        stats = {
            'total_files': len(assessments),
            'full_recovery': 0,
            'partial_recovery': 0,
            'metadata_only': 0,
            'overwritten': 0,
            'unknown': 0,
            'average_recovery_pct': 0.0
        }

        total_pct = 0.0

        for assessment in assessments:
            if assessment.status == RecoveryStatus.FULL:
                stats['full_recovery'] += 1
            elif assessment.status == RecoveryStatus.PARTIAL:
                stats['partial_recovery'] += 1
            elif assessment.status == RecoveryStatus.METADATA_ONLY:
                stats['metadata_only'] += 1
            elif assessment.status == RecoveryStatus.OVERWRITTEN:
                stats['overwritten'] += 1
            else:
                stats['unknown'] += 1

            total_pct += assessment.recovery_percentage

        if stats['total_files'] > 0:
            stats['average_recovery_pct'] = total_pct / stats['total_files']

        return stats


def get_recovery_badge_color(recovery_status: str) -> str:
    """
    Get CSS badge color for recovery status

    Args:
        recovery_status: Recovery status string

    Returns:
        CSS class name for badge
    """

    status_colors = {
        'FULL': 'badge-green',
        'PARTIAL': 'badge-orange',
        'METADATA_ONLY': 'badge-gray',
        'OVERWRITTEN': 'badge-red',
        'UNKNOWN': 'badge-gray'
    }

    return status_colors.get(recovery_status, 'badge-gray')


def get_recovery_icon(recovery_status: str) -> str:
    """
    Get icon for recovery status

    Args:
        recovery_status: Recovery status string

    Returns:
        Emoji icon
    """

    status_icons = {
        'FULL': '✅',
        'PARTIAL': '⚠️',
        'METADATA_ONLY': '📋',
        'OVERWRITTEN': '❌',
        'UNKNOWN': '❓'
    }

    return status_icons.get(recovery_status, '❓')
