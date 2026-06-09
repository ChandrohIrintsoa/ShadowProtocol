"""
Dictionary Scanner - Advanced target detection and cleanup modes

Provides:
- Keyword-based binary scanning using user-provided dictionaries
- Deep binary analysis before any patching
- Mode A: Clean targets and logs
- Mode B: Radical cleanup (complete file erasure + deep caching)
"""

import re
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class ScanResult:
    """Result of a binary scan operation"""
    keyword: str
    offset: int
    context_before: bytes
    context_after: bytes
    binary_type: str
    confidence: float


class DictionaryScanner:
    """Scan binaries using keyword dictionaries with deep analysis"""

    def __init__(self, binary_path: str):
        """Initialize scanner for a binary file.

        Args:
            binary_path: Path to the binary file to scan
        """
        self.binary_path = Path(binary_path)
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        with open(binary_path, 'rb') as f:
            self.binary_data = f.read()

        self.binary_type = self._detect_binary_type()
        self.scan_results: List[ScanResult] = []

    def _detect_binary_type(self) -> str:
        """Detect the type of binary file.

        Returns:
            Type string: 'ELF', 'APK', 'DEX', 'SO', 'UNKNOWN'
        """
        if self.binary_data.startswith(b'\x7fELF'):
            return 'ELF'
        elif self.binary_data.startswith(b'PK\x03\x04'):
            if b'AndroidManifest.xml' in self.binary_data:
                return 'APK'
            return 'ZIP'
        elif self.binary_data.startswith(b'dex\n'):
            return 'DEX'
        elif b'.so' in self.binary_data[:100]:
            return 'SO'
        return 'UNKNOWN'

    def load_dictionary_from_file(self, dict_path: str) -> List[str]:
        """Load keywords from a dictionary file.

        Args:
            dict_path: Path to the .txt file with keywords

        Returns:
            List of keywords
        """
        if not Path(dict_path).exists():
            raise FileNotFoundError(f"Dictionary file not found: {dict_path}")

        with open(dict_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Parse keywords separated by commas or newlines
        keywords = re.split(r'[,\n]', content)
        return [k.strip() for k in keywords if k.strip()]

    def parse_manual_keywords(self, keywords_str: str) -> List[str]:
        """Parse manually entered keywords.

        Args:
            keywords_str: Comma-separated keywords from user input

        Returns:
            List of keywords
        """
        keywords = [k.strip() for k in keywords_str.split(',')]
        return [k for k in keywords if k]

    def _find_keyword_offsets(self, keyword: str) -> List[int]:
        """Find all offsets of a keyword in the binary.

        Args:
            keyword: Keyword to search for

        Returns:
            List of byte offsets
        """
        keyword_bytes = keyword.encode('utf-8')
        offsets = []
        start = 0

        while True:
            offset = self.binary_data.find(keyword_bytes, start)
            if offset == -1:
                break
            offsets.append(offset)
            start = offset + 1

        return offsets

    def _analyze_context(self, offset: int, context_size: int = 32) -> Dict:
        """Analyze the context around an offset.

        Args:
            offset: Byte offset to analyze
            context_size: Bytes to inspect before and after

        Returns:
            Analysis dictionary with context and metadata
        """
        start = max(0, offset - context_size)
        end = min(len(self.binary_data), offset + context_size)

        context_before = self.binary_data[start:offset]
        context_after = self.binary_data[offset:end]

        # Check for null bytes (boundary markers)
        has_null_before = b'\x00' in context_before[-8:]
        has_null_after = b'\x00' in context_after[:8]

        # Check for ASCII printable content
        is_ascii_before = all(32 <= b <= 126 or b in (9, 10, 13)
                               for b in context_before[-8:])
        is_ascii_after = all(32 <= b <= 126 or b in (9, 10, 13)
                             for b in context_after[:8])

        # Confidence score
        confidence = 0.0
        if has_null_before or has_null_after:
            confidence += 0.3
        if is_ascii_before or is_ascii_after:
            confidence += 0.2
        if offset > 64:  # Avoid header section
            confidence += 0.2
        if offset + len(self.binary_data) // 4 < len(self.binary_data):  # Safe zone
            confidence += 0.3

        return {
            'context_before': context_before,
            'context_after': context_after,
            'has_null_before': has_null_before,
            'has_null_after': has_null_after,
            'is_ascii_nearby': is_ascii_before or is_ascii_after,
            'confidence': min(confidence, 1.0)
        }

    def deep_scan(self, keywords: List[str]) -> Dict[str, List[ScanResult]]:
        """Perform deep binary scan WITHOUT modifying the file.

        Args:
            keywords: List of keywords to search for

        Returns:
            Dictionary mapping keywords to scan results
        """
        results = {}

        for keyword in keywords:
            offsets = self._find_keyword_offsets(keyword)
            keyword_results = []

            for offset in offsets:
                analysis = self._analyze_context(offset)

                scan_result = ScanResult(
                    keyword=keyword,
                    offset=offset,
                    context_before=analysis['context_before'],
                    context_after=analysis['context_after'],
                    binary_type=self.binary_type,
                    confidence=analysis['confidence']
                )

                keyword_results.append(scan_result)

            results[keyword] = keyword_results

        self.scan_results = [
            result for results_list in results.values()
            for result in results_list
        ]

        return results

    def get_scan_report(self) -> str:
        """Generate a human-readable scan report.

        Returns:
            Formatted scan report
        """
        if not self.scan_results:
            return "No scan results available"

        report = f"\n=== Deep Scan Report ===\n"
        report += f"Binary: {self.binary_path.name}\n"
        report += f"Type: {self.binary_type}\n"
        report += f"Size: {len(self.binary_data)} bytes\n"
        report += f"Total findings: {len(self.scan_results)}\n\n"

        # Group by keyword
        by_keyword = {}
        for result in self.scan_results:
            if result.keyword not in by_keyword:
                by_keyword[result.keyword] = []
            by_keyword[result.keyword].append(result)

        for keyword, results in by_keyword.items():
            report += f"\nKeyword: '{keyword}' ({len(results)} matches)\n"
            report += "-" * 40 + "\n"

            for i, result in enumerate(results, 1):
                report += f"  [{i}] Offset: 0x{result.offset:08x}\n"
                report += f"      Confidence: {result.confidence * 100:.1f}%\n"
                report += f"      Type: {result.binary_type}\n"

        return report


class CleanupManager:
    """Manage target cleanup in modes A and B"""

    def __init__(self, target_path: str):
        """Initialize cleanup manager.

        Args:
            target_path: Path to the target file
        """
        self.target_path = Path(target_path)
        self.target_dir = self.target_path.parent

    def mode_a_cleanup(self) -> bool:
        """Mode A: Clean target files and activity logs.

        Returns:
            True if successful
        """
        try:
            # Remove target file
            if self.target_path.exists():
                self.target_path.unlink()

            # Remove activity logs
            log_patterns = ['*.log', '.shadowprotocol_*', '*_session_*']
            for pattern in log_patterns:
                for log in self.target_dir.glob(pattern):
                    if log.is_file():
                        log.unlink(missing_ok=True)

            return True
        except Exception as e:
            print(f"Mode A cleanup error: {e}")
            return False

    def mode_b_cleanup(self) -> bool:
        """Mode B: Radical cleanup - complete erasure + deep cache removal.

        Removes:
        - Original target file
        - All related cache files
        - Activity logs
        - Temporary files
        - System metadata

        Returns:
            True if successful
        """
        try:
            # Stage 1: Remove target
            if self.target_path.exists():
                self.target_path.unlink()

            # Stage 2: Deep cache removal
            cache_patterns = [
                '*.pyc', '__pycache__',
                '.pytest_cache', '*.pyo',
                '.shadowprotocol_*', '*_session_*',
                '.cache', '*.tmp', '*.lock',
                '.DS_Store', 'Thumbs.db'
            ]

            for pattern in cache_patterns:
                for item in self.target_dir.glob(pattern):
                    try:
                        if item.is_dir():
                            import shutil
                            shutil.rmtree(item, ignore_errors=True)
                        else:
                            item.unlink(missing_ok=True)
                    except Exception:
                        pass

            # Stage 3: Remove activity logs
            log_extensions = ['.log', '.txt', '.tmp']
            for ext in log_extensions:
                for log in self.target_dir.glob(f'*{ext}'):
                    if log.name.startswith(('.shadowprotocol', 'activity',
                                           'session', 'scan', 'patch')):
                        try:
                            log.unlink(missing_ok=True)
                        except Exception:
                            pass

            # Stage 4: Verify cleanup
            remaining = list(self.target_dir.glob('*'))
            if self.target_path not in remaining:
                return True

            return False
        except Exception as e:
            print(f"Mode B cleanup error: {e}")
            return False

    def get_cleanup_report(self, mode: str) -> str:
        """Generate a cleanup report.

        Args:
            mode: 'A' or 'B'

        Returns:
            Cleanup report string
        """
        report = f"\n=== Cleanup Report (Mode {mode}) ===\n"
        report += f"Target: {self.target_path.name}\n"
        report += f"Directory: {self.target_dir}\n"

        if mode.upper() == 'A':
            report += "Actions: Remove target file and logs\n"
        elif mode.upper() == 'B':
            report += "Actions: Radical cleanup (all caches + logs + target)\n"

        return report
