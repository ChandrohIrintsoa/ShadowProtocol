"""
Keyword Analyzer - Binary target detection via keyword dictionary
Analyzes binary signatures to find safe injection points without blind patching.
"""

import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple


class KeywordDictionary:
    """Manage keyword dictionary for binary targeting"""

    def __init__(self, dict_file: Optional[str] = None):
        """Initialize keyword dictionary.

        Args:
            dict_file: Path to .txt file with keywords (comma-separated)
        """
        self.keywords: List[str] = []
        if dict_file and Path(dict_file).exists():
            self.load_from_file(dict_file)

    def load_from_file(self, path: str) -> bool:
        """Load keywords from .txt file.

        Format:
        - Comma-separated: "keyword1", "keyword2", "keyword3"
        - Or one per line: keyword1\\nkeyword2\\nkeyword3

        Args:
            path: Path to .txt file

        Returns:
            True if loaded successfully
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Try comma-separated first
            if ',' in content:
                self.keywords = [kw.strip().strip('"\'') for kw in content.split(',')]
            else:
                self.keywords = [kw.strip() for kw in content.splitlines() if kw.strip()]

            return len(self.keywords) > 0
        except Exception:
            return False

    def add_keyword(self, keyword: str) -> None:
        """Add a keyword manually.

        Args:
            keyword: Keyword to add
        """
        if keyword and keyword not in self.keywords:
            self.keywords.append(keyword.strip())

    def remove_keyword(self, keyword: str) -> None:
        """Remove a keyword.

        Args:
            keyword: Keyword to remove
        """
        self.keywords = [kw for kw in self.keywords if kw != keyword]

    def save_to_file(self, path: str) -> bool:
        """Save keywords to .txt file.

        Args:
            path: Path to save

        Returns:
            True if saved successfully
        """
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(', '.join(f'"{kw}"' for kw in self.keywords))
            return True
        except Exception:
            return False

    def get_keywords(self) -> List[str]:
        """Get all keywords.

        Returns:
            List of keywords
        """
        return self.keywords.copy()


class BinaryAnalyzer:
    """Deep binary analysis for safe targeting"""

    def __init__(self, binary_path: str):
        """Initialize analyzer for binary.

        Args:
            binary_path: Path to binary file
        """
        self.binary_path = Path(binary_path)
        self.binary_data = None
        self._load_binary()

    def _load_binary(self) -> bool:
        """Load binary file into memory.

        Returns:
            True if loaded successfully
        """
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
            return len(self.binary_data) > 0
        except Exception:
            return False

    def find_keyword_offsets(self, keyword: str) -> List[int]:
        """Find all occurrences of keyword in binary.

        Args:
            keyword: Keyword to search (string or hex pattern)

        Returns:
            List of offsets where keyword is found
        """
        if not self.binary_data:
            return []

        offsets = []
        try:
            # Try as UTF-8 string
            keyword_bytes = keyword.encode('utf-8', errors='ignore')
        except Exception:
            return []

        # Find all occurrences
        start = 0
        while True:
            pos = self.binary_data.find(keyword_bytes, start)
            if pos == -1:
                break
            offsets.append(pos)
            start = pos + 1

        return offsets

    def analyze_context(self, offset: int, context_size: int = 64) -> Dict:
        """Analyze binary context around offset.

        Args:
            offset: Offset to analyze
            context_size: Bytes to read before/after

        Returns:
            Dict with context analysis
        """
        if not self.binary_data or offset < 0:
            return {}

        start = max(0, offset - context_size)
        end = min(len(self.binary_data), offset + context_size)

        context = self.binary_data[start:end]
        before = self.binary_data[max(0, offset - 16):offset]
        after = self.binary_data[offset:min(len(self.binary_data), offset + 16)]

        return {
            'offset': offset,
            'context': context.hex(),
            'before': before.hex(),
            'after': after.hex(),
            'size': len(context),
            'is_valid': self._validate_offset(offset)
        }

    def _validate_offset(self, offset: int) -> bool:
        """Validate if offset is safe for patching.

        Checks:
        - Not in header regions
        - Not in ELF magic bytes
        - Has sufficient context

        Args:
            offset: Offset to validate

        Returns:
            True if offset appears safe
        """
        if not self.binary_data:
            return False

        # Check bounds
        if offset < 64 or offset >= len(self.binary_data) - 8:
            return False

        # Check if in ELF header
        if offset < 64 and self.binary_data[:4] == b'\x7fELF':
            return False

        # Check for minimal context
        return offset + 8 <= len(self.binary_data)

    def scan_for_safe_patches(self, keyword: str,
                             min_context: int = 8) -> List[Dict]:
        """Scan binary for safe patch points around keyword.

        Args:
            keyword: Keyword to search for
            min_context: Minimum bytes needed around offset

        Returns:
            List of safe patch candidates with metadata
        """
        offsets = self.find_keyword_offsets(keyword)
        safe_patches = []

        for offset in offsets:
            analysis = self.analyze_context(offset)
            if analysis.get('is_valid'):
                safe_patches.append({
                    'keyword': keyword,
                    'offset': offset,
                    'analysis': analysis,
                    'status': 'SAFE'
                })

        return safe_patches

    def deep_scan(self, keywords: List[str]) -> Dict[str, List[Dict]]:
        """Perform deep scan of binary with multiple keywords.

        Does NOT patch - only analyzes and reports findings.

        Args:
            keywords: List of keywords to search

        Returns:
            Dict mapping keywords to list of safe patch points
        """
        results = {}
        for keyword in keywords:
            results[keyword] = self.scan_for_safe_patches(keyword)

        return results

    def get_binary_info(self) -> Dict:
        """Get binary file information.

        Returns:
            Dict with file metadata
        """
        if not self.binary_data:
            return {}

        is_elf = self.binary_data[:4] == b'\x7fELF'
        is_zip = self.binary_data[:2] == b'PK'

        return {
            'path': str(self.binary_path),
            'size': len(self.binary_data),
            'is_elf': is_elf,
            'is_apk': is_zip,
            'header': self.binary_data[:16].hex()
        }

    def verify_patch_safety(self, offset: int, patch_size: int) -> bool:
        """Verify if patch at offset is safe.

        Args:
            offset: Patch offset
            patch_size: Size of patch

        Returns:
            True if safe to patch
        """
        if not self.binary_data:
            return False

        # Check bounds
        if offset < 0 or offset + patch_size > len(self.binary_data):
            return False

        # Check not in critical regions
        if offset < 64 and self.binary_data[:4] == b'\x7fELF':
            return False

        # Verify context exists
        return self._validate_offset(offset)
