"""
Advanced Utilities - Performance optimization and batch operations

Provides:
- Parallel scanning
- Result caching
- Batch operations
- Performance metrics
"""

import json
import time
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


class ScanCache:
    """Cache system for scan results to avoid redundant analysis"""

    def __init__(self, cache_dir: str = '.shadowprotocol_cache'):
        """Initialize cache system

        Args:
            cache_dir: Directory for cache storage
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

    def _get_cache_key(self, binary_path: str, keywords: List[str]) -> str:
        """Generate cache key from binary and keywords

        Args:
            binary_path: Path to binary
            keywords: List of keywords

        Returns:
            Cache key (hash)
        """
        with open(binary_path, 'rb') as f:
            binary_hash = hashlib.md5(f.read()).hexdigest()

        keywords_str = ','.join(sorted(keywords))
        key_data = f"{binary_hash}:{keywords_str}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def get(self, binary_path: str, keywords: List[str]) -> Optional[Dict]:
        """Retrieve cached results

        Args:
            binary_path: Path to binary
            keywords: List of keywords

        Returns:
            Cached results or None if not found
        """
        try:
            cache_key = self._get_cache_key(binary_path, keywords)
            cache_file = self.cache_dir / f"{cache_key}.json"

            if cache_file.exists():
                with open(cache_file) as f:
                    return json.load(f)
        except Exception:
            pass

        return None

    def set(self, binary_path: str, keywords: List[str], results: Dict) -> bool:
        """Store results in cache

        Args:
            binary_path: Path to binary
            keywords: List of keywords
            results: Results to cache

        Returns:
            True if successful
        """
        try:
            cache_key = self._get_cache_key(binary_path, keywords)
            cache_file = self.cache_dir / f"{cache_key}.json"

            with open(cache_file, 'w') as f:
                json.dump(results, f)
            return True
        except Exception:
            return False

    def clear(self) -> bool:
        """Clear all cached results

        Returns:
            True if successful
        """
        try:
            import shutil
            if self.cache_dir.exists():
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir()
            return True
        except Exception:
            return False


class ParallelScanner:
    """Parallel binary scanning for batch operations"""

    def __init__(self, max_workers: int = 4):
        """Initialize parallel scanner

        Args:
            max_workers: Number of parallel threads
        """
        self.max_workers = max_workers
        self.results = {}
        self.timings = {}

    def scan_batch(self, binaries: List[str], keywords: List[str],
                   progress_callback=None) -> Dict:
        """Scan multiple binaries in parallel

        Args:
            binaries: List of binary paths
            keywords: Keywords to search
            progress_callback: Optional progress callback

        Returns:
            Dictionary of results
        """
        from .dictionary_scanner import DictionaryScanner

        results = {}
        total = len(binaries)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}

            # Submit all tasks
            for binary_path in binaries:
                future = executor.submit(
                    self._scan_single,
                    binary_path,
                    keywords
                )
                futures[future] = binary_path

            # Collect results
            completed = 0
            for future in as_completed(futures):
                completed += 1
                binary_path = futures[future]

                try:
                    result = future.result()
                    results[binary_path] = result
                except Exception as e:
                    results[binary_path] = {'error': str(e)}

                if progress_callback:
                    progress_callback(completed, total)

        self.results = results
        return results

    def _scan_single(self, binary_path: str, keywords: List[str]) -> Dict:
        """Scan a single binary

        Args:
            binary_path: Path to binary
            keywords: Keywords to search

        Returns:
            Scan results
        """
        from .dictionary_scanner import DictionaryScanner

        start_time = time.time()

        try:
            scanner = DictionaryScanner(binary_path)
            results = scanner.deep_scan(keywords)
            elapsed = time.time() - start_time

            self.timings[binary_path] = elapsed

            return {
                'binary': binary_path,
                'binary_type': scanner.binary_type,
                'binary_size': len(scanner.binary_data),
                'scan_time': elapsed,
                'results': results,
                'status': 'success'
            }

        except Exception as e:
            return {
                'binary': binary_path,
                'status': 'error',
                'error': str(e)
            }

    def get_statistics(self) -> Dict:
        """Get performance statistics

        Returns:
            Statistics dictionary
        """
        if not self.results:
            return {}

        successful = sum(1 for r in self.results.values()
                        if r.get('status') == 'success')
        total = len(self.results)
        total_time = sum(self.timings.values())

        return {
            'total_scans': total,
            'successful': successful,
            'failed': total - successful,
            'total_time': total_time,
            'average_time': total_time / successful if successful > 0 else 0,
            'performance': 'Fast' if total_time < 10 else 'Moderate' if total_time < 30 else 'Slow'
        }


class TargetValidator:
    """Validate and filter binary targets"""

    @staticmethod
    def is_valid_binary(path: str) -> bool:
        """Check if file is a valid binary

        Args:
            path: Path to file

        Returns:
            True if valid binary
        """
        try:
            p = Path(path)
            if not p.exists() or not p.is_file():
                return False

            with open(p, 'rb') as f:
                magic = f.read(4)

            # Check magic bytes
            valid_magics = [
                b'\x7fELF',      # ELF
                b'PK\x03\x04',   # ZIP/APK
                b'dex\n',        # DEX
            ]

            return magic in valid_magics

        except Exception:
            return False

    @staticmethod
    def filter_binaries(directory: str, extensions: List[str] = None) -> List[str]:
        """Filter valid binaries in directory

        Args:
            directory: Path to scan
            extensions: File extensions to check (.so, .apk, etc)

        Returns:
            List of valid binary paths
        """
        if extensions is None:
            extensions = ['.so', '.apk', '.elf', '.bin', '.dex']

        valid_binaries = []
        dir_path = Path(directory)

        if not dir_path.is_dir():
            return []

        for binary_path in dir_path.rglob('*'):
            if binary_path.is_file():
                # Check extension
                if any(binary_path.name.endswith(ext) for ext in extensions):
                    if TargetValidator.is_valid_binary(str(binary_path)):
                        valid_binaries.append(str(binary_path))

        return valid_binaries


class ScanStatistics:
    """Comprehensive scan statistics and reporting"""

    def __init__(self):
        """Initialize statistics tracker"""
        self.scans = []
        self.start_time = None
        self.end_time = None

    def start_session(self):
        """Start a statistics session"""
        self.start_time = datetime.now()

    def end_session(self):
        """End statistics session"""
        self.end_time = datetime.now()

    def add_scan(self, binary: str, results: Dict, duration: float):
        """Add scan to statistics

        Args:
            binary: Binary path
            results: Scan results
            duration: Scan duration in seconds
        """
        total_matches = sum(len(m) for m in results.values())

        self.scans.append({
            'binary': binary,
            'total_matches': total_matches,
            'duration': duration,
            'timestamp': datetime.now().isoformat()
        })

    def generate_report(self) -> str:
        """Generate statistics report

        Returns:
            Formatted report string
        """
        if not self.scans:
            return "No scans recorded"

        report = "\n=== Scan Statistics Report ===\n"

        total_scans = len(self.scans)
        total_matches = sum(s['total_matches'] for s in self.scans)
        total_time = sum(s['duration'] for s in self.scans)
        avg_time = total_time / total_scans if total_scans > 0 else 0

        report += f"Total scans: {total_scans}\n"
        report += f"Total matches found: {total_matches}\n"
        report += f"Total time: {total_time:.2f}s\n"
        report += f"Average time per scan: {avg_time:.2f}s\n"

        if self.start_time and self.end_time:
            session_time = (self.end_time - self.start_time).total_seconds()
            report += f"Session duration: {session_time:.2f}s\n"

        return report

    def export_json(self, output_file: str) -> bool:
        """Export statistics to JSON

        Args:
            output_file: Output file path

        Returns:
            True if successful
        """
        try:
            with open(output_file, 'w') as f:
                json.dump(self.scans, f, indent=2)
            return True
        except Exception:
            return False


class BinarySignatureBuilder:
    """Build custom binary signatures for targeting"""

    @staticmethod
    def extract_signature(binary_path: str, offset: int, length: int = 16) -> str:
        """Extract signature from binary at offset

        Args:
            binary_path: Path to binary
            offset: Byte offset
            length: Signature length

        Returns:
            Hex string of signature
        """
        try:
            with open(binary_path, 'rb') as f:
                f.seek(offset)
                data = f.read(length)
                return data.hex()
        except Exception:
            return ""

    @staticmethod
    def find_similar_offsets(binary_path: str, signature: str,
                            threshold: float = 0.8) -> List[int]:
        """Find offsets with similar patterns

        Args:
            binary_path: Path to binary
            signature: Hex signature to match
            threshold: Similarity threshold (0-1)

        Returns:
            List of matching offsets
        """
        try:
            sig_bytes = bytes.fromhex(signature)
            with open(binary_path, 'rb') as f:
                data = f.read()

            matches = []
            for i in range(len(data) - len(sig_bytes) + 1):
                chunk = data[i:i + len(sig_bytes)]
                if chunk == sig_bytes:
                    matches.append(i)

            return matches
        except Exception:
            return []
