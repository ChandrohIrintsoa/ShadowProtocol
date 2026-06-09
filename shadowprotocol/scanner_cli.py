"""
Dictionary Scanner CLI - Command-line interface for advanced binary scanning

Provides:
- Interactive CLI for dictionary-based scanning
- Results export (JSON, CSV, TXT)
- Batch operations
- Performance statistics
"""

import json
import csv
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

from .dictionary_scanner import DictionaryScanner, CleanupManager, ScanResult
from .file_manager import FileManager


class DictionaryScannerCLI:
    """Interactive CLI for dictionary scanning operations"""

    def __init__(self):
        """Initialize CLI"""
        self.last_results = None
        self.last_binary = None
        self.last_keywords = None

    def interactive_scan(self):
        """Run interactive scan workflow"""
        print("\n" + "=" * 70)
        print(" Dictionary Scanner - Interactive Mode")
        print("=" * 70)

        # Step 1: Select target
        target = self._select_target()
        if not target:
            print("[!] No target selected")
            return False

        # Step 2: Load/enter keywords
        keywords = self._get_keywords()
        if not keywords:
            print("[!] No keywords provided")
            return False

        # Step 3: Run scan
        print(f"\n[*] Scanning {Path(target).name}...")
        try:
            scanner = DictionaryScanner(target)
            self.last_scanner = scanner
            self.last_keywords = keywords

            results = scanner.deep_scan(keywords)
            self.last_results = results

            # Step 4: Display results
            print(scanner.get_scan_report())

            # Step 5: Offer export
            self._offer_export(scanner, results)

            # Step 6: Offer cleanup
            self._offer_cleanup(target)

            return True

        except Exception as e:
            print(f"[!] Scan error: {e}")
            return False

    def _select_target(self) -> Optional[str]:
        """Select binary target"""
        print("\n[*] Select target binary:")
        print("  [1] Specify path manually")
        print("  [2] Auto-detect in directory")

        choice = input("\nChoice [1-2]: ").strip()

        if choice == '1':
            path = input("Enter binary path: ").strip()
            if Path(path).exists():
                return path
            print("[!] File not found")
            return None

        elif choice == '2':
            dir_path = input("Enter directory path: ").strip()
            if not Path(dir_path).exists():
                print("[!] Directory not found")
                return None

            targets = FileManager.find_targets_in_path(dir_path)
            if not targets:
                print("[!] No targets found")
                return None

            return FileManager.select_target(targets)

        return None

    def _get_keywords(self) -> Optional[List[str]]:
        """Get keywords from user"""
        print("\n[*] Load keywords:")
        print("  [1] From file (keywords.txt)")
        print("  [2] Manual input (comma-separated)")

        choice = input("\nChoice [1-2]: ").strip()

        try:
            if choice == '1':
                dict_path = input("Dictionary file path: ").strip()
                scanner = DictionaryScanner.__new__(DictionaryScanner)
                return scanner.load_dictionary_from_file(dict_path)

            elif choice == '2':
                keywords_str = input("Enter keywords (comma-separated): ").strip()
                scanner = DictionaryScanner.__new__(DictionaryScanner)
                return scanner.parse_manual_keywords(keywords_str)

        except Exception as e:
            print(f"[!] Error loading keywords: {e}")
            return None

        return None

    def _offer_export(self, scanner: DictionaryScanner, results: Dict):
        """Offer to export results"""
        print("\n[*] Export results?")
        print("  [1] JSON")
        print("  [2] CSV")
        print("  [3] TXT")
        print("  [4] Skip")

        choice = input("\nChoice [1-4]: ").strip()

        if choice == '1':
            self._export_json(scanner, results)
        elif choice == '2':
            self._export_csv(results)
        elif choice == '3':
            self._export_txt(scanner, results)

    def _export_json(self, scanner: DictionaryScanner, results: Dict):
        """Export results to JSON"""
        output = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'binary': scanner.binary_path.name,
                'binary_type': scanner.binary_type,
                'binary_size': len(scanner.binary_data)
            },
            'results': {}
        }

        for keyword, matches in results.items():
            output['results'][keyword] = [
                {
                    'offset': f'0x{m.offset:08x}',
                    'confidence': f'{m.confidence * 100:.1f}%',
                    'type': m.binary_type
                }
                for m in matches
            ]

        filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)

        print(f"[+] Exported to {filename}")

    def _export_csv(self, results: Dict):
        """Export results to CSV"""
        filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Keyword', 'Offset (hex)', 'Offset (dec)', 'Confidence (%)'])

            for keyword, matches in results.items():
                for match in matches:
                    writer.writerow([
                        keyword,
                        f'0x{match.offset:08x}',
                        match.offset,
                        f'{match.confidence * 100:.1f}'
                    ])

        print(f"[+] Exported to {filename}")

    def _export_txt(self, scanner: DictionaryScanner, results: Dict):
        """Export results to TXT"""
        filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        with open(filename, 'w') as f:
            f.write(scanner.get_scan_report())

        print(f"[+] Exported to {filename}")

    def _offer_cleanup(self, target: str):
        """Offer cleanup options"""
        print("\n[*] Cleanup options:")
        print("  [1] Mode A (simple clean)")
        print("  [2] Mode B (radical clean)")
        print("  [3] Skip cleanup")

        choice = input("\nChoice [1-3]: ").strip()

        if choice == '1':
            cleanup = CleanupManager(target)
            if cleanup.mode_a_cleanup():
                print("[+] Mode A cleanup completed")
            else:
                print("[!] Mode A cleanup failed")

        elif choice == '2':
            print("\n[!] Mode B performs RADICAL cleanup")
            confirm = input("Continue? (yes/no): ").strip().lower()
            if confirm == 'yes':
                cleanup = CleanupManager(target)
                if cleanup.mode_b_cleanup():
                    print("[+] Mode B cleanup completed")
                else:
                    print("[!] Mode B cleanup failed")

    def batch_scan(self, targets: List[str], keywords: List[str]) -> Dict:
        """Scan multiple targets with same keywords

        Args:
            targets: List of binary paths
            keywords: List of keywords to search

        Returns:
            Results dictionary
        """
        batch_results = {}

        for target in targets:
            try:
                print(f"\n[*] Scanning {Path(target).name}...")
                scanner = DictionaryScanner(target)
                results = scanner.deep_scan(keywords)
                batch_results[target] = results

            except Exception as e:
                print(f"[!] Error scanning {target}: {e}")
                batch_results[target] = None

        return batch_results

    def statistics(self) -> Dict:
        """Get statistics from last scan

        Returns:
            Statistics dictionary
        """
        if not self.last_results:
            return {}

        stats = {
            'total_keywords': len(self.last_results),
            'total_matches': sum(len(m) for m in self.last_results.values()),
            'keywords_with_matches': sum(1 for m in self.last_results.values() if m),
            'keywords_without_matches': sum(1 for m in self.last_results.values() if not m),
            'average_confidence': 0.0
        }

        all_matches = [m for matches in self.last_results.values() for m in matches]
        if all_matches:
            avg_conf = sum(m.confidence for m in all_matches) / len(all_matches)
            stats['average_confidence'] = f'{avg_conf * 100:.1f}%'

        return stats


class ResultsExporter:
    """Export scanning results in various formats"""

    @staticmethod
    def to_json(results: Dict, output_file: str, metadata: Optional[Dict] = None):
        """Export to JSON format"""
        output = {'metadata': metadata or {}, 'results': {}}

        for keyword, matches in results.items():
            output['results'][keyword] = [
                {
                    'offset': f'0x{m.offset:08x}',
                    'confidence': m.confidence,
                    'type': m.binary_type
                }
                for m in matches
            ]

        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)

    @staticmethod
    def to_csv(results: Dict, output_file: str):
        """Export to CSV format"""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Keyword', 'Offset (hex)', 'Offset (dec)', 'Confidence (%)'])

            for keyword, matches in results.items():
                for match in matches:
                    writer.writerow([
                        keyword,
                        f'0x{match.offset:08x}',
                        match.offset,
                        f'{match.confidence * 100:.1f}'
                    ])

    @staticmethod
    def to_html(results: Dict, scanner: DictionaryScanner, output_file: str):
        """Export to HTML format"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Scan Report - {scanner.binary_path.name}</title>
    <style>
        body {{ font-family: monospace; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        .high {{ color: green; }}
        .medium {{ color: orange; }}
        .low {{ color: red; }}
    </style>
</head>
<body>
    <h1>Binary Scan Report</h1>
    <p><strong>Binary:</strong> {scanner.binary_path.name}</p>
    <p><strong>Type:</strong> {scanner.binary_type}</p>
    <p><strong>Size:</strong> {len(scanner.binary_data)} bytes</p>
    <p><strong>Timestamp:</strong> {datetime.now().isoformat()}</p>

    <h2>Results</h2>
    <table>
        <tr>
            <th>Keyword</th>
            <th>Offset</th>
            <th>Confidence</th>
            <th>Type</th>
        </tr>
"""

        for keyword, matches in results.items():
            for match in matches:
                conf_pct = match.confidence * 100
                conf_class = 'high' if conf_pct >= 80 else 'medium' if conf_pct >= 50 else 'low'
                html += f"""        <tr>
            <td>{keyword}</td>
            <td>0x{match.offset:08x}</td>
            <td class="{conf_class}">{conf_pct:.1f}%</td>
            <td>{match.binary_type}</td>
        </tr>
"""

        html += """    </table>
</body>
</html>"""

        with open(output_file, 'w') as f:
            f.write(html)
