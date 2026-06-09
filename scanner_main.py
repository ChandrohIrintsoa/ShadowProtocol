#!/usr/bin/env python3
"""
ShadowProtocol Dictionary Scanner - Main CLI Interface

Advanced binary scanning with dictionary-based keyword detection,
batch operations, and comprehensive reporting.

Usage:
    python3 scanner_main.py --binary <path> --dict <keywords.txt>
    python3 scanner_main.py --batch <directory> --keywords "key1,key2"
    python3 scanner_main.py --interactive
"""

import sys
import argparse
import json
from pathlib import Path

# Add shadowprotocol to path
sys.path.insert(0, str(Path(__file__).parent))

from shadowprotocol.dictionary_scanner import DictionaryScanner, CleanupManager
from shadowprotocol.scanner_cli import DictionaryScannerCLI, ResultsExporter
from shadowprotocol.advanced_utils import (
    ParallelScanner, TargetValidator, ScanStatistics, ScanCache
)


def cmd_scan(args):
    """Single binary scan"""
    if not Path(args.binary).exists():
        print(f"[!] Binary not found: {args.binary}")
        return False

    print(f"\n[*] Scanning: {args.binary}")

    try:
        scanner = DictionaryScanner(args.binary)
        print(f"[+] Binary type: {scanner.binary_type}")
        print(f"[+] Size: {len(scanner.binary_data)} bytes")

        # Get keywords
        if args.dict:
            keywords = scanner.load_dictionary_from_file(args.dict)
            print(f"[+] Loaded {len(keywords)} keywords from {args.dict}")
        elif args.keywords:
            keywords = scanner.parse_manual_keywords(args.keywords)
            print(f"[+] Parsed {len(keywords)} keywords")
        else:
            print("[!] No keywords provided")
            return False

        # Scan
        print("[*] Scanning...")
        results = scanner.deep_scan(keywords)

        # Report
        print(scanner.get_scan_report())

        # Export if requested
        if args.output:
            if args.output.endswith('.json'):
                ResultsExporter.to_json(
                    results, args.output,
                    metadata={'binary': args.binary, 'type': scanner.binary_type}
                )
            elif args.output.endswith('.csv'):
                ResultsExporter.to_csv(results, args.output)
            elif args.output.endswith('.html'):
                ResultsExporter.to_html(results, scanner, args.output)

            print(f"[+] Results exported to {args.output}")

        # Cleanup if requested
        if args.cleanup:
            cleanup = CleanupManager(args.binary)
            if args.cleanup.upper() == 'A':
                if cleanup.mode_a_cleanup():
                    print("[+] Mode A cleanup completed")
            elif args.cleanup.upper() == 'B':
                if cleanup.mode_b_cleanup():
                    print("[+] Mode B cleanup completed")

        return True

    except Exception as e:
        print(f"[!] Error: {e}")
        return False


def cmd_batch(args):
    """Batch scanning of multiple binaries"""
    # Find binaries
    binaries = TargetValidator.filter_binaries(args.batch)
    if not binaries:
        print(f"[!] No valid binaries found in {args.batch}")
        return False

    print(f"[*] Found {len(binaries)} binaries to scan")

    # Get keywords
    if args.dict:
        scanner = DictionaryScanner.__new__(DictionaryScanner)
        keywords = scanner.load_dictionary_from_file(args.dict)
    elif args.keywords:
        keywords = args.keywords.split(',')
    else:
        print("[!] No keywords provided")
        return False

    # Parallel scan
    print(f"[*] Starting batch scan with {args.workers} workers...")
    parallel = ParallelScanner(max_workers=args.workers)

    def progress(done, total):
        pct = (done / total) * 100
        print(f"  Progress: {done}/{total} ({pct:.0f}%)")

    results = parallel.scan_batch(binaries, keywords, progress)

    # Statistics
    stats = parallel.get_statistics()
    print(f"\n[+] Scan completed:")
    print(f"    Successful: {stats['successful']}/{stats['total_scans']}")
    print(f"    Total time: {stats['total_time']:.2f}s")
    print(f"    Avg time: {stats['average_time']:.2f}s")

    # Export
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results exported to {args.output}")

    return True


def cmd_interactive(args):
    """Interactive mode"""
    cli = DictionaryScannerCLI()
    return cli.interactive_scan()


def cmd_cleanup(args):
    """Execute cleanup operations"""
    if not Path(args.target).exists():
        print(f"[!] Target not found: {args.target}")
        return False

    cleanup = CleanupManager(args.target)

    mode = args.mode.upper()
    if mode == 'A':
        print("[*] Mode A cleanup (logs/cache)...")
        success = cleanup.mode_a_cleanup()
    elif mode == 'B':
        print("[!] RADICAL cleanup (everything)...")
        success = cleanup.mode_b_cleanup()
    else:
        print(f"[!] Unknown mode: {mode}")
        return False

    if success:
        print(f"[+] Cleanup Mode {mode} completed")
    else:
        print(f"[!] Cleanup failed")

    return success


def cmd_validate(args):
    """Validate binaries in directory"""
    binaries = TargetValidator.filter_binaries(args.directory)

    if not binaries:
        print(f"[!] No valid binaries found in {args.directory}")
        return False

    print(f"\n[+] Found {len(binaries)} valid binaries:\n")
    for binary in sorted(binaries):
        size = Path(binary).stat().st_size
        size_mb = size / (1024 * 1024)
        print(f"  {binary} ({size_mb:.2f} MB)")

    return True


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description='ShadowProtocol Dictionary Scanner - Advanced Binary Analysis'
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan single binary')
    scan_parser.add_argument('-b', '--binary', required=True, help='Binary path')
    scan_parser.add_argument('-d', '--dict', help='Dictionary file (.txt)')
    scan_parser.add_argument('-k', '--keywords', help='Keywords (comma-separated)')
    scan_parser.add_argument('-o', '--output', help='Output file (json/csv/html)')
    scan_parser.add_argument('-c', '--cleanup', help='Cleanup mode (A or B)')
    scan_parser.set_defaults(func=cmd_scan)

    # Batch command
    batch_parser = subparsers.add_parser('batch', help='Batch scan directory')
    batch_parser.add_argument('-b', '--batch', required=True, help='Directory path')
    batch_parser.add_argument('-d', '--dict', help='Dictionary file (.txt)')
    batch_parser.add_argument('-k', '--keywords', help='Keywords (comma-separated)')
    batch_parser.add_argument('-w', '--workers', type=int, default=4,
                             help='Number of workers (default: 4)')
    batch_parser.add_argument('-o', '--output', help='Output file (json)')
    batch_parser.set_defaults(func=cmd_batch)

    # Interactive command
    interactive_parser = subparsers.add_parser('interactive', help='Interactive mode')
    interactive_parser.set_defaults(func=cmd_interactive)

    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Cleanup operations')
    cleanup_parser.add_argument('-t', '--target', required=True, help='Target binary')
    cleanup_parser.add_argument('-m', '--mode', default='A', help='Mode A or B')
    cleanup_parser.set_defaults(func=cmd_cleanup)

    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate binaries')
    validate_parser.add_argument('-d', '--directory', required=True, help='Directory path')
    validate_parser.set_defaults(func=cmd_validate)

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Execute command
    try:
        result = args.func(args)
        return 0 if result else 1
    except Exception as e:
        print(f"\n[!] Error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
