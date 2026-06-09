
import sys
from pathlib import Path

# Add shadowprotocol to path
sys.path.insert(0, str(Path(__file__).parent))

from shadowprotocol.dictionary_scanner import DictionaryScanner, CleanupManager


def demo_scan(binary_path: str, keywords_input: str):
    """Demonstrate dictionary scanning without modifying the binary.

    Args:
        binary_path: Path to binary file to scan
        keywords_input: Either path to .txt file or comma-separated keywords
    """
    try:
        # Initialize scanner
        print(f"\n[*] Initializing scanner for: {binary_path}")
        scanner = DictionaryScanner(binary_path)
        print(f"    Binary type: {scanner.binary_type}")
        print(f"    Binary size: {len(scanner.binary_data)} bytes")

        # Load keywords
        print(f"\n[*] Loading keywords from: {keywords_input}")
        if keywords_input.endswith('.txt') and Path(keywords_input).exists():
            keywords = scanner.load_dictionary_from_file(keywords_input)
            print(f"    Loaded {len(keywords)} keywords from file")
        else:
            keywords = scanner.parse_manual_keywords(keywords_input)
            print(f"    Parsed {len(keywords)} keywords from input")

        if not keywords:
            print("    [!] No keywords to scan!")
            return

        # Perform deep scan (NO MODIFICATIONS)
        print(f"\n[*] Performing deep scan (analysis only)...")
        results = scanner.deep_scan(keywords)

        # Print report
        print(scanner.get_scan_report())

        # Summary
        total_matches = sum(len(matches) for matches in results.values())
        print(f"\n[+] Scan Complete: {total_matches} total matches found")

    except FileNotFoundError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)


def demo_cleanup(target_path: str, mode: str = 'A'):
    """Demonstrate cleanup operations.

    Args:
        target_path: Path to target file
        mode: 'A' (clean) or 'B' (radical)
    """
    try:
        cleanup = CleanupManager(target_path)
        print(cleanup.get_cleanup_report(mode))

        if mode.upper() == 'A':
            print("[?] Execute mode A cleanup? (y/n): ", end="")
            if input().lower() == 'y':
                if cleanup.mode_a_cleanup():
                    print("[+] Mode A cleanup succeeded")
                else:
                    print("[!] Mode A cleanup failed")
        elif mode.upper() == 'B':
            print("[?] Execute RADICAL mode B cleanup? (y/n): ", end="")
            if input().lower() == 'y':
                if cleanup.mode_b_cleanup():
                    print("[+] Mode B cleanup succeeded")
                else:
                    print("[!] Mode B cleanup failed")

    except Exception as e:
        print(f"[!] Cleanup error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    binary_path = sys.argv[1]
    keywords_input = sys.argv[2]

    # Check if binary exists
    if not Path(binary_path).exists():
        print(f"[!] Binary not found: {binary_path}")
        sys.exit(1)

    # Run demo
    demo_scan(binary_path, keywords_input)
