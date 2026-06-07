"""
Flutter Patcher - PP Patching, ASM Patching, False Address Patching

Merged from flutter_patcher.py and ultimate_flutter_patcher.py,
deduplicating all shared code. Uses r2pipe for Radare2 operations.
"""

import os
import re

try:
    import r2pipe
    HAS_R2PIPE = True
except ImportError:
    HAS_R2PIPE = False

from .core import (
    extract_arm64_folder_from_apk,
    run_blutter,
    cleanup_workspace,
    replace_lib_in_apk,
    find_related_functions,
)
from ..results_writer import write_patch_results, write_generic_results

# Configuration defaults
KEYWORDS_TRUE = ["keyword"]
KEYWORDS_FALSE = [
    "isPro", "ispremium", "is_premium", "is_pro", "lifetime",
    "CustomerInfo", "isSubscription", "issubscribe"
]

ASM_REGEX_PATTERNS = [
    r"(((premium|subscribed|_getUserActivationStatus|isPremium|isSubscription|ispro\b|is_pro\b|is_premium|is_subscription)\w*\s*\([^)]*\)\s*(?:async\s*)?\{?)|(entitlementinfo)|(customerinfo))(?:[\s\S]*?)}",
    r"((?:\b(?:get|fetch|retrieve)?issubscription|islifetime|get.*subscription.*info|subscription.*status|plus|subscription.*controller|is_lifetime|has.*lifetime|\w*lifetime\b|\blifetime\w*|is subscription|isSubscription|issubscription\b|has.*subscription|\bispro\b|pro_access|\bhaspro\b|\bis.*pro\b|has_premium|hasPremium|get.*PREMIUM|subscribed|is_subscribed|setpremium|set_premium|isPremium|vip|has.*access|is_premium|is_subscription)(?:(?!\/\/ \*\* addr:).)*?\n\s*\/\/ \*\* addr: .*, size:)(?:[\s\S]*?)}"
]

ASM_FALSE_PATTERNS = [
    r"(\b0x[0-9a-fA-F]+):\s*(?:r\d+|x\d+|w\d+)\s*=\s*false",
    r"(\b0x[0-9a-fA-F]+).*false\b",
    r"^(\b0x[0-9a-fA-F]+):.*\bfalse"
]


class FlutterPatcher:
    """Flutter patcher with configurable options.

    Provides PP patching (0x20 <-> 0x30) and ASM folder-based patching.
    """

    def __init__(self, enable_pp_patch=False, enable_asm_patch=True,
                 enable_true_patch=False, enable_false_patch=True,
                 keywords_true=None, keywords_false=None):
        """Initialize FlutterPatcher with configuration.

        Args:
            enable_pp_patch: Enable pp.txt-based patching.
            enable_asm_patch: Enable asm folder-based patching.
            enable_true_patch: Enable TRUE patch mode (0x20 -> 0x30).
            enable_false_patch: Enable FALSE patch mode (0x30 -> 0x20).
            keywords_true: Keywords for TRUE patch addresses.
            keywords_false: Keywords for FALSE patch addresses.
        """
        self.enable_pp_patch = enable_pp_patch
        self.enable_asm_patch = enable_asm_patch
        self.enable_true_patch = enable_true_patch
        self.enable_false_patch = enable_false_patch
        self.keywords_true = keywords_true or KEYWORDS_TRUE
        self.keywords_false = keywords_false or KEYWORDS_FALSE

    def process_combined(self, apk_path):
        """Combined flutter patching using both pp.txt and asm folder.

        Args:
            apk_path: Path to the APK file.

        Returns:
            Path to the (potentially patched) APK.
        """
        print("\n" + "="*60)
        print("COMBINED FLUTTER PATCHING (PP.TXT + ASM FOLDER)")
        print("="*60)
        print(f"PP Patching: {'ENABLED' if self.enable_pp_patch else 'DISABLED'}")
        print(f"ASM Patching: {'ENABLED' if self.enable_asm_patch else 'DISABLED'}")
        print("="*60)

        apk_dir = os.path.dirname(os.path.abspath(apk_path))
        if not apk_dir:
            apk_dir = "."

        print(f"Working directory: {apk_dir}")

        total_successful_patches = 0

        try:
            extract_arm64_folder_from_apk(apk_path, apk_dir)
        except Exception as e:
            print(f"Extraction error: {e}")
            return apk_path

        base = os.path.splitext(os.path.basename(apk_path))[0]
        blutter_out_dir = run_blutter(base, apk_dir)

        if self.enable_pp_patch:
            _, pp_patches = process_pp_patch(
                apk_path,
                keywords_true=self.keywords_true,
                keywords_false=self.keywords_false,
                enable_true_patch=self.enable_true_patch,
                enable_false_patch=self.enable_false_patch,
            )
            total_successful_patches += pp_patches

        if self.enable_asm_patch:
            asm_patches = process_asm_patch(apk_path, apk_dir, out_dir=blutter_out_dir)
            total_successful_patches += asm_patches

        libapp_path = os.path.join(apk_dir, "libapp.so")

        if total_successful_patches > 0:
            print(f"\n{'='*60}")
            print(f"TOTAL {total_successful_patches} PATCHES APPLIED")
            print(f"{'='*60}")
            print("Updating APK with patched libapp.so...")
            replace_lib_in_apk(apk_path, libapp_path)
        else:
            print(f"\n{'='*60}")
            print("NO PATCHES APPLIED")
            print(f"{'='*60}")

        cleanup_workspace(apk_dir)

        # Clean up temporary analysis files
        for file in ['pp.txt', 'smngn.txt']:
            file_path = os.path.join(apk_dir, file)
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Temporary file removed: {file_path}")

        return apk_path


def analyze_function_with_r2_commands(libso_path, func_addr):
    """Analyze a function using r2pipe commands.

    Args:
        libso_path: Path to the .so binary.
        func_addr: Function address (0x...).

    Returns:
        Disassembly output string, or empty string on error.
    """
    if not HAS_R2PIPE:
        print("r2pipe not available for function analysis")
        return ""
    try:
        r2 = r2pipe.open(libso_path, flags=["-2"])

        print(f"  -> s {func_addr}")
        r2.cmd(f"s {func_addr}")

        print(f"  -> aF")
        r2.cmd("aF")

        print(f"  -> pdr")
        disasm = r2.cmd("pdr")

        r2.quit()
        return disasm
    except Exception as e:
        print(f"R2 command analysis error: {e}")
        return ""


def patch_true_functions(libso_path, related_funcs, indices):
    """PP PATCHING: FALSE patch mode (0x20 -> 0x30).

    Searches for 'add x[0-30], x22, 0x20' and replaces with 0x30.

    Args:
        libso_path: Path to libapp.so.
        related_funcs: List of (func_addr, offset) tuples.
        indices: List of 1-based indices into related_funcs.

    Returns:
        Dict mapping index to (func_addr, offset, patched, patched_at, register, patch_type).
    """
    if not related_funcs:
        print("No related functions provided.")
        return {}

    print("\n" + "="*60)
    print("FALSE PATCH MODE (0x20 -> 0x30)")
    print("="*60)
    print("Searching: add x[0-30], x22, 0x20")
    print("Replacing: add x[0-30], x22, 0x30")
    print("="*60 + "\n")

    patterns = [
        r"add\s+(x([0-9]|[12][0-9]|30)),\s*x22,\s*0x20",
        r"add\s+(x([0-9]|[12][0-9]|30)),\s*x22,\s*#?0x20"
    ]

    results = {}

    try:
        for i in indices:
            func_addr, offset = related_funcs[i-1]
            print(f"\nChecking function #{i} for FALSE patch @ {func_addr} (offset {offset})")

            print("  Executing R2 commands...")
            disasm = analyze_function_with_r2_commands(libso_path, func_addr)

            if not disasm:
                print("  Could not get disassembly from R2 commands")
                results[i] = (func_addr, offset, False, None, None, "TRUE_PATCH")
                continue

            patched = False
            patched_at = None
            matched_register = None

            for pattern in patterns:
                for line in disasm.splitlines():
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match and "0x20" in line:
                        matched_register = match.group(1)
                        addr_match = re.search(r"(0x[0-9a-fA-F]+)", line)
                        instr_addr = addr_match.group(1) if addr_match else func_addr

                        print(f"TRUE pattern found: {line.strip()}")
                        print(f"  Address: {instr_addr}")
                        print(f"  Register: {matched_register}")

                        try:
                            r2 = r2pipe.open(libso_path, flags=["-w", "-2"])
                            r2.cmd(f"s {instr_addr}")
                            r2.cmd(f"wa add {matched_register}, x22, 0x30")
                            r2.quit()

                            print(f"  Patched to 'add {matched_register}, x22, 0x30' (true -> false)")

                            patched = True
                            patched_at = instr_addr
                            break
                        except Exception as e:
                            print(f"  Patching error: {e}")
                if patched:
                    break

            results[i] = (func_addr, offset, patched, patched_at, matched_register, "TRUE_PATCH")
            if patched:
                print(f"Function #{i} FALSE patched at {patched_at}.")
            else:
                print(f"Function #{i}: No target found for FALSE patch.")
                print("\npdr output (first 3 lines):")
                for j, line in enumerate(disasm.splitlines()[:3]):
                    print(f"  {j:3d}: {line}")

    except Exception as e:
        print(f"FALSE patching error: {e}")

    return results


def patch_false_functions(libso_path, related_funcs, indices):
    """PP PATCHING: TRUE patch mode (0x30 -> 0x20).

    Searches for 'add x[0-30], x22, 0x30' and replaces with 0x20.

    Args:
        libso_path: Path to libapp.so.
        related_funcs: List of (func_addr, offset) tuples.
        indices: List of 1-based indices into related_funcs.

    Returns:
        Dict mapping index to (func_addr, offset, patched, patched_at, register, patch_type).
    """
    if not related_funcs:
        print("No related functions provided.")
        return {}

    print("\n" + "="*60)
    print("TRUE PATCH MODE (0x30 -> 0x20)")
    print("="*60)
    print("Searching: add x[0-30], x22, 0x30")
    print("Replacing: add x[0-30], x22, 0x20")
    print("="*60 + "\n")

    patterns = [
        r"add\s+(x([0-9]|[12][0-9]|30)),\s*x22,\s*0x30",
        r"add\s+(x([0-9]|[12][0-9]|30)),\s*x22,\s*#?0x30"
    ]

    results = {}

    try:
        for i in indices:
            func_addr, offset = related_funcs[i-1]
            print(f"\nChecking function #{i} for TRUE patch @ {func_addr} (offset {offset})")

            print("  Executing R2 commands...")
            disasm = analyze_function_with_r2_commands(libso_path, func_addr)

            if not disasm:
                print("  Could not get disassembly from R2 commands")
                results[i] = (func_addr, offset, False, None, None, "FALSE_PATCH")
                continue

            patched = False
            patched_at = None
            matched_register = None

            for pattern in patterns:
                for line in disasm.splitlines():
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match and "0x30" in line:
                        matched_register = match.group(1)
                        addr_match = re.search(r"(0x[0-9a-fA-F]+)", line)
                        instr_addr = addr_match.group(1) if addr_match else func_addr

                        print(f"FALSE pattern found: {line.strip()}")
                        print(f"  Address: {instr_addr}")
                        print(f"  Register: {matched_register}")

                        try:
                            r2 = r2pipe.open(libso_path, flags=["-w", "-2"])
                            r2.cmd(f"s {instr_addr}")
                            r2.cmd(f"wa add {matched_register}, x22, 0x20")
                            r2.quit()

                            print(f"  Patched to 'add {matched_register}, x22, 0x20' (false -> true)")

                            patched = True
                            patched_at = instr_addr
                            break
                        except Exception as e:
                            print(f"  Patching error: {e}")
                if patched:
                    break

            results[i] = (func_addr, offset, patched, patched_at, matched_register, "FALSE_PATCH")
            if patched:
                print(f"Function #{i} TRUE patched at {patched_at}.")
            else:
                print(f"Function #{i}: No target found for TRUE patch.")
                print("\npdr output (first 3 lines):")
                for j, line in enumerate(disasm.splitlines()[:3]):
                    print(f"  {j:3d}: {line}")

    except Exception as e:
        print(f"TRUE patching error: {e}")

    return results


def patch_selected_functions(libso_path, related_funcs, patch_instr="wa add x0, x22, 0x20", indices=None):
    """Function patching with specified indices.

    WARNING: The interactive input() version that was here previously
    conflicted with the curses TUI. The indices parameter must now
    be provided explicitly.

    Args:
        libso_path: Path to libapp.so.
        related_funcs: List of (func_addr, offset) tuples.
        patch_instr: The r2 patch instruction to apply.
        indices: List of 1-based indices to patch. If None, patches all.

    Returns:
        Dict mapping index to (func_addr, offset, patched, patched_at).
    """
    if not related_funcs:
        print("No related functions provided.")
        return {}

    if not HAS_R2PIPE:
        print("r2pipe not available for patching")
        return {}

    max_index = len(related_funcs)
    if indices is None:
        indices = list(range(1, max_index + 1))
    if not indices:
        print("No selection -- skipping patch step.")
        return {}

    search_pattern = re.compile(r"add\s+x0,\s*x22,\s*0x30", re.IGNORECASE)
    results = {}

    try:
        r2 = r2pipe.open(libso_path, flags=["-w", "-2"])
        r2.cmd("e asm.lines = true")
        r2.cmd("e asm.bytes = false")
        r2.cmd("e asm.comments = false")

        for i in indices:
            func_addr, offset = related_funcs[i-1]
            print(f"\nChecking function #{i} @ {func_addr} (offset {offset})")
            disasm = r2.cmd(f"pd {int(offset, 16) * 20} @ {func_addr}")

            patched = False
            patched_at = None
            for line in disasm.splitlines():
                if search_pattern.search(line):
                    addr_match = re.search(r"(0x[0-9a-fA-F]+)", line)
                    instr_addr = addr_match.group(1) if addr_match else func_addr
                    print(f"Found target at {instr_addr}. Patching...")
                    r2.cmd(f"s {instr_addr}")
                    r2.cmd(patch_instr)
                    patched = True
                    patched_at = instr_addr
                    break

            results[i] = (func_addr, offset, patched, patched_at)
            if patched:
                print(f"Function #{i} patched at {patched_at}.")
            else:
                print(f"Function #{i}: target not found in range.")
        r2.quit()

    except Exception as e:
        print(f"Error during patching: {e}")

    return results


def search_asm_folder(asm_folder):
    """Search for regex patterns in .dart files within asm folder.

    Args:
        asm_folder: Path to the asm folder from blutter output.

    Returns:
        List of match dicts with 'address', 'context', 'file', 'match_text'.
    """
    print("\n" + "="*60)
    print("SEARCHING ASM FOLDER FOR REGEX PATTERNS")
    print("="*60)

    all_matches = []

    if not os.path.exists(asm_folder):
        print(f"asm folder not found: {asm_folder}")
        return all_matches

    dart_files = []
    for root, dirs, files in os.walk(asm_folder):
        for file in files:
            if file.endswith('.dart'):
                dart_files.append(os.path.join(root, file))

    print(f"Found {len(dart_files)} .dart files")

    for i, dart_file in enumerate(dart_files, 1):
        try:
            with open(dart_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            for regex_pattern in ASM_REGEX_PATTERNS:
                matches = re.finditer(regex_pattern, content, re.IGNORECASE)
                for match in matches:
                    addr_match = re.search(
                        r'// \*\* addr: (0x[0-9a-fA-F]+)',
                        content[max(0, match.start()-200):match.end()]
                    )
                    if addr_match:
                        address = addr_match.group(1)

                        lines = content.splitlines()
                        match_line_idx = content[:match.start()].count('\n')
                        context_start = max(0, match_line_idx - 10)
                        context_end = min(len(lines), match_line_idx + 10)
                        context = match.group()

                        all_matches.append({
                            'address': address,
                            'context': context,
                            'file': os.path.relpath(dart_file, asm_folder),
                            'match_text': match.group() if len(match.group()) > 200 else match.group()
                        })

                        if len(all_matches) % 10 == 0:
                            print(f"  Found {len(all_matches)} matches so far...")

        except Exception as e:
            print(f"  Error reading {dart_file}: {e}")

        if i % 50 == 0:
            print(f"  Processed {i}/{len(dart_files)} files")

    print(f"\nTotal matches found: {len(all_matches)}")
    return all_matches


def create_smngn_file(matches, output_file="smngn.txt"):
    """Create smngn.txt file with all matches.

    Args:
        matches: List of match dicts from search_asm_folder.
        output_file: Output file path.

    Returns:
        Path to the created file.
    """
    print(f"\nCreating {output_file}...")

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("="*60 + "\n")
        f.write("SMNGN REGEX MATCHES\n")
        f.write("="*60 + "\n\n")

        for i, match in enumerate(matches, 1):
            f.write(f"MATCH #{i}\n")
            f.write(f"Address: {match['address']}\n")
            f.write(f"File: {match['file']}\n")
            f.write(f"Context:\n{match['context']}\n")
            f.write(f"Match Text:\n{match['match_text']}\n")
            f.write("-"*60 + "\n\n")

    print(f"{output_file} created with {len(matches)} matches")
    return output_file


def extract_false_addresses_from_smngn(smngn_file):
    """Extract false addresses from smngn.txt file.

    Args:
        smngn_file: Path to the smngn.txt file.

    Returns:
        List of address strings (0x...).
    """
    print(f"\nExtracting false addresses from {smngn_file}...")

    false_addresses = []

    if not os.path.exists(smngn_file):
        print(f"{smngn_file} not found")
        return false_addresses

    try:
        with open(smngn_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        for pattern in ASM_FALSE_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                address = match.group(1)
                if address not in false_addresses:
                    false_addresses.append(address)

                    lines = content.splitlines()
                    for j, line in enumerate(lines):
                        if address in line and 'false' in line.lower():
                            context_start = max(0, j - 2)
                            context_end = min(len(lines), j + 3)
                            context = '\n'.join(lines[context_start:context_end])
                            print(f"  Found false at {address}: {line.strip()}")
                            break

        print(f"Extracted {len(false_addresses)} false addresses")
        return false_addresses

    except Exception as e:
        print(f"Error reading {smngn_file}: {e}")
        return []


def patch_false_addresses(libso_path, false_addresses):
    """ASM PATCHING: Patch false addresses (false -> true).

    Pattern: add x[0-30], x22, 0x30 -> add x[0-30], x22, 0x20

    Args:
        libso_path: Path to libapp.so.
        false_addresses: List of address strings to patch.

    Returns:
        Dict mapping address to patch result info.
    """
    if not false_addresses:
        print("No false addresses to patch")
        return {}

    if not HAS_R2PIPE:
        print("r2pipe not available for patching")
        return {}

    print("\n" + "="*60)
    print("ASM PATCHING FALSE ADDRESSES (false -> true)")
    print("="*60)
    print("Pattern: add x[0-30], x22, 0x30 -> add x[0-30], x22, 0x20")
    print("="*60)

    results = {}

    for i, address in enumerate(false_addresses, 1):
        print(f"\n[{i}/{len(false_addresses)}] Patching false address: {address}")

        try:
            r2 = r2pipe.open(libso_path, flags=["-w", "-2"])

            print(f"  -> s {address}")
            r2.cmd(f"s {address}")

            print(f"  -> pd1")
            disasm = r2.cmd("pd1")
            print(f"  Instruction: {disasm.strip()}")

            add_pattern = r"add\s+(x([0-9]|[12][0-9]|30)),\s*x22,\s*0x30"
            match = re.search(add_pattern, disasm, re.IGNORECASE)

            if match:
                matched_register = match.group(1)
                print(f"  Found: {disasm.strip()}")
                print(f"  Register: {matched_register}")

                patch_cmd = f"wa add {matched_register}, x22, 0x20"
                print(f"  -> {patch_cmd}")
                r2.cmd(patch_cmd)

                r2.cmd(f"s {address}")
                verify_disasm = r2.cmd("pd1")
                print(f"  Patched to: {verify_disasm.strip()}")

                results[address] = {
                    'patched': True,
                    'original': disasm.strip(),
                    'patched_to': verify_disasm.strip(),
                    'register': matched_register,
                    'type': 'FALSE_TO_TRUE'
                }

                print(f"  Successfully patched {address}")
            else:
                print(f"  Not an add x[0-30], x22, 0x30 instruction")
                results[address] = {
                    'patched': False,
                    'reason': 'Not matching pattern',
                    'instruction': disasm.strip()
                }

            r2.quit()

        except Exception as e:
            print(f"  Error patching {address}: {e}")
            results[address] = {
                'patched': False,
                'reason': str(e)
            }

    successful = sum(1 for r in results.values() if r.get('patched', False))
    print(f"\n" + "="*60)
    print(f"ASM PATCH SUMMARY: {successful}/{len(false_addresses)} successful")
    print("="*60)

    # Persist ASM patch results
    result_file = write_patch_results(results, "D_ASM",
                                      extra_metadata={"libso_path": libso_path,
                                                      "successful": successful,
                                                      "total": len(false_addresses)})
    print(f"ASM patch results saved: {result_file}")

    return results


def process_pp_patch(apk_path, keywords_true=None, keywords_false=None,
                     enable_true_patch=False, enable_false_patch=True):
    """Process pp.txt based patching.

    Args:
        apk_path: Path to the APK file.
        keywords_true: Keywords for TRUE addresses.
        keywords_false: Keywords for FALSE addresses.
        enable_true_patch: Enable TRUE patch mode.
        enable_false_patch: Enable FALSE patch mode.

    Returns:
        Tuple of (apk_path, successful_patch_count).
    """
    keywords_true = keywords_true or KEYWORDS_TRUE
    keywords_false = keywords_false or KEYWORDS_FALSE

    print("\n" + "="*60)
    print("PP.TXT BASED PATCHING")
    print("="*60)

    apk_dir = os.path.dirname(os.path.abspath(apk_path))
    if not apk_dir:
        apk_dir = "."

    print(f"TRUE Keywords: {keywords_true}")
    print(f"FALSE Keywords: {keywords_false}")

    pp_txt = os.path.join(apk_dir, "pp.txt")
    if not os.path.exists(pp_txt):
        print("pp.txt not found!")
        return apk_path, 0

    pp_addresses_true = []
    pp_addresses_false = []

    with open(pp_txt, "r", errors="ignore") as f:
        lines = f.readlines()

    if enable_true_patch:
        for kw in keywords_true:
            found_for_kw = False
            for line in lines:
                if kw.lower() in line.lower():
                    m = re.search(r"\[pp\+(0x[0-9a-fA-F]+)\]", line)
                    if m:
                        pp_addr = m.group(1)
                        if pp_addr not in pp_addresses_true:
                            pp_addresses_true.append(pp_addr)
                            print(f"Address found for TRUE '{kw}' -> {pp_addr}")
                            found_for_kw = True
            if not found_for_kw:
                print(f"No address found for TRUE '{kw}'")

    if enable_false_patch:
        for kw in keywords_false:
            found_for_kw = False
            for line in lines:
                if kw.lower() in line.lower():
                    m = re.search(r"\[pp\+(0x[0-9a-fA-F]+)\]", line)
                    if m:
                        pp_addr = m.group(1)
                        if pp_addr not in pp_addresses_false:
                            pp_addresses_false.append(pp_addr)
                            print(f"Address found for FALSE '{kw}' -> {pp_addr}")
                            found_for_kw = True
            if not found_for_kw:
                print(f"No address found for FALSE '{kw}'")

    libapp_path = os.path.join(apk_dir, "libapp.so")
    all_patch_results = {}

    if pp_addresses_true and enable_true_patch:
        print(f"\n{'='*60}")
        print(f"PP: STARTING TRUE PATCH PROCESS ({len(pp_addresses_true)} addresses)")
        print(f"{'='*60}")

        for idx, pp_address in enumerate(pp_addresses_true, 1):
            print(f"\n[{idx}/{len(pp_addresses_true)}] PP TRUE patch process for {pp_address}:")

            related_funcs = find_related_functions(libapp_path, pp_address)
            if related_funcs:
                max_index = len(related_funcs)
                indices = list(range(1, max_index + 1))
                patch_results = patch_true_functions(libapp_path, related_funcs, indices)

                for k, v in patch_results.items():
                    all_patch_results[f"TRUE_{pp_address}_{k}"] = v
            else:
                print(f"  No functions found for {pp_address}.")

    if pp_addresses_false and enable_false_patch:
        print(f"\n{'='*60}")
        print(f"PP: STARTING FALSE PATCH PROCESS ({len(pp_addresses_false)} addresses)")
        print(f"{'='*60}")

        for idx, pp_address in enumerate(pp_addresses_false, 1):
            print(f"\n[{idx}/{len(pp_addresses_false)}] PP FALSE patch process for {pp_address}:")

            related_funcs = find_related_functions(libapp_path, pp_address)
            if related_funcs:
                max_index = len(related_funcs)
                indices = list(range(1, max_index + 1))
                patch_results = patch_false_functions(libapp_path, related_funcs, indices)

                for k, v in patch_results.items():
                    all_patch_results[f"FALSE_{pp_address}_{k}"] = v
            else:
                print(f"  No functions found for {pp_address}.")

    successful_patches = sum(1 for info in all_patch_results.values() if info[2])
    print(f"\nPP PATCHING: {successful_patches} successful patches")

    # Persist PP patch results
    patch_data = {k: {"func_addr": v[0], "offset": v[1], "patched": v[2],
                       "patched_at": v[3], "register": v[4], "type": v[5]}
                  for k, v in all_patch_results.items()}
    result_file = write_patch_results(patch_data, "D_PP",
                                      extra_metadata={"apk_path": apk_path,
                                                      "successful_patches": successful_patches})
    print(f"PP patch results saved: {result_file}")

    return apk_path, successful_patches


def process_asm_patch(apk_path, apk_dir, out_dir=None):
    """Process asm folder based patching.

    Args:
        apk_path: Path to the APK file.
        apk_dir: Working directory for the APK.
        out_dir: Optional blutter output directory. If None, runs blutter.

    Returns:
        Number of successful patches.
    """
    print("\n" + "="*60)
    print("ASM FOLDER BASED PATCHING")
    print("="*60)

    try:
        if not out_dir:
            base = os.path.splitext(os.path.basename(apk_path))[0]
            out_dir = run_blutter(base, apk_dir)

        if not out_dir:
            print("Blutter failed to create output directory")
            return 0

        asm_folder = os.path.join(out_dir, "asm")
        matches = search_asm_folder(asm_folder)

        if not matches:
            print("No regex matches found in asm folder")
            return 0

        smngn_file = os.path.join(apk_dir, "smngn.txt")
        create_smngn_file(matches, smngn_file)

        false_addresses = extract_false_addresses_from_smngn(smngn_file)

        libapp_path = os.path.join(apk_dir, "libapp.so")

        if false_addresses:
            print(f"\n{'='*60}")
            print(f"ASM: PATCHING {len(false_addresses)} FALSE ADDRESSES")
            print(f"{'='*60}")

            patch_results = patch_false_addresses(libapp_path, false_addresses)

            successful_patches = sum(
                1 for info in patch_results.values() if info.get('patched', False)
            )
            print(f"\nASM PATCHING: {successful_patches} successful patches")
            return successful_patches
        else:
            print("\nASM: No false addresses found to patch.")
            return 0

    except Exception as e:
        print(f"ASM patching error: {e}")
        return 0


def process_flutter_patch_combined(apk_path):
    """Combined flutter patching using both pp.txt and asm folder.

    Uses default configuration (PP disabled, ASM enabled, FALSE patch mode).

    Args:
        apk_path: Path to the APK file.

    Returns:
        Path to the (potentially patched) APK.
    """
    patcher = FlutterPatcher()
    return patcher.process_combined(apk_path)
