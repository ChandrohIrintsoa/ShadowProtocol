"""
Flutter Patcher Core - Extraction, Blutter, Cleanup, APK operations

Merged from flutter_patcher.py and ultimate_flutter_patcher.py,
deduplicating shared functionality.
"""

import os
import shutil
import subprocess
import tempfile
import zipfile
import re

from ..results_writer import write_related_functions


def extract_arm64_folder_from_apk(apk_path, dest_parent='.'):
    """Extract arm64-v8a folder and libapp.so from APK.

    Args:
        apk_path: Path to the APK file.
        dest_parent: Destination parent directory (default: current directory).

    Returns:
        The destination folder path.

    Raises:
        FileNotFoundError: If APK does not exist.
        RuntimeError: If lib/arm64-v8a/ is not found in APK.
    """
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK not found: {apk_path}")

    with zipfile.ZipFile(apk_path, 'r') as z:
        members = [m for m in z.namelist() if m.startswith('lib/arm64-v8a/')]
        if not members:
            raise RuntimeError("'lib/arm64-v8a/' folder not found in APK.")

        tmpdir = tempfile.mkdtemp(prefix='apk_extract_')
        try:
            for m in members:
                if not m.endswith('/'):
                    z.extract(m, path=tmpdir)

            src_folder = os.path.join(tmpdir, 'lib', 'arm64-v8a')
            dst_folder = os.path.join(os.path.abspath(dest_parent), 'arm64-v8a')

            if os.path.exists(dst_folder):
                shutil.rmtree(dst_folder)
            shutil.move(src_folder, dst_folder)
            print(f"'lib/arm64-v8a' extracted -> {dst_folder}")

            libso = os.path.join(dst_folder, 'libapp.so')
            if os.path.exists(libso):
                dst_so = os.path.join(os.path.abspath(dest_parent), 'libapp.so')
                if os.path.exists(dst_so):
                    os.remove(dst_so)
                shutil.copy(libso, dst_so)
                print(f"libapp.so copied -> {dst_so}")
            else:
                print("libapp.so not found in arm64-v8a folder.")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    return dst_folder


def run_blutter(filename, apk_dir='.'):
    """Run Blutter to extract asm files.

    Args:
        filename: Base name for the output directory.
        apk_dir: Directory containing the arm64-v8a folder.

    Returns:
        Path to the Blutter output directory.
    """
    home = os.path.expanduser("~")

    extracted_path = os.path.join(apk_dir, "arm64-v8a")
    if not os.path.exists(extracted_path):
        os.makedirs(extracted_path, exist_ok=True)

    out_dir = os.path.join(home, "blutter-termux", f"out_dir_{filename}")
    cmd = ["python3", "blutter.py", extracted_path, out_dir]
    print("Running Blutter to extract files...")
    try:
        subprocess.run(cmd, cwd=os.path.join(home, "blutter-termux"), check=True)
    except subprocess.CalledProcessError as e:
        print(f"Blutter execution failed (return code {e.returncode})")
        return out_dir
    except FileNotFoundError:
        print("Blutter not found. Ensure blutter-termux is installed in ~/blutter-termux/")
        return out_dir

    # Check if asm folder was created
    asm_folder = os.path.join(out_dir, "asm")
    if os.path.exists(asm_folder):
        print(f"asm folder created: {asm_folder}")

    # Copy pp.txt if exists
    pp_source = os.path.join(out_dir, "pp.txt")
    pp_dest = os.path.join(apk_dir, "pp.txt")
    if os.path.exists(pp_source):
        shutil.copy(pp_source, pp_dest)
        print(f"pp.txt copied to directory: {pp_dest}")

    return out_dir


def cleanup_workspace(apk_dir='.'):
    """Clean up temporary files and folders.

    Args:
        apk_dir: Working directory to clean up.
    """
    for folder in ['arm64-v8a']:
        folder_path = os.path.join(apk_dir, folder)
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path, ignore_errors=True)
            print(f"Folder removed: {folder_path}")

    for file in ['libapp.so']:
        file_path = os.path.join(apk_dir, file)
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"File removed: {file_path}")


def replace_lib_in_apk(apk_path, patched_lib):
    """Replace libapp.so in APK with patched version.

    Args:
        apk_path: Path to the APK file.
        patched_lib: Path to the patched libapp.so.
    """
    tmp_apk = apk_path + ".tmp"
    with zipfile.ZipFile(apk_path, 'r') as zin, zipfile.ZipFile(tmp_apk, 'w') as zout:
        for item in zin.infolist():
            if item.filename == "lib/arm64-v8a/libapp.so":
                print(f"Replacing {item.filename} with patched version...")
                zout.write(patched_lib, item.filename)
            else:
                zout.writestr(item, zin.read(item.filename))
    os.replace(tmp_apk, apk_path)
    print(f"libapp.so replaced in {apk_path}")


def find_related_functions(lib_path, pp_address, timeout=12):
    """Find related functions for a given pp_address using pptool.

    Tries pptool directly first, then falls back to r2 with pptool.

    Args:
        lib_path: Path to the libapp.so binary.
        pp_address: The PP offset address (0x...).
        timeout: Command timeout in seconds.

    Returns:
        List of (function_address, offset_value) tuples.
    """
    print(f"Searching for related functions for {pp_address} using pptool...\n")
    output = ""

    # Try pptool directly
    try:
        proc = subprocess.run(["pptool", lib_path, pp_address],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, timeout=timeout)
        output = proc.stdout or ""
    except Exception:
        pass

    # Fallback to r2
    if not output.strip():
        try:
            proc = subprocess.run(["r2", "-w", lib_path, "-c",
                                   f'!pptool {lib_path} {pp_address}; q'],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, timeout=timeout)
            output = proc.stdout or ""
        except Exception:
            pass

    if not output.strip():
        print("No pptool output found.")
        return []

    # Clean ANSI escape codes
    ansi_re = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
    clean = ansi_re.sub("", output)
    lines = [re.sub(r'[ \t]+', ' ', ln).strip() for ln in clean.splitlines()]

    # Extract function-offset pairs
    triple_re = re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)')
    matches = [(m.group(1), m.group(3)) for ln in lines if (m := triple_re.search(ln))]

    if not matches:
        for ln in lines:
            toks = re.findall(r'0x[0-9a-fA-F]+', ln)
            if len(toks) >= 3:
                matches.append((toks[0], toks[-1]))

    if not matches:
        print("No function-offset pairs found.")
        return []

    # Deduplicate preserving order
    seen, functions = set(), []
    for func_addr, offset in matches:
        key = (func_addr.lower(), offset.lower())
        if key not in seen:
            seen.add(key)
            functions.append((func_addr, offset))

    print("Related functions found:\n")
    for i, (func_addr, offset) in enumerate(functions, start=1):
        print(f" {i}. function_address = {func_addr} | offset_value = {offset}")
    print("\nRelated functions search completed.")

    # Persist results to file
    result_file = write_related_functions(functions, pp_address,
                                          extra_metadata={"lib_path": lib_path})
    print(f"Related functions saved: {result_file}")

    return functions


def parse_selection(selection_str, max_index):
    """Parse user selection string into list of indices.

    Supports: "1,3,5", "2-4", "all"

    Args:
        selection_str: User input string.
        max_index: Maximum valid index.

    Returns:
        Sorted list of selected indices.
    """
    if not selection_str:
        return []
    s = selection_str.strip().lower()
    if s == "all":
        return list(range(1, max_index + 1))

    indices = set()
    for token in re.split(r'\s*,\s*', s):
        if re.match(r'^\d+-\d+$', token):
            a, b = map(int, token.split('-'))
            for i in range(min(a, b), max(a, b) + 1):
                if 1 <= i <= max_index:
                    indices.add(i)
        elif token.isdigit():
            i = int(token)
            if 1 <= i <= max_index:
                indices.add(i)
    return sorted(indices)
