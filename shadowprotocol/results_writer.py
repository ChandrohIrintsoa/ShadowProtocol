"""
Results Writer - Persistent output for search results and offset data

Ensures that all search results, offset data, and patching results are
written to a dedicated 'results/' directory, separate from logs.
Each output file is clearly identified and accessible.
"""

import os
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Union


# Default results directory (relative to project root)
DEFAULT_RESULTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "results"
)


def _ensure_results_dir(results_dir: Optional[str] = None) -> str:
    """Ensure the results directory exists and return its path.

    Args:
        results_dir: Custom results directory path.
                     If None, uses DEFAULT_RESULTS_DIR.

    Returns:
        Absolute path to the results directory.
    """
    target_dir = results_dir or DEFAULT_RESULTS_DIR
    os.makedirs(target_dir, exist_ok=True)
    return target_dir


def _timestamp_tag() -> str:
    """Generate a compact timestamp tag for file naming.

    Returns:
        String in format YYYYMMDD_HHMMSS.
    """
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def write_offset_results(
    offsets: List[Dict[str, Any]],
    mode_label: str,
    results_dir: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Write offset search results to a persistent file.

    Args:
        offsets: List of offset result dicts (address, instruction, etc.).
        mode_label: Mode identifier (e.g. 'A', 'B', 'E_v2').
        results_dir: Custom results directory path.
        extra_metadata: Additional metadata to include in the output.

    Returns:
        Path to the written results file.
    """
    out_dir = _ensure_results_dir(results_dir)
    tag = _timestamp_tag()
    filename = f"offsets_mode{mode_label}_{tag}.txt"
    filepath = os.path.join(out_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write(f"SHADOWPROTOCOL - OFFSET SEARCH RESULTS\n")
        f.write(f"Mode: {mode_label}\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total results: {len(offsets)}\n")
        if extra_metadata:
            for key, value in extra_metadata.items():
                f.write(f"{key}: {value}\n")
        f.write("=" * 70 + "\n\n")

        if not offsets:
            f.write("(No results found)\n")
        else:
            for i, entry in enumerate(offsets, 1):
                f.write(f"--- Result #{i} ---\n")
                if isinstance(entry, dict):
                    for key, value in entry.items():
                        f.write(f"  {key}: {value}\n")
                elif isinstance(entry, (list, tuple)):
                    for j, item in enumerate(entry):
                        f.write(f"  [{j}]: {item}\n")
                else:
                    f.write(f"  {entry}\n")
                f.write("\n")

    return filepath


def write_patch_results(
    patch_results: Dict[str, Any],
    mode_label: str,
    results_dir: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Write patching results to a persistent file.

    Args:
        patch_results: Dict of patch result data.
        mode_label: Mode identifier.
        results_dir: Custom results directory path.
        extra_metadata: Additional metadata to include.

    Returns:
        Path to the written results file.
    """
    out_dir = _ensure_results_dir(results_dir)
    tag = _timestamp_tag()
    filename = f"patches_mode{mode_label}_{tag}.txt"
    filepath = os.path.join(out_dir, filename)

    successful = sum(
        1 for v in patch_results.values()
        if isinstance(v, dict) and v.get("patched", False)
    )

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write(f"SHADOWPROTOCOL - PATCH RESULTS\n")
        f.write(f"Mode: {mode_label}\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total entries: {len(patch_results)}\n")
        f.write(f"Successful patches: {successful}\n")
        if extra_metadata:
            for key, value in extra_metadata.items():
                f.write(f"{key}: {value}\n")
        f.write("=" * 70 + "\n\n")

        for key, info in patch_results.items():
            f.write(f"[{key}]\n")
            if isinstance(info, dict):
                for k, v in info.items():
                    f.write(f"  {k}: {v}\n")
            elif isinstance(info, (list, tuple)):
                f.write(f"  {info}\n")
            else:
                f.write(f"  {info}\n")
            f.write("\n")

    return filepath


def write_function_results(
    functions: List[Dict[str, Any]],
    search_type: str,
    results_dir: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Write function search results (from Mode E / find_functions) to a file.

    Args:
        functions: List of function result dicts (address, instruction, etc.).
        search_type: Search variant identifier (e.g. 'v2', 'v3', 'all').
        results_dir: Custom results directory path.
        extra_metadata: Additional metadata to include.

    Returns:
        Path to the written results file.
    """
    out_dir = _ensure_results_dir(results_dir)
    tag = _timestamp_tag()
    filename = f"functions_{search_type}_{tag}.txt"
    filepath = os.path.join(out_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write(f"SHADOWPROTOCOL - FUNCTION SEARCH RESULTS\n")
        f.write(f"Search type: {search_type}\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total functions found: {len(functions)}\n")
        if extra_metadata:
            for key, value in extra_metadata.items():
                f.write(f"{key}: {value}\n")
        f.write("=" * 70 + "\n\n")

        if not functions:
            f.write("(No functions found)\n")
        else:
            for i, entry in enumerate(functions, 1):
                f.write(f"--- Function #{i} ---\n")
                if isinstance(entry, dict):
                    for key, value in entry.items():
                        f.write(f"  {key}: {value}\n")
                elif isinstance(entry, (list, tuple)):
                    f.write(f"  address: {entry[0] if len(entry) > 0 else 'N/A'}\n")
                    f.write(f"  instruction: {entry[1] if len(entry) > 1 else 'N/A'}\n")
                else:
                    f.write(f"  {entry}\n")
                f.write("\n")

    return filepath


def write_scan_targets(
    targets: List[Dict[str, Any]],
    mode_label: str,
    results_dir: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Write scan target results (from Mode B auto-scan) to a file.

    Args:
        targets: List of target dicts (address, instruction, etc.).
        mode_label: Mode identifier.
        results_dir: Custom results directory path.
        extra_metadata: Additional metadata to include.

    Returns:
        Path to the written results file.
    """
    out_dir = _ensure_results_dir(results_dir)
    tag = _timestamp_tag()
    filename = f"scan_targets_mode{mode_label}_{tag}.txt"
    filepath = os.path.join(out_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write(f"SHADOWPROTOCOL - SCAN TARGET RESULTS\n")
        f.write(f"Mode: {mode_label}\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total targets: {len(targets)}\n")
        if extra_metadata:
            for key, value in extra_metadata.items():
                f.write(f"{key}: {value}\n")
        f.write("=" * 70 + "\n\n")

        if not targets:
            f.write("(No targets found)\n")
        else:
            for i, entry in enumerate(targets, 1):
                f.write(f"Target #{i}:\n")
                if isinstance(entry, dict):
                    for key, value in entry.items():
                        f.write(f"  {key}: {value}\n")
                elif isinstance(entry, (list, tuple)):
                    for j, item in enumerate(entry):
                        f.write(f"  [{j}]: {item}\n")
                else:
                    f.write(f"  {entry}\n")
                f.write("\n")

    return filepath


def write_related_functions(
    functions: List[tuple],
    pp_address: str,
    results_dir: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Write related functions results (from pptool/PP analysis) to a file.

    Args:
        functions: List of (function_address, offset_value) tuples.
        pp_address: The PP offset address that was queried.
        results_dir: Custom results directory path.
        extra_metadata: Additional metadata to include.

    Returns:
        Path to the written results file.
    """
    out_dir = _ensure_results_dir(results_dir)
    tag = _timestamp_tag()
    filename = f"related_functions_{pp_address}_{tag}.txt"
    filepath = os.path.join(out_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write(f"SHADOWPROTOCOL - RELATED FUNCTIONS RESULTS\n")
        f.write(f"PP Address: {pp_address}\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total functions: {len(functions)}\n")
        if extra_metadata:
            for key, value in extra_metadata.items():
                f.write(f"{key}: {value}\n")
        f.write("=" * 70 + "\n\n")

        if not functions:
            f.write("(No related functions found)\n")
        else:
            for i, (func_addr, offset_val) in enumerate(functions, 1):
                f.write(f"  {i}. function_address = {func_addr} | offset_value = {offset_val}\n")
        f.write("\n")

    return filepath


def write_generic_results(
    data: Any,
    title: str,
    results_dir: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Write generic results to a persistent file.

    Args:
        data: Any data to write (will be JSON-serialized if not a string).
        title: Short title for the results file.
        results_dir: Custom results directory path.
        extra_metadata: Additional metadata to include.

    Returns:
        Path to the written results file.
    """
    out_dir = _ensure_results_dir(results_dir)
    tag = _timestamp_tag()
    safe_title = title.replace(" ", "_").replace("/", "_")
    filename = f"{safe_title}_{tag}.txt"
    filepath = os.path.join(out_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write(f"SHADOWPROTOCOL - {title.upper()}\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        if extra_metadata:
            for key, value in extra_metadata.items():
                f.write(f"{key}: {value}\n")
        f.write("=" * 70 + "\n\n")

        if isinstance(data, str):
            f.write(data)
        else:
            try:
                f.write(json.dumps(data, indent=2, ensure_ascii=False))
            except (TypeError, ValueError):
                f.write(str(data))
        f.write("\n")

    return filepath
