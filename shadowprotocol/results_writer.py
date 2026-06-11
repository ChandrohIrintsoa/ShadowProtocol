"""
ShadowProtocol - Ecriture des Resultats

Sortie persistante pour les resultats de recherche et les donnees d'offset.
Assure que tous les resultats de recherche, donnees d'offset et resultats
de patchage sont ecrits dans un repertoire 'results/' dedie, separe des logs.
"""

import os
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from .config import Config


def _ensure_results_dir(results_dir: Optional[str] = None) -> str:
    """Ensure the results directory exists and return its path."""
    if results_dir:
        target_dir = results_dir
    else:
        cfg_dir = Config.get('results_dir')
        target_dir = str(cfg_dir) if cfg_dir else './results'
    os.makedirs(target_dir, exist_ok=True)
    return target_dir


def _timestamp_tag() -> str:
    """Generate a compact timestamp tag for file naming."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def write_offset_results(
    offsets: List[Dict[str, Any]],
    mode_label: str,
    results_dir: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Write offset search results to a persistent file."""
    out_dir = _ensure_results_dir(results_dir)
    tag = _timestamp_tag()
    filename = f"offsets_mode{mode_label}_{tag}.txt"
    filepath = os.path.join(out_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("SHADOWPROTOCOL - OFFSET SEARCH RESULTS\n")
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
    """Write patching results to a persistent file."""
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
        f.write("SHADOWPROTOCOL - PATCH RESULTS\n")
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
            else:
                f.write(f"  {info}\n")
            f.write("\n")
    return filepath


def write_function_results(
    functions: List,
    search_type: str,
    results_dir: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Write function search results to a file."""
    out_dir = _ensure_results_dir(results_dir)
    tag = _timestamp_tag()
    filename = f"functions_{search_type}_{tag}.txt"
    filepath = os.path.join(out_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("SHADOWPROTOCOL - FUNCTION SEARCH RESULTS\n")
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


def write_related_functions(
    functions: List[tuple],
    pp_address: str,
    results_dir: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Write related functions results to a file."""
    out_dir = _ensure_results_dir(results_dir)
    tag = _timestamp_tag()
    filename = f"related_functions_{pp_address}_{tag}.txt"
    filepath = os.path.join(out_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("SHADOWPROTOCOL - RELATED FUNCTIONS RESULTS\n")
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
    """Write generic results to a persistent file."""
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
