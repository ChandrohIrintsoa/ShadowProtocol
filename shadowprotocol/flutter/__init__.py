"""
ShadowProtocol Flutter Patcher Subpackage

Provides Flutter APK patching functionality:
- core: Extraction, blutter, cleanup, APK operations
- patcher: PP patching, ASM patching, false address patching
- manifest: Manifest patching (license check removal, extractNativeLibs)
- installer: Auto-install for Termux environments
- find_functions: ARM64 function pattern finding (v2/v3)
- blutter: Integrated Blutter-Termux analysis (Rituel D replacement)
"""

# Lazy imports - only import what's needed when needed
# This avoids importing heavy dependencies (r2pipe, etc.) at package load

__all__ = [
    "extract_arm64_folder_from_apk",
    "run_blutter",
    "cleanup_workspace",
    "replace_lib_in_apk",
    "find_related_functions",
    "FlutterPatcher",
    "patch_true_functions",
    "patch_false_functions",
    "patch_false_addresses",
    "process_pp_patch",
    "process_asm_patch",
    "process_flutter_patch_combined",
    "patch_android_manifest",
    "process_manifest_patcher",
    "check_termux",
    "install_packages",
    "install_blutter",
    "check_and_install_r2",
    "check_and_install_pptool",
    "run_auto_installation",
    "FunctionFinder",
    "BlutterRunner",
]


def __getattr__(name):
    """Lazy import to avoid loading heavy dependencies at package init."""
    if name in (
        "extract_arm64_folder_from_apk", "run_blutter", "cleanup_workspace",
        "replace_lib_in_apk", "find_related_functions",
    ):
        from . import core
        return getattr(core, name)

    if name in (
        "FlutterPatcher", "patch_true_functions", "patch_false_functions",
        "patch_false_addresses", "process_pp_patch", "process_asm_patch",
        "process_flutter_patch_combined",
    ):
        from . import patcher
        return getattr(patcher, name)

    if name in ("patch_android_manifest", "process_manifest_patcher"):
        from . import manifest
        return getattr(manifest, name)

    if name in (
        "check_termux", "install_packages", "install_blutter",
        "check_and_install_r2", "check_and_install_pptool",
        "run_auto_installation",
    ):
        from . import installer
        return getattr(installer, name)

    if name == "FunctionFinder":
        from .find_functions import FunctionFinder
        return FunctionFinder

    if name == "BlutterRunner":
        from .blutter import BlutterRunner
        return BlutterRunner

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
