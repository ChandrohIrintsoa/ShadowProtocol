"""
ShadowProtocol Flutter Patcher Subpackage

Provides Flutter APK patching functionality:
- core: Extraction, blutter, cleanup, APK operations
- patcher: PP patching, ASM patching, false address patching
- manifest: Manifest patching (license check removal, extractNativeLibs)
- installer: Auto-install for Termux environments
- find_functions: ARM64 function pattern finding (v2/v3)
"""

from .core import (
    extract_arm64_folder_from_apk,
    run_blutter,
    cleanup_workspace,
    replace_lib_in_apk,
    find_related_functions,
)
from .patcher import (
    FlutterPatcher,
    patch_true_functions,
    patch_false_functions,
    patch_false_addresses,
    process_pp_patch,
    process_asm_patch,
)
from .manifest import (
    patch_android_manifest,
    process_manifest_patcher,
)
from .installer import (
    check_termux,
    install_packages,
    install_blutter,
    check_and_install_r2,
    check_and_install_pptool,
    run_auto_installation,
)
from .find_functions import FunctionFinder

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
    "patch_android_manifest",
    "process_manifest_patcher",
    "check_termux",
    "install_packages",
    "install_blutter",
    "check_and_install_r2",
    "check_and_install_pptool",
    "run_auto_installation",
    "FunctionFinder",
]
