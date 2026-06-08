"""
Modes Module - Six processing modes with OOP pattern + Real Radare2 Integration
Fuses v2 architecture with v1 functionality + Flutter/APK/Manifest/FindFunctions modes
"""

import re
import time
import threading
from abc import ABC, abstractmethod
from typing import Callable, List, Tuple

try:
    import r2pipe
    HAS_R2PIPE = True
except ImportError:
    HAS_R2PIPE = False

from .results_writer import (
    write_offset_results,
    write_patch_results,
    write_function_results,
    write_generic_results,
)

class Radare2Handler:
    """Radare2 binary manipulation using r2pipe.

    Uses the r2pipe library for proper API integration,
    falling back to subprocess if r2pipe is unavailable.
    """

    def __init__(self, binary_path: str):
        """Initialize r2 handler.

        Args:
            binary_path: Path to the binary file to analyze/patch.
        """
        self.binary_path = binary_path
        self.pipe = None
        self._use_r2pipe = HAS_R2PIPE

    def open(self, write: bool = False) -> bool:
        """Open binary in Radare2.

        Args:
            write: Whether to open in write mode.

        Returns:
            True if opened successfully, False otherwise.
        """
        if not self._use_r2pipe:
            return False
        try:
            flags = ["-w", "-2"] if write else ["-2"]
            self.pipe = r2pipe.open(self.binary_path, flags=flags)
            return True
        except Exception:
            self.pipe = None
            return False

    def execute(self, cmd: str) -> Tuple[bool, str, str]:
        """Execute r2 command with explicit error reporting.

        Args:
            cmd: The r2 command string to execute.

        Returns:
            (success: bool, output: str, error: str)
        """
        if not self.pipe:
            return (False, "", "r2pipe not initialized")
        try:
            result = self.pipe.cmd(cmd)
            if result is None:
                return (False, "", "r2 returned None")
            return (True, result or "", "")
        except Exception as e:
            return (False, "", f"r2 error: {str(e)}")

    def validate_binary(self) -> Tuple[bool, str]:
        """Validate that binary opened successfully"""
        if not self.pipe:
            return (False, "r2pipe not initialized")

        try:
            result = self.pipe.cmd("i")
            if result and "arch" in result:
                return (True, result.split('\n')[0])
        except Exception as e:
            return (False, str(e))

        return (False, "Could not analyze binary")

    def close(self):
        """Close r2 session."""
        if self.pipe:
            try:
                self.pipe.quit()
            except Exception:
                pass
            finally:
                self.pipe = None

class BaseMode(ABC):
    """Base class for processing modes.

    Provides a common interface for all modes with:
    - Thread-safe stop signaling via threading.Event
    - Step execution with progress updates
    - Graceful interruption support
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable):
        """Initialize mode with logging and progress callbacks.

        Args:
            log_callback: Function to call for log messages
            progress_callback: Function to call for progress updates
        """
        self.log = log_callback
        self.progress = progress_callback
        self._stop_event = threading.Event()

    @abstractmethod
    def execute(self) -> bool:
        """Execute the mode.

        Returns:
            True if completed successfully, False if stopped by user.
        """

    @abstractmethod
    def get_label(self) -> str:
        """Return the short mode label (e.g. 'A', 'B', 'C')."""

    def stop(self):
        """Signal the mode to stop gracefully."""
        self._stop_event.set()

    def is_stopping(self) -> bool:
        """Check if a stop has been requested."""
        return self._stop_event.is_set()

    def _run_steps(self, label: str, steps: List[Tuple[str, float]]) -> bool:
        """Execute a list of steps with progress reporting.

        Each step is a tuple of (step_name, duration_seconds).
        Progress is reported as current_step/total_steps.

        Args:
            label: Mode label for log prefixes
            steps: List of (step_name, duration) tuples

        Returns:
            True if all steps completed, False if interrupted.
        """
        for i, (step_name, duration) in enumerate(steps):
            if self.is_stopping():
                self.log(f"[!] MODE {label}: Stop detected - cleaning up...")
                return False

            self.log(f"[{label}] {step_name}...")
            time.sleep(duration)
            self.progress(i + 1, len(steps), f"MODE {label}")

        return True

class ModeA(BaseMode):
    """MODE A - Manual Assisted (Radare2 integration)

    Manual offset-based binary patching with
    step-by-step verification and integrity checks.
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 binary_path: str = None, offset: str = None):
        """Initialize MODE A

        Args:
            log_callback: Logging function
            progress_callback: Progress update function
            binary_path: Path to target .so file
            offset: Offset from pptool (0x...)
        """
        super().__init__(log_callback, progress_callback)
        self.binary = binary_path
        self.offset = offset
        self.r2 = Radare2Handler(binary_path) if binary_path else None

    def get_label(self) -> str:
        return "A"

    def validate_offset(self) -> bool:
        """Validate offset format & existence"""
        if not self.offset or not re.match(r'^0x[0-9a-fA-F]+$', self.offset):
            self.log("[!] Invalid offset (format: 0x...)")
            return False

        if not self.r2:
            self.log("[!] No binary loaded for Radare2")
            return False

        self.log(f"[*] Validating offset: {self.offset}")

        if not self.r2.open(write=False):
            self.log("[!] Error opening Radare2")
            return False

        try:
            success, _, error = self.r2.execute(f"s {self.offset}")
            if not success:
                self.log(f"[!] r2 seek error: {error}")
            success, disasm, error = self.r2.execute("pd 5")
            self.r2.close()

            if not success:
                self.log(f"[!] r2 disasm error: {error}")
                return False

            if "0x30" in disasm:
                self.log(f"[+] Pattern found at {self.offset}")
                return True

            self.log("[W] Pattern 0x30 not found")
            return False
        except Exception as e:
            self.log(f"[!] Validation error: {e}")
            return False

    def patch(self) -> bool:
        """Apply patch via Radare2"""
        if not self.r2:
            self.log("[!] No binary loaded for Radare2")
            return False

        if not self.r2.open(write=True):
            self.log("[!] Error opening in write mode")
            return False

        try:
            self.log("[*] Applying patch...")
            self.r2.execute(f"s {self.offset}")
            self.r2.execute("wa add x0, x22, 0x20")

            success, verify, error = self.r2.execute("pd 1")
            self.r2.close()

            if not success:
                self.log(f"[!] Verification read error: {error}")
                return False

            if "0x20" in verify:
                self.log("[+] Patch applied and verified")
                return True

            self.log("[!] Patch verification failed")
            return False
        except Exception as e:
            self.log(f"[!] Patch error: {e}")
            return False

    def execute(self) -> bool:
        """Execute MODE A - Validate offset then patch"""
        self.log("[*] MODE A: Manual analysis started...")
        self._stop_event.clear()

        # Guard: require binary and offset
        if not self.binary:
            self.log("[!] MODE A: No target binary selected (use option [1])")
            return False
        if not self.offset:
            self.log("[!] MODE A: No offset provided (use option [2])")
            return False

        # Phase 1: Validate offset
        self.log("[A] Validating offset...")
        self.progress(1, 2, "MODE A")

        if self.is_stopping():
            self.log("[W] MODE A: Stopped before validation")
            return False

        valid = self.validate_offset()

        # Persist offset validation result
        offset_data = [{"offset": self.offset, "binary": self.binary,
                        "validated": valid, "pattern": "0x30"}]
        result_file = write_offset_results(offset_data, self.get_label(),
                                           extra_metadata={"binary": self.binary})
        self.log(f"[A] Offset results saved: {result_file}")

        if not valid:
            self.log("[!] MODE A: Offset validation failed - aborting")
            return False

        # Phase 2: Apply patch
        self.log("[A] Applying patch...")
        self.progress(2, 2, "MODE A")

        if self.is_stopping():
            self.log("[W] MODE A: Stopped before patching")
            return False

        patched = self.patch()

        # Persist patch result
        patch_data = {self.offset: {"patched": patched, "binary": self.binary,
                     "instruction": "wa add x0, x22, 0x20"}}
        result_file = write_patch_results(patch_data, self.get_label(),
                                          extra_metadata={"binary": self.binary})
        self.log(f"[A] Patch results saved: {result_file}")

        if patched:
            self.log("[+] MODE A: Analysis completed successfully")
        else:
            self.log("[W] MODE A: Patch could not be applied")

        return patched

class ModeB(BaseMode):
    """MODE B - Auto-Patching (full binary scan)

    Full binary scan with automatic pattern detection
    and batch patching across multiple targets.
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 binary_path: str = None):
        """Initialize MODE B

        Args:
            log_callback: Logging function
            progress_callback: Progress update function
            binary_path: Path to target .so file
        """
        super().__init__(log_callback, progress_callback)
        self.binary = binary_path
        self.r2 = Radare2Handler(binary_path) if binary_path else None
        self.targets: List[Tuple[str, str]] = []

    def get_label(self) -> str:
        return "B"

    def scan(self) -> List[Tuple[str, str]]:
        """Scan entire binary for pattern"""
        if not self.r2:
            self.log("[!] No binary loaded for Radare2")
            return []

        if not self.r2.open(write=False):
            self.log("[!] Error opening Radare2")
            return []

        self.log("[*] Scanning binary...")

        try:
            self.r2.execute("aaa")

            pattern = re.compile(r"add\s+x\d+,\s*x\d+,\s*0x30", re.IGNORECASE)

            # Use afl to get function list, then search each function
            success, func_list, error = self.r2.execute("afl")
            if not success or not func_list.strip():
                self.log(f"[!] r2 function list error: {error}")
                self.r2.close()
                return []

            func_addrs = []
            for line in func_list.split('\n'):
                parts = line.split()
                if len(parts) >= 3:
                    addr = parts[0]
                    if addr.startswith("0x"):
                        func_addrs.append(addr)

            for func_addr in func_addrs:
                if self.is_stopping():
                    break
                self.r2.execute(f"s {func_addr}")
                success, disasm, _ = self.r2.execute("pdr")
                if not success or not disasm:
                    continue
                for line in disasm.split('\n'):
                    if pattern.search(line):
                        addr_match = re.search(r'(0x[0-9a-fA-F]+)', line)
                        if addr_match:
                            self.targets.append((addr_match.group(1), line.strip()))

            self.r2.close()
            self.log(f"[+] {len(self.targets)} targets found")
            return self.targets
        except Exception as e:
            self.log(f"[!] Scan error: {e}")
            try:
                self.r2.close()
            except Exception:
                pass
            return []

    def patch_all(self) -> int:
        """Patch all targets"""
        if not self.targets:
            self.log("[!] No targets to patch")
            return 0

        if not self.r2:
            self.log("[!] No binary loaded for Radare2")
            return 0

        if not self.r2.open(write=True):
            self.log("[!] Error opening in write mode")
            return 0

        try:
            self.log("[*] Applying patches...")

            patched = 0
            for i, (addr, instr) in enumerate(self.targets, 1):
                if self.is_stopping():
                    break

                self.r2.execute(f"s {addr}")
                self.r2.execute("wa add x0, x22, 0x20")

                _, verify, _ = self.r2.execute("pd 1")
                if "0x20" in verify:
                    patched += 1
                    if i % 10 == 0:
                        self.log(f"[*] {patched}/{len(self.targets)} patched")

                self.progress(i, len(self.targets), "MODE B")

            self.r2.close()
            self.log(f"[+] {patched}/{len(self.targets)} patches applied")
            return patched
        except Exception as e:
            self.log(f"[!] Patch error: {e}")
            try:
                self.r2.close()
            except Exception:
                pass
            return 0

    def execute(self) -> bool:
        """Execute MODE B - Scan then auto-patch"""
        self.log("[*] MODE B: Auto-scan started...")
        self._stop_event.clear()

        if not self.binary:
            self.log("[!] MODE B: No target binary selected (use option [1])")
            return False

        # Phase 1: Scan for targets
        self.log("[B] Scanning binary for patterns...")
        self.progress(1, 2, "MODE B")

        if self.is_stopping():
            self.log("[W] MODE B: Stopped before scan")
            return False

        targets = self.scan()

        # Persist scan results
        scan_data = [{"address": addr, "instruction": instr} for addr, instr in targets]
        result_file = write_offset_results(scan_data, self.get_label(),
                                           extra_metadata={"binary": self.binary,
                                                           "total_targets": len(targets)})
        self.log(f"[B] Scan results saved: {result_file}")

        if not targets:
            self.log("[W] MODE B: No targets found - nothing to patch")
            return True  # Not an error, just no targets

        # Phase 2: Patch all targets
        self.log(f"[B] Patching {len(targets)} targets...")
        self.progress(2, 2, "MODE B")

        if self.is_stopping():
            self.log("[W] MODE B: Stopped before patching")
            return False

        patched_count = self.patch_all()

        # Persist patch results
        patch_data = {addr: {"patched": True, "instruction": instr}
                      for addr, instr in self.targets}
        result_file = write_patch_results(patch_data, self.get_label(),
                                          extra_metadata={"binary": self.binary,
                                                          "patched_count": patched_count,
                                                          "total_targets": len(targets)})
        self.log(f"[B] Patch results saved: {result_file}")

        if patched_count > 0:
            self.log(f"[+] MODE B: {patched_count} patches applied successfully")
            return True
        else:
            self.log("[W] MODE B: No patches could be applied")
            return False

class ModeC(BaseMode):
    """MODE C - Raw Radare2 (direct manipulation)

    Raw Radare2 binary manipulation with
    direct memory writes and disassembly verification.
    Note: interactive() uses r2pipe for commands instead of input().
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 binary_path: str = None):
        """Initialize MODE C

        Args:
            log_callback: Logging function
            progress_callback: Progress update function
            binary_path: Path to target .so file
        """
        super().__init__(log_callback, progress_callback)
        self.binary = binary_path
        self.r2 = Radare2Handler(binary_path) if binary_path else None

    def get_label(self) -> str:
        return "C"

    def run_r2_commands(self, commands: List[str]) -> List[str]:
        """Run a series of r2 commands and return outputs.

        Args:
            commands: List of r2 command strings.

        Returns:
            List of output strings.
        """
        if not self.r2:
            self.log("[!] No binary loaded for Radare2")
            return []

        if not self.r2.open(write=True):
            self.log("[!] Error opening Radare2")
            return []

        results = []
        try:
            for i, cmd in enumerate(commands):
                if self.is_stopping():
                    break
                success, output, error = self.r2.execute(cmd)
                results.append(output)
                self.log(f"[*] r2> {cmd}")
                if not success:
                    self.log(f"    [!] r2 error: {error}")
                elif output.strip():
                    self.log(f"    {output.strip()[:200]}")
                self.progress(i + 1, len(commands), "MODE C")
        finally:
            self.r2.close()

        return results

    def execute(self) -> bool:
        """Execute MODE C - Run default r2 command sequence"""
        self.log("[*] MODE C: Raw Radare2 session started...")
        self._stop_event.clear()

        if not self.binary:
            self.log("[!] MODE C: No target binary selected (use option [1])")
            return False

        if not self.r2:
            self.log("[!] MODE C: Radare2 not available")
            return False

        # Default command sequence for raw binary manipulation
        default_commands = [
            "aaa",
            "afl",
            "iS",
            "/ add x0, x22, 0x30",
            "/ add x0, x22, 0x20",
        ]

        if self.is_stopping():
            self.log("[W] MODE C: Stopped before execution")
            return False

        results = self.run_r2_commands(default_commands)

        # Persist r2 command results
        result_data = "\n".join(
            f"--- Command: {cmd} ---\n{output}"
            for cmd, output in zip(default_commands, results)
        )
        result_file = write_generic_results(
            result_data, "raw_r2_session",
            extra_metadata={"binary": self.binary,
                            "commands_executed": len(results)})
        self.log(f"[C] Session results saved: {result_file}")

        if results:
            self.log("[+] MODE C: Radare2 manipulation completed")
            return True
        else:
            self.log("[W] MODE C: No results from Radare2")
            return False

class ModeD(BaseMode):
    """MODE D - Flutter Patcher

    Integrates the Flutter patching functionality:
    - APK merge (split APKs)
    - ARM64 extraction from APK
    - Blutter analysis
    - PP patching (0x20 <-> 0x30)
    - ASM folder search with regex
    - APK replacement
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 binary_path: str = None):
        super().__init__(log_callback, progress_callback)
        self.binary = binary_path

    def get_label(self) -> str:
        return "D"

    def execute(self) -> bool:
        """Execute MODE D - Flutter Patcher"""
        self.log("[*] MODE D: Flutter Patcher started...")
        self._stop_event.clear()

        if not self.binary:
            self.log("[!] MODE D: No APK path provided (use option [1] with APK path)")
            return False

        try:
            from .flutter.patcher import FlutterPatcher

            self.log("[D] Starting combined flutter patching...")
            self.progress(1, 2, "MODE D")

            if self.is_stopping():
                self.log("[W] MODE D: Stopped before patching")
                return False

            patcher = FlutterPatcher(
                enable_pp_patch=True,
                enable_asm_patch=True,
                enable_true_patch=False,
                enable_false_patch=True,
            )
            result_path = patcher.process_combined(self.binary)

            self.progress(2, 2, "MODE D")

            # Persist flutter patch summary
            result_file = write_generic_results(
                f"Flutter patching completed\nAPK path: {result_path}",
                "flutter_patcher",
                extra_metadata={"apk_path": self.binary,
                                "result_path": result_path})
            self.log(f"[D] Flutter patch results saved: {result_file}")

            self.log("[+] MODE D: Flutter patching completed")
            return True

        except Exception as e:
            self.log(f"[!] MODE D: Flutter patching error: {e}")
            result_file = write_generic_results(
                f"Flutter patching error: {e}",
                "flutter_patcher_error",
                extra_metadata={"apk_path": self.binary, "error": str(e)})
            self.log(f"[D] Error logged: {result_file}")
            return False

class ModeE(BaseMode):
    """MODE E - Find Functions

    Uses r2pipe to find functions with specific ARM64 patterns:
    - v2: stp x29, x30, [x15, -0x10]! + add x0, x22, 0x30 (specific x0)
    - v3: stp x29, x30, [x15, -0x10]! + add x<d+>, x<d+>, 0x30 (any register)
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 binary_path: str = None):
        super().__init__(log_callback, progress_callback)
        self.binary = binary_path

    def get_label(self) -> str:
        return "E"

    def execute(self) -> bool:
        """Execute MODE E - Find Functions"""
        self.log("[*] MODE E: Function finder started...")
        self._stop_event.clear()

        if not self.binary:
            self.log("[!] MODE E: No target binary selected (use option [1])")
            return False

        try:
            from .flutter.find_functions import FunctionFinder

            self.log("[E] Searching for v2 patterns (add x0, x22, 0x30)...")
            self.progress(1, 2, "MODE E")

            if self.is_stopping():
                self.log("[W] MODE E: Stopped before v2 search")
                return False

            finder = FunctionFinder(self.binary)

            v2_results = finder.find_v2()
            self.log(f"[+] v2: {len(v2_results)} functions found")

            # Persist v2 results
            result_file = write_function_results(
                v2_results, "v2",
                extra_metadata={"binary": self.binary, "pattern": "add x0, x22, 0x30"})
            self.log(f"[E] v2 results saved: {result_file}")

            self.progress(2, 2, "MODE E")

            if self.is_stopping():
                self.log("[W] MODE E: Stopped before v3 search")
                return True  # v2 already completed

            self.log("[E] Searching for v3 patterns (add x<d+>, x<d+>, 0x30)...")
            v3_results = finder.find_v3()
            self.log(f"[+] v3: {len(v3_results)} functions found")

            # Persist v3 results
            result_file = write_function_results(
                v3_results, "v3",
                extra_metadata={"binary": self.binary, "pattern": "add x<d+>, x<d+>, 0x30"})
            self.log(f"[E] v3 results saved: {result_file}")

            self.log(f"[+] MODE E: Function search completed (v2: {len(v2_results)}, v3: {len(v3_results)})")
            return True

        except Exception as e:
            self.log(f"[!] MODE E: Function search error: {e}")
            return False

class ModeF(BaseMode):
    """MODE F - Manifest Patcher

    APK manifest patching:
    - Decompile APK with APKEditor
    - Remove license check receivers
    - Fix extractNativeLibs attribute
    - Rebuild APK
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 binary_path: str = None):
        super().__init__(log_callback, progress_callback)
        self.binary = binary_path

    def get_label(self) -> str:
        return "F"

    def execute(self) -> bool:
        """Execute MODE F - Manifest Patcher"""
        self.log("[*] MODE F: Manifest Patcher started...")
        self._stop_event.clear()

        if not self.binary:
            self.log("[!] MODE F: No APK path provided (use option [1] with APK path)")
            return False

        try:
            from .flutter.manifest import process_manifest_patcher
            from .apk.editor import ensure_apkeditor

            self.log("[F] Locating APKEditor jar...")
            self.progress(1, 2, "MODE F")

            jar_file = ensure_apkeditor()
            if not jar_file:
                self.log("[!] MODE F: APKEditor jar not available")
                return False

            if self.is_stopping():
                self.log("[W] MODE F: Stopped before patching")
                return False

            self.log("[F] Patching AndroidManifest.xml...")
            self.progress(2, 2, "MODE F")

            success = process_manifest_patcher(self.binary, jar_file)

            # Persist manifest patch results
            result_file = write_generic_results(
                f"Manifest patching {'succeeded' if success else 'failed'}\nAPK: {self.binary}",
                "manifest_patcher",
                extra_metadata={"apk_path": self.binary, "success": success})
            self.log(f"[F] Manifest results saved: {result_file}")

            if success:
                self.log("[+] MODE F: Manifest patching completed")
            else:
                self.log("[W] MODE F: Manifest patching failed")

            return success

        except Exception as e:
            self.log(f"[!] MODE F: Manifest patching error: {e}")
            return False

def get_mode(mode_name: str, log_cb: Callable, progress_cb: Callable,
             binary_path: str = None, offset: str = None) -> BaseMode:
    """Factory: create a mode instance by name.

    Args:
        mode_name: 'A', 'B', 'C', 'D', 'E', or 'F'
        log_cb: Log callback function
        progress_cb: Progress callback function
        binary_path: Path to binary (for modes A/B/C/D/E/F)
        offset: Offset for MODE A

    Returns:
        Instance of the corresponding mode class

    Raises:
        ValueError: If mode_name is not A-F
    """
    mode_name = mode_name.upper()
    if mode_name == 'A':
        return ModeA(log_cb, progress_cb, binary_path, offset)
    elif mode_name == 'B':
        return ModeB(log_cb, progress_cb, binary_path)
    elif mode_name == 'C':
        return ModeC(log_cb, progress_cb, binary_path)
    elif mode_name == 'D':
        return ModeD(log_cb, progress_cb, binary_path)
    elif mode_name == 'E':
        return ModeE(log_cb, progress_cb, binary_path)
    elif mode_name == 'F':
        return ModeF(log_cb, progress_cb, binary_path)
    else:
        raise ValueError(f"Unknown mode: {mode_name}")
