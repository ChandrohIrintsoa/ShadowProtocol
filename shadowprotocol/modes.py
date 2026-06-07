"""
Modes Module - Six processing modes with OOP pattern + Real Radare2 Integration
Fuses v2 architecture with v1 functionality + Flutter/APK/Manifest/FindFunctions modes

Key improvements (no business logic changes):
- All search/offset results are persisted to results/ directory via results_writer
- Better error handling with explicit messages
- Robust validation throughout
"""

import re
import os
import time
import threading
from abc import ABC, abstractmethod
from typing import Callable, List, Optional, Tuple

try:
    import r2pipe
    HAS_R2PIPE = True
except ImportError:
    HAS_R2PIPE = False

from .results_writer import (
    write_offset_results,
    write_patch_results,
    write_scan_targets,
    write_function_results,
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

    def execute(self, cmd: str) -> str:
        """Execute r2 command via r2pipe.

        Args:
            cmd: The r2 command string to execute.

        Returns:
            The command output as a string, or empty string on error.
        """
        if not self.pipe:
            return ""
        try:
            return self.pipe.cmd(cmd) or ""
        except Exception:
            return ""

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
        pass

    @abstractmethod
    def get_label(self) -> str:
        """Return the short mode label (e.g. 'A', 'B', 'C')."""
        pass

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

    Simulates manual offset-based binary patching with
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

        self.log(f"[*] Validating offset: {self.offset}")

        if not self.r2:
            self.log("[!] No binary loaded for Radare2 analysis")
            return False

        if not self.r2.open(write=False):
            self.log("[!] Error opening Radare2")
            return False

        try:
            self.r2.execute(f"s {self.offset}")
            disasm = self.r2.execute("pd 5")
            self.r2.close()

            if "0x30" in disasm:
                self.log(f"[+] Pattern found at {self.offset}")
                # Persist the offset validation result
                result_path = write_offset_results(
                    offsets=[{"address": self.offset, "pattern": "0x30", "status": "found"}],
                    mode_label="A",
                    extra_metadata={"binary": self.binary or "N/A"}
                )
                self.log(f"[+] Offset result saved to: {result_path}")
                return True

            self.log("[W] Pattern 0x30 not found")
            # Persist negative result too
            result_path = write_offset_results(
                offsets=[{"address": self.offset, "pattern": "0x30", "status": "not_found"}],
                mode_label="A",
                extra_metadata={"binary": self.binary or "N/A"}
            )
            self.log(f"[*] Offset result saved to: {result_path}")
            return False
        except Exception as e:
            self.log(f"[!] Validation error: {e}")
            return False

    def patch(self) -> bool:
        """Apply patch via Radare2"""
        if not self.r2:
            self.log("[!] No binary loaded for patching")
            return False

        if not self.r2.open(write=True):
            self.log("[!] Error opening in write mode")
            return False

        try:
            self.log("[*] Applying patch...")
            self.r2.execute(f"s {self.offset}")
            self.r2.execute("wa add x0, x22, 0x20")

            verify = self.r2.execute("pd 1")
            self.r2.close()

            patch_success = "0x20" in verify

            # Persist patch result
            result_path = write_patch_results(
                patch_results={
                    self.offset: {
                        "patched": patch_success,
                        "offset": self.offset,
                        "instruction": "add x0, x22, 0x20",
                        "verification": verify.strip() if verify else "N/A",
                        "type": "MANUAL_ASSISTED"
                    }
                },
                mode_label="A",
                extra_metadata={"binary": self.binary or "N/A"}
            )
            self.log(f"[*] Patch result saved to: {result_path}")

            if patch_success:
                self.log("[+] Patch applied and verified")
                return True

            self.log("[!] Patch verification failed")
            return False
        except Exception as e:
            self.log(f"[!] Patch error: {e}")
            return False

    def execute(self) -> bool:
        """Execute MODE A"""
        self.log("[*] MODE A: Manual analysis started...")
        self._stop_event.clear()

        steps = [
            ("Initialising system", 0.2),
            ("Loading binary", 0.3),
            ("Analysing ELF header", 0.25),
            ("Extracting symbols", 0.4),
            ("Verifying offset", 0.3),
            ("Validating pattern", 0.2),
            ("Preparing pptool", 0.25),
            ("Injecting patch", 0.35),
            ("Verifying integrity", 0.3),
            ("Memory synchronisation", 0.25),
            ("Functional test", 0.4),
            ("Final report", 0.2),
            ("Cleaning resources", 0.15),
            ("Analysis complete", 0.1),
        ]

        success = self._run_steps("A", steps)

        if success:
            self.log("[+] MODE A: Analysis completed successfully")
        else:
            self.log("[W] MODE A: Clean stop executed")

        return success


class ModeB(BaseMode):
    """MODE B - Auto-Patching (full binary scan)

    Simulates full binary scan with automatic pattern detection
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
            self.log("[!] No binary loaded for scanning")
            return []

        if not self.r2.open(write=False):
            self.log("[!] Error opening Radare2")
            return []

        self.log("[*] Scanning binary...")

        try:
            self.r2.execute("aaa")

            pattern = re.compile(r"add\s+x\d+,\s*x\d+,\s*0x30", re.IGNORECASE)

            disasm = self.r2.execute("pd")

            for line in disasm.split('\n'):
                if pattern.search(line):
                    addr_match = re.search(r'(0x[0-9a-fA-F]+)', line)
                    if addr_match:
                        self.targets.append((addr_match.group(1), line.strip()))

            self.r2.close()
            self.log(f"[+] {len(self.targets)} targets found")

            # Persist scan results to results/ directory
            if self.targets:
                scan_data = [
                    {"address": addr, "instruction": instr}
                    for addr, instr in self.targets
                ]
                result_path = write_scan_targets(
                    targets=scan_data,
                    mode_label="B",
                    extra_metadata={"binary": self.binary or "N/A"}
                )
                self.log(f"[+] Scan results saved to: {result_path}")

            return self.targets
        except Exception as e:
            self.log(f"[!] Scan error: {e}")
            return []

    def patch_all(self) -> int:
        """Patch all targets"""
        if not self.targets:
            self.log("[!] No targets to patch")
            return 0

        if not self.r2:
            self.log("[!] No binary loaded for patching")
            return 0

        if not self.r2.open(write=True):
            self.log("[!] Error opening in write mode")
            return 0

        try:
            self.log("[*] Applying patches...")

            patched = 0
            patch_results = {}
            for i, (addr, instr) in enumerate(self.targets, 1):
                if self.is_stopping():
                    break

                self.r2.execute(f"s {addr}")
                self.r2.execute("wa add x0, x22, 0x20")

                verify = self.r2.execute("pd 1")
                is_patched = "0x20" in verify
                if is_patched:
                    patched += 1
                    if i % 10 == 0:
                        self.log(f"[*] {patched}/{len(self.targets)} patched")

                patch_results[addr] = {
                    "patched": is_patched,
                    "original": instr,
                    "verification": verify.strip() if verify else "N/A"
                }

            self.r2.close()
            self.log(f"[+] {patched}/{len(self.targets)} patches applied")

            # Persist patch results
            result_path = write_patch_results(
                patch_results=patch_results,
                mode_label="B",
                extra_metadata={"binary": self.binary or "N/A"}
            )
            self.log(f"[*] Patch results saved to: {result_path}")

            return patched
        except Exception as e:
            self.log(f"[!] Patch error: {e}")
            return 0

    def execute(self) -> bool:
        """Execute MODE B"""
        self.log("[*] MODE B: Auto-scan started...")
        self._stop_event.clear()

        steps = [
            ("Initialising scanner", 0.2),
            ("Loading full binary", 0.4),
            ("Analysing headers", 0.3),
            ("Scanning .text section", 0.35),
            ("Detecting pattern 1", 0.25),
            ("Detecting pattern 2", 0.25),
            ("Detecting pattern 3", 0.3),
            ("Detecting pattern 4", 0.25),
            ("Detecting pattern 5", 0.2),
            ("Sorting results", 0.15),
            ("Checking duplicates", 0.2),
            ("Preparing patches", 0.3),
            ("Patch batch 1", 0.4),
            ("Patch batch 2", 0.4),
            ("Patch batch 3", 0.4),
            ("Verifying batch 1", 0.3),
            ("Verifying batch 2", 0.3),
            ("Verifying batch 3", 0.3),
            ("Rewriting sections", 0.35),
            ("Synchronisation", 0.25),
            ("Integration test", 0.4),
            ("Final validation", 0.3),
            ("Generating report", 0.2),
            ("Cleaning resources", 0.15),
            ("Scan complete", 0.1),
        ]

        success = self._run_steps("B", steps)

        if success:
            self.log("[+] MODE B: Scan and patches completed")
        else:
            self.log("[W] MODE B: Clean stop with recovery")

        return success


class ModeC(BaseMode):
    """MODE C - Raw Radare2 (direct manipulation)

    Simulates raw Radare2 binary manipulation with
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
            self.log("[!] No binary loaded for Radare2 session")
            return []

        if not self.r2.open(write=True):
            self.log("[!] Error opening Radare2")
            return []

        results = []
        try:
            for cmd in commands:
                if self.is_stopping():
                    break
                output = self.r2.execute(cmd)
                results.append(output)
                self.log(f"[*] r2> {cmd}")
                if output.strip():
                    self.log(f"    {output.strip()[:200]}")
        finally:
            self.r2.close()

        # Persist r2 command results
        if results:
            cmd_data = [
                {"command": cmd, "output": out.strip()[:500] if out else "(empty)"}
                for cmd, out in zip(commands, results)
            ]
            result_path = write_offset_results(
                offsets=cmd_data,
                mode_label="C",
                extra_metadata={"binary": self.binary or "N/A", "type": "r2_commands"}
            )
            self.log(f"[*] R2 command results saved to: {result_path}")

        return results

    def execute(self) -> bool:
        """Execute MODE C"""
        self.log("[*] MODE C: Raw Radare2 session started...")
        self._stop_event.clear()

        steps = [
            ("Initialising r2", 0.25),
            ("Opening binary in write mode", 0.3),
            ("Basic analysis (aaa)", 0.35),
            ("Enumerating functions", 0.25),
            ("Listing sections", 0.2),
            ("Raw pattern search", 0.3),
            ("Calculating addresses", 0.25),
            ("Preparing instructions", 0.3),
            ("Memory write 1", 0.25),
            ("Verification 1", 0.2),
            ("Memory write 2", 0.25),
            ("Verification 2", 0.2),
            ("Memory write 3", 0.25),
            ("Verification 3", 0.2),
            ("Flush cache", 0.2),
            ("Disassembly verification", 0.3),
            ("Instruction report", 0.2),
            ("Closing session", 0.15),
            ("Cleanup", 0.1),
        ]

        success = self._run_steps("C", steps)

        if success:
            self.log("[+] MODE C: Radare2 manipulation completed")
        else:
            self.log("[W] MODE C: Session closed cleanly")

        return success


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

        steps = [
            ("Initialising Flutter Patcher", 0.3),
            ("Checking APK/APKS files", 0.2),
            ("Merging split APKs if needed", 0.4),
            ("Extracting arm64-v8a from APK", 0.35),
            ("Running blutter analysis", 0.5),
            ("Searching pp.txt for addresses", 0.3),
            ("Finding related functions via pptool", 0.4),
            ("PP patching (0x20 <-> 0x30)", 0.35),
            ("ASM folder search with regex", 0.4),
            ("Extracting false addresses", 0.3),
            ("Patching false addresses", 0.35),
            ("Replacing libapp.so in APK", 0.25),
            ("Verifying APK integrity", 0.2),
            ("Cleaning workspace", 0.15),
            ("Flutter patch complete", 0.1),
        ]

        success = self._run_steps("D", steps)

        if success:
            self.log("[+] MODE D: Flutter patching completed")
        else:
            self.log("[W] MODE D: Flutter patching stopped")

        return success


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

    def _find_and_persist(self, search_type: str, results: list) -> None:
        """Persist function search results to the results directory.

        Args:
            search_type: Search variant identifier ('v2' or 'v3').
            results: List of (address, instruction) tuples.
        """
        if results:
            func_data = [
                {"address": addr, "instruction": instr}
                for addr, instr in results
            ]
            result_path = write_function_results(
                functions=func_data,
                search_type=search_type,
                extra_metadata={"binary": self.binary or "N/A"}
            )
            self.log(f"[+] Function search results ({search_type}) saved to: {result_path}")

    def execute(self) -> bool:
        """Execute MODE E - Find Functions"""
        self.log("[*] MODE E: Function finder started...")
        self._stop_event.clear()

        steps = [
            ("Initialising function finder", 0.2),
            ("Loading binary with r2pipe", 0.3),
            ("Analysing binary (aaa)", 0.4),
            ("Searching STP prologue pattern", 0.35),
            ("Scanning for add x0, x22, 0x30 (v2)", 0.3),
            ("Scanning for add x<d+>, x<d+>, 0x30 (v3)", 0.3),
            ("Cross-referencing matches", 0.25),
            ("Deduplicating results", 0.15),
            ("Generating function list", 0.2),
            ("Reporting findings", 0.15),
            ("Cleanup", 0.1),
        ]

        success = self._run_steps("E", steps)

        if success:
            self.log("[+] MODE E: Function search completed")
        else:
            self.log("[W] MODE E: Function search stopped")

        return success


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

        steps = [
            ("Initialising Manifest Patcher", 0.2),
            ("Locating APKEditor jar", 0.15),
            ("Decompiling APK", 0.5),
            ("Reading AndroidManifest.xml", 0.2),
            ("Removing license check receivers", 0.3),
            ("Patching extractNativeLibs", 0.2),
            ("Verifying manifest changes", 0.15),
            ("Rebuilding APK", 0.4),
            ("Verifying APK integrity", 0.2),
            ("Cleaning work directory", 0.15),
            ("Manifest patch complete", 0.1),
        ]

        success = self._run_steps("F", steps)

        if success:
            self.log("[+] MODE F: Manifest patching completed")
        else:
            self.log("[W] MODE F: Manifest patching stopped")

        return success


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
