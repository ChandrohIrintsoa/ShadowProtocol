"""
Find Functions - ARM64 function pattern finding

Merged from find_fnc_v2.py and find_fnc_v3.py:
- v2: Finds functions with `stp x29, x30, [x15, -0x10]!` + `add x0, x22, 0x30` (specific x0 register)
- v3: Finds functions with `stp x29, x30, [x15, -0x10]!` + `add x<d+>, x<d+>, 0x30` (any register)

Uses r2pipe for proper Radare2 API integration.
"""

import re
from typing import List, Tuple

try:
    import r2pipe
    HAS_R2PIPE = True
except ImportError:
    HAS_R2PIPE = False

class FunctionFinder:
    """Find ARM64 functions matching specific instruction patterns.

    Provides two search modes:
    - v2: Specific x0 register pattern
    - v3: Any register pattern
    """

    # STP prologue pattern: stp x29, x30, [xN, -0x10]!
    STP_PROLOGUE = r"stp\s+x29,\s*x30,\s*\[x(\d+),\s*-0x10\]!"

    # v2: add x0, x22, 0x30 (specific x0 register)
    ADD_X0_PATTERN = r"add\s+x0,\s*x22,\s*0x30"

    # v3: add x<d+>, x<d+>, 0x30 (any register)
    ADD_ANY_PATTERN = r"add\s+x\d+,\s*x\d+,\s*0x30"

    def __init__(self, binary_path: str):
        """Initialize FunctionFinder.

        Args:
            binary_path: Path to the ARM64 binary to analyze.
        """
        self.binary_path = binary_path
        self._r2 = None

    def _open(self) -> bool:
        """Open the binary with r2pipe.

        Returns:
            True if opened successfully.
        """
        if not HAS_R2PIPE:
            return False
        try:
            self._r2 = r2pipe.open(self.binary_path, flags=["-2"])
            self._r2.cmd("aaa")
            return True
        except Exception:
            self._r2 = None
            return False

    def _close(self):
        """Close the r2pipe session."""
        if self._r2:
            try:
                self._r2.quit()
            except Exception:
                pass
            finally:
                self._r2 = None

    def find_v2(self) -> List[Tuple[str, str]]:
        """Find functions with stp prologue + add x0, x22, 0x30.

        Searches for the pattern combination:
        1. stp x29, x30, [xN, -0x10]!  (function prologue)
        2. add x0, x22, 0x30            (specific x0 register)

        Returns:
            List of (function_address, instruction) tuples.
        """
        if not self._open():
            return []

        results = []
        try:
            # Get all functions
            func_list = self._r2.cmd("afl")
            functions = []

            for line in func_list.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    addr = parts[0]
                    functions.append(addr)

            # Search each function for the patterns
            stp_re = re.compile(self.STP_PROLOGUE, re.IGNORECASE)
            add_x0_re = re.compile(self.ADD_X0_PATTERN, re.IGNORECASE)

            for func_addr in functions:
                if not func_addr.startswith("0x"):
                    continue

                # Get disassembly of the function
                self._r2.cmd(f"s {func_addr}")
                disasm = self._r2.cmd("pdr")

                if not disasm:
                    continue

                has_stp = False
                has_add_x0 = False

                for line in disasm.splitlines():
                    if stp_re.search(line):
                        has_stp = True
                    if add_x0_re.search(line):
                        has_add_x0 = True

                if has_stp and has_add_x0:
                    # Find the exact address of the add instruction
                    for line in disasm.splitlines():
                        if add_x0_re.search(line):
                            addr_match = re.search(r"(0x[0-9a-fA-F]+)", line)
                            if addr_match:
                                results.append((addr_match.group(1), line.strip()))
                                break

        except Exception as e:
            print(f"v2 search error: {e}")
        finally:
            self._close()

        return results

    def find_v3(self) -> List[Tuple[str, str]]:
        """Find functions with stp prologue + add x<d+>, x<d+>, 0x30.

        Searches for the pattern combination:
        1. stp x29, x30, [xN, -0x10]!  (function prologue)
        2. add x<d+>, x<d+>, 0x30       (any register)

        Returns:
            List of (function_address, instruction) tuples.
        """
        if not self._open():
            return []

        results = []
        try:
            # Get all functions
            func_list = self._r2.cmd("afl")
            functions = []

            for line in func_list.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    addr = parts[0]
                    functions.append(addr)

            # Search each function for the patterns
            stp_re = re.compile(self.STP_PROLOGUE, re.IGNORECASE)
            add_any_re = re.compile(self.ADD_ANY_PATTERN, re.IGNORECASE)

            for func_addr in functions:
                if not func_addr.startswith("0x"):
                    continue

                # Get disassembly of the function
                self._r2.cmd(f"s {func_addr}")
                disasm = self._r2.cmd("pdr")

                if not disasm:
                    continue

                has_stp = False
                has_add = False

                for line in disasm.splitlines():
                    if stp_re.search(line):
                        has_stp = True
                    if add_any_re.search(line):
                        has_add = True

                if has_stp and has_add:
                    # Find all add instructions matching the pattern
                    for line in disasm.splitlines():
                        if add_any_re.search(line):
                            addr_match = re.search(r"(0x[0-9a-fA-F]+)", line)
                            if addr_match:
                                results.append((addr_match.group(1), line.strip()))

        except Exception as e:
            print(f"v3 search error: {e}")
        finally:
            self._close()

        return results

    def find_all(self) -> dict:
        """Run both v2 and v3 searches.

        Returns:
            Dict with 'v2' and 'v3' keys, each containing a list of
            (address, instruction) tuples.
        """
        return {
            'v2': self.find_v2(),
            'v3': self.find_v3()
        }

def find_functions_v2(binary_path: str) -> List[Tuple[str, str]]:
    """Standalone function: find functions with x0-specific pattern.

    Args:
        binary_path: Path to the ARM64 binary.

    Returns:
        List of (address, instruction) tuples.
    """
    finder = FunctionFinder(binary_path)
    return finder.find_v2()

def find_functions_v3(binary_path: str) -> List[Tuple[str, str]]:
    """Standalone function: find functions with any-register pattern.

    Args:
        binary_path: Path to the ARM64 binary.

    Returns:
        List of (address, instruction) tuples.
    """
    finder = FunctionFinder(binary_path)
    return finder.find_v3()
