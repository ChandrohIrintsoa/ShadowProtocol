"""
Target Selector - Detect & select .so files

Provides target detection and formatting for the TUI.
Selection is handled by the UI layer, not by print/input.
"""

import os
from pathlib import Path
from typing import List, Optional, Tuple


class TargetValidator:
    """Validate .so file integrity"""

    @staticmethod
    def is_valid_so(path: str) -> bool:
        """Verify ELF binary"""
        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
                return magic == b'\x7fELF'
        except Exception:
            return False

    @staticmethod
    def get_arch(path: str) -> Optional[str]:
        """Get binary architecture"""
        try:
            with open(path, 'rb') as f:
                f.seek(0x12)
                machine = int.from_bytes(f.read(2), 'little')
                archs = {0xB7: "ARM64", 0x03: "i386", 0x3E: "x86_64"}
                return archs.get(machine)
        except Exception:
            return None

    @staticmethod
    def is_writable(path: str) -> bool:
        """Check write permissions"""
        return os.access(path, os.W_OK)


class TargetSelector:
    """Target selection with TUI-compatible formatting.

    The select_interactive() method no longer uses print()/input() directly.
    Instead, it returns formatted data that the UI layer renders and handles
    input for, keeping the TUI in control of the screen.
    """

    def __init__(self, start_path: str = "."):
        """Initialize selector"""
        self.start_path = Path(start_path)
        self.validator = TargetValidator()

    def find_targets(self, recursive: bool = True) -> List[str]:
        """Find all .so files"""
        targets = []

        if recursive:
            pattern = self.start_path.rglob("*.so")
        else:
            pattern = self.start_path.glob("*.so")

        for path in pattern:
            if self.validator.is_valid_so(str(path)):
                targets.append(str(path))

        return sorted(targets)

    def format_target_list(self, targets: List[str]) -> List[Tuple[int, str, str, str, float]]:
        """Format target list for TUI display.

        Args:
            targets: List of target file paths.

        Returns:
            List of (index, path, arch, rw, size_mb) tuples for display.
        """
        formatted = []
        for i, target in enumerate(targets, 1):
            arch = self.validator.get_arch(target) or "Unknown"
            writable = "Y" if self.validator.is_writable(target) else "N"
            try:
                size = os.path.getsize(target) / 1024 / 1024
            except OSError:
                size = 0.0
            formatted.append((i, target, arch, writable, size))
        return formatted

    def select_interactive(self, targets: List[str]) -> Optional[str]:
        """Interactive selection menu (fallback for non-TUI usage).

        WARNING: This uses print/input directly and should NOT be called
        when the TUI is active. Use the TUI selection mode instead.

        Args:
            targets: List of target file paths.

        Returns:
            Selected target path, or None if cancelled.
        """
        if not targets:
            return None

        for i, target in enumerate(targets, 1):
            arch = self.validator.get_arch(target)
            writable = "Y" if self.validator.is_writable(target) else "N"
            size = os.path.getsize(target) / 1024 / 1024

            print(f"[{i}] {target}")
            print(f"    Arch: {arch} | RW: {writable} | Size: {size:.2f}MB")

        try:
            choice = int(input(f"\nSelect target [1-{len(targets)}]: "))
            if 1 <= choice <= len(targets):
                return targets[choice - 1]
        except (ValueError, IndexError):
            pass

        return None

    def get_target_by_index(self, targets: List[str], index: int) -> Optional[str]:
        """Get target by 1-based index.

        Args:
            targets: List of target file paths.
            index: 1-based index.

        Returns:
            Target path if valid index, None otherwise.
        """
        if 1 <= index <= len(targets):
            return targets[index - 1]
        return None

    def select_path(self, path: str) -> Optional[str]:
        """Select specific file or directory (non-TUI fallback)"""
        path = Path(path)

        if path.is_file():
            if self.validator.is_valid_so(str(path)):
                return str(path)
            return None

        elif path.is_dir():
            targets = self.find_targets()
            if targets:
                return self.select_interactive(targets)
            return None

        return None
