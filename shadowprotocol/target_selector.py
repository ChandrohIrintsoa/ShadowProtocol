"""
Target Selector - Detect, validate & select .so files
Supports both manual path entry and interactive list selection.
"""

import os
from pathlib import Path
from typing import List, Optional


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
    """Target selection with manual path entry and auto-detection"""

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

    def validate_manual_path(self, path: str) -> Optional[str]:
        """Validate a manually entered file path.

        Accepts any valid file path (not just .so extension),
        verifies the file exists and is a valid ELF binary.
        Rejects symlinks, directories, and unreadable files.

        Args:
            path: The file path entered by the user.

        Returns:
            The validated absolute path if valid, None otherwise.
        """
        if not path or not path.strip():
            return None

        path = path.strip()

        # Expand ~ and environment variables
        path = os.path.expanduser(path)
        path = os.path.expandvars(path)

        # Resolve to absolute path (follows symlinks)
        try:
            abs_path = os.path.abspath(path)
        except (OSError, ValueError):
            return None

        # Reject symlinks
        if os.path.islink(abs_path):
            return None

        # Check if file exists
        if not os.path.isfile(abs_path):
            return None

        # Must have read permission
        if not os.access(abs_path, os.R_OK):
            return None

        # Validate ELF binary
        if not self.validator.is_valid_so(abs_path):
            return None

        return abs_path

    def get_file_info(self, path: str) -> str:
        """Get formatted file information for a validated target.

        Args:
            path: Validated file path.

        Returns:
            Formatted info string (arch, writable, size).
        """
        arch = self.validator.get_arch(path) or "Unknown"
        writable = "Y" if self.validator.is_writable(path) else "N"
        try:
            size = os.path.getsize(path) / 1024 / 1024
            return f"Arch: {arch} | RW: {writable} | Size: {size:.2f}MB"
        except OSError:
            return f"Arch: {arch} | RW: {writable}"

    def select_interactive(self, targets: List[str]) -> Optional[str]:
        """Interactive selection menu (fallback, NOT TUI-safe).

        WARNING: This method uses print() and input() which conflict
        with curses TUI. Use validate_manual_path() with TUI input mode
        instead.

        Args:
            targets: List of target file paths.

        Returns:
            Selected file path, or None if cancelled.
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

    def select_path(self, path: str) -> Optional[str]:
        """Select specific file or directory"""
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
