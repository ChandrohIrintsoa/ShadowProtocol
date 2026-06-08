"""
Target Selector - Multi-format target detection & selection
Supports .so (ELF), .apk (APK), and custom binary formats.
Accepts both file paths and directory paths with recursive search.
"""

import os
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple

class TargetValidator:
    """Multi-format target validator (.so, .apk, binaries)"""

    VALID_EXTENSIONS = {'.so', '.apk', '.bin', '.elf', '.exe', '.a', '.o'}

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
    def is_valid_apk(path: str) -> bool:
        """Verify APK (ZIP with AndroidManifest.xml)"""
        try:
            if not zipfile.is_zipfile(path):
                return False
            with zipfile.ZipFile(path, 'r') as z:
                return 'AndroidManifest.xml' in z.namelist()
        except Exception:
            return False

    @staticmethod
    def detect_target_type(path: str) -> Optional[str]:
        """Detect target type by magic bytes and extension"""
        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
        except Exception:
            return None

        if magic == b'\x7fELF':
            return 'ELF'
        if magic[:2] == b'PK':
            if TargetValidator.is_valid_apk(path):
                return 'APK'
        return None

    @staticmethod
    def get_arch(path: str) -> Optional[str]:
        """Get binary architecture (ELF only)"""
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
    """Multi-format target selector with Path support (.so, .apk, etc)"""

    def __init__(self, start_path: str = "."):
        """Initialize selector with start path"""
        self.start_path = Path(start_path)
        self.validator = TargetValidator()

    def find_targets(self, recursive: bool = True,
                    target_types: Optional[List[str]] = None) -> List[Tuple[str, str]]:
        """Find targets (.so, .apk, etc).

        Args:
            recursive: Search recursively in subdirectories
            target_types: Types to find ['so', 'apk', etc]. None = all types

        Returns:
            List of (path, type) tuples
        """
        if target_types is None:
            target_types = ['so', 'apk']

        targets = []
        patterns = [f"*.{ext}" for ext in target_types]

        for pattern in patterns:
            if recursive:
                paths = self.start_path.rglob(pattern)
            else:
                paths = self.start_path.glob(pattern)

            for path in paths:
                if path.is_file():
                    target_type = self.validator.detect_target_type(str(path))
                    if target_type:
                        targets.append((str(path), target_type))

        return sorted(targets, key=lambda x: x[0])

    def validate_manual_path(self, path: str) -> Optional[str]:
        """Validate target file via Path (supports .so, .apk, etc).

        Accepts:
        - Relative paths: ./lib/libapp.so, ../target.apk
        - Absolute paths: /home/user/lib.so, /data/app.apk
        - Environment variables: $HOME/lib.so, ~/app.apk
        - File extensions: .so, .apk, .bin, .elf, etc

        Rejects:
        - Non-existent files
        - Symlinks
        - Directories
        - Unreadable files

        Args:
            path: File path (relative, absolute, or with env vars)

        Returns:
            Validated absolute path if valid, None otherwise
        """
        if not path or not path.strip():
            return None

        path = path.strip()

        # Expand ~ (home) and environment variables
        path = os.path.expanduser(path)
        path = os.path.expandvars(path)

        # Resolve to absolute path
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

        # Validate by type
        target_type = self.validator.detect_target_type(abs_path)
        if not target_type:
            # Fallback: check if valid ELF
            if not self.validator.is_valid_so(abs_path):
                return None

        return abs_path

    def get_file_info(self, path: str) -> str:
        """Get formatted file information (supports .so, .apk, etc).

        Args:
            path: Validated file path

        Returns:
            Formatted info string with type, arch, permissions, size
        """
        target_type = self.validator.detect_target_type(path) or "Unknown"
        writable = "Y" if self.validator.is_writable(path) else "N"

        arch = ""
        if target_type == "ELF":
            arch = self.validator.get_arch(path) or "Unknown"
            arch = f" | Arch: {arch}"

        try:
            size = os.path.getsize(path) / 1024 / 1024
            return f"Type: {target_type}{arch} | RW: {writable} | Size: {size:.2f}MB"
        except OSError:
            return f"Type: {target_type}{arch} | RW: {writable}"

    def select_interactive(self, targets: List[Tuple[str, str]]) -> Optional[str]:
        """Interactive selection menu (fallback, NOT TUI-safe).

        WARNING: This method uses print() and input() which conflict
        with curses TUI. Use validate_manual_path() with TUI input mode
        instead.

        Args:
            targets: List of (path, type) tuples

        Returns:
            Selected file path, or None if cancelled
        """
        if not targets:
            return None

        for i, (target, target_type) in enumerate(targets, 1):
            writable = "Y" if self.validator.is_writable(target) else "N"
            size = os.path.getsize(target) / 1024 / 1024

            arch = ""
            if target_type == "ELF":
                arch = self.validator.get_arch(target) or "Unknown"
                arch = f" | Arch: {arch}"

            print(f"[{i}] {target}")
            print(f"    Type: {target_type}{arch} | RW: {writable} | Size: {size:.2f}MB")

        try:
            choice = int(input(f"\nSelect target [1-{len(targets)}]: "))
            if 1 <= choice <= len(targets):
                return targets[choice - 1][0]
        except (ValueError, IndexError):
            pass

        return None

    def select_path(self, path: str) -> Optional[str]:
        """Select specific file or directory with multi-format support"""
        path = Path(path)

        if path.is_file():
            validated = self.validate_manual_path(str(path))
            return validated

        elif path.is_dir():
            targets = self.find_targets()
            if targets:
                return self.select_interactive(targets)
            return None

        return None
