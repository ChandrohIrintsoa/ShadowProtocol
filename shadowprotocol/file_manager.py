"""
File Manager - Handle target files, backups, and output organization
Supports auto-detection, multiple targets, and skull (☠️) output folder.
"""

import os
import shutil
from pathlib import Path
from typing import List, Optional, Tuple


class FileManager:
    """Manage patched files, backups, and output organization"""

    SKULL_FOLDER = "☠️"

    def __init__(self, target_path: str):
        """Initialize file manager for a target.

        Args:
            target_path: Path to the target file
        """
        self.target_path = Path(target_path)
        self.target_dir = self.target_path.parent
        self.skull_dir = self.target_dir / self.SKULL_FOLDER

    def create_skull_folder(self) -> bool:
        """Create ☠️ folder for patched files.

        Returns:
            True if created/exists, False if error
        """
        try:
            self.skull_dir.mkdir(exist_ok=True, mode=0o755)
            return True
        except Exception:
            return False

    def move_patched_file(self, patched_path: str) -> Optional[str]:
        """Move patched file to ☠️ folder.

        Args:
            patched_path: Path to the patched file

        Returns:
            Path in ☠️ folder, or None if error
        """
        if not self.create_skull_folder():
            return None

        try:
            patched = Path(patched_path)
            dest = self.skull_dir / patched.name
            shutil.move(str(patched), str(dest))
            return str(dest)
        except Exception:
            return None

    def copy_patched_file(self, patched_path: str) -> Optional[str]:
        """Copy patched file to ☠️ folder (keep original).

        Args:
            patched_path: Path to the patched file

        Returns:
            Path in ☠️ folder, or None if error
        """
        if not self.create_skull_folder():
            return None

        try:
            patched = Path(patched_path)
            dest = self.skull_dir / patched.name
            shutil.copy2(str(patched), str(dest))
            return str(dest)
        except Exception:
            return None

    @staticmethod
    def find_targets_in_path(path: str, extensions: List[str] = None) -> List[Tuple[str, str]]:
        """Find all target files in a path.

        Args:
            path: Directory or file path
            extensions: File extensions to search (.so, .apk, etc)

        Returns:
            List of (file_path, file_type) tuples
        """
        if extensions is None:
            extensions = ['so', 'apk', 'elf', 'bin']

        targets = []
        path_obj = Path(path)

        if path_obj.is_file():
            targets.append((str(path_obj), path_obj.suffix[1:] or 'unknown'))
        elif path_obj.is_dir():
            for ext in extensions:
                for match in path_obj.rglob(f"*.{ext}"):
                    if match.is_file() and match.name != "SKIP_ME":
                        targets.append((str(match), ext))

        return sorted(targets, key=lambda x: x[0])

    @staticmethod
    def select_target(targets: List[Tuple[str, str]]) -> Optional[str]:
        """Let user select from multiple targets.

        Args:
            targets: List of (file_path, file_type) tuples

        Returns:
            Selected target path, or None
        """
        if not targets:
            return None
        if len(targets) == 1:
            return targets[0][0]

        print("\n[*] Multiple targets found:")
        for i, (path, ext) in enumerate(targets, 1):
            size = os.path.getsize(path) / 1024 / 1024
            print(f"  [{i}] {Path(path).name} ({ext}) - {size:.2f}MB")

        try:
            choice = int(input(f"\nSelect target [1-{len(targets)}]: "))
            if 1 <= choice <= len(targets):
                return targets[choice - 1][0]
        except (ValueError, KeyboardInterrupt):
            pass

        return None

    def cleanup_targets(self, keep_patched: bool = True) -> bool:
        """Clean up target files and caches.

        Args:
            keep_patched: If True, keep patched files in ☠️

        Returns:
            True if cleanup succeeded
        """
        try:
            # Delete original target
            if self.target_path.exists():
                self.target_path.unlink()

            # Delete cache files
            cache_patterns = ['.shadowprotocol_session', '*.pyc', '__pycache__']
            for pattern in cache_patterns:
                if '*' in pattern:
                    for match in self.target_dir.glob(pattern):
                        if match.is_dir():
                            shutil.rmtree(match, ignore_errors=True)
                        else:
                            match.unlink(missing_ok=True)
                else:
                    (self.target_dir / pattern).unlink(missing_ok=True)

            return True
        except Exception:
            return False

    def get_skull_contents(self) -> List[str]:
        """Get list of patched files in ☠️ folder.

        Returns:
            List of file paths
        """
        if not self.skull_dir.exists():
            return []

        return [str(f) for f in self.skull_dir.iterdir() if f.is_file()]

    def cleanup_logs(self, pattern: str = "*.log") -> int:
        """Clean up activity logs.

        Args:
            pattern: Log file pattern

        Returns:
            Number of logs deleted
        """
        count = 0
        for log in self.target_dir.glob(pattern):
            try:
                log.unlink()
                count += 1
            except Exception:
                pass

        return count
