"""
ShadowProtocol - Selecteur de Cible

Detection, validation et selection de fichiers .so.
Support de l'entree manuelle et de la detection automatique
des librairies natives Android dans le repertoire courant.
"""

import os
from pathlib import Path
from typing import List, Optional, Tuple

class TargetValidator:
    """Validateur d'integrite des fichiers ELF .so"""

    @staticmethod
    def is_valid_so(path: str) -> bool:
        """Verifier la signature magique ELF."""
        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
                return magic == b'\x7fELF'
        except Exception:
            return False

    @staticmethod
    def get_arch(path: str) -> Optional[str]:
        """Determiner l'architecture du binaire."""
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
        """Verifier les permissions d'ecriture."""
        return os.access(path, os.W_OK)

class TargetSelector:
    """Selection de cible avec detection automatique et entree manuelle."""

    def __init__(self, start_path: str = "."):
        self.start_path = Path(start_path)
        self.validator = TargetValidator()

    def find_targets(self, recursive: bool = True) -> List[str]:
        """Trouver tous les fichiers .so valides."""
        targets = []
        pattern = self.start_path.rglob("*.so") if recursive else self.start_path.glob("*.so")
        for path in pattern:
            if self.validator.is_valid_so(str(path)):
                targets.append(str(path))
        return sorted(targets)

    def validate_manual_path(self, path: str) -> Optional[str]:
        """Valider un chemin de fichier entre manuellement.

        Accepte tout chemin valide, verifie l'existence et la
        signature ELF. Rejette les liens symboliques et repertoires.
        """
        if not path or not path.strip():
            return None

        path = path.strip()
        path = os.path.expanduser(path)
        path = os.path.expandvars(path)

        try:
            abs_path = os.path.abspath(path)
        except (OSError, ValueError):
            return None

        if os.path.islink(abs_path):
            return None
        if not os.path.isfile(abs_path):
            return None
        if not os.access(abs_path, os.R_OK):
            return None
        if not self.validator.is_valid_so(abs_path):
            return None

        return abs_path

    def get_file_info(self, path: str) -> Tuple[str, str, str, str]:
        """Recuperer les informations d'un fichier cible.

        Returns:
            (nom, arch, taille_formatee, rw)
        """
        name = os.path.basename(path)
        arch = self.validator.get_arch(path) or "Inconnu"
        writable = "Oui" if self.validator.is_writable(path) else "Non"
        try:
            size_bytes = os.path.getsize(path)
            if size_bytes >= 1024 * 1024:
                size = f"{size_bytes / 1024 / 1024:.1f} Mo"
            elif size_bytes >= 1024:
                size = f"{size_bytes / 1024:.1f} Ko"
            else:
                size = f"{size_bytes} o"
        except OSError:
            size = "N/A"
        return name, arch, size, writable

    def select_interactive(self, targets: List[str]) -> Optional[str]:
        """Selection interactive (fallback, NON TUI-safe).

        WARNING: Utilise print() et input() qui conflictent
        avec curses TUI. Utiliser validate_manual_path() avec
        le mode saisie TUI a la place.
        """
        if not targets:
            return None

        for i, target in enumerate(targets, 1):
            arch = self.validator.get_arch(target)
            writable = "Oui" if self.validator.is_writable(target) else "Non"
            try:
                size_bytes = os.path.getsize(target)
                size = f"{size_bytes / 1024 / 1024:.2f} Mo"
            except OSError:
                size = "N/A"

            print(f"[{i}] {target}")
            print(f"    Arch: {arch} | RW: {writable} | Taille: {size}")

        try:
            choice = int(input(f"\nSelectionner cible [1-{len(targets)}]: "))
            if 1 <= choice <= len(targets):
                return targets[choice - 1]
        except (ValueError, IndexError):
            pass

        return None
