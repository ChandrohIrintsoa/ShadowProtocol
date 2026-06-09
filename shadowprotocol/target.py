"""
ShadowProtocol - Selecteur de Cible (Multi-format)

Detection, validation et selection de fichiers .so, .apk, etc.
Support de l'entree manuelle, de la detection automatique,
et de la selection interactive multi-cibles.
"""

import os
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple


class TargetValidator:
    """Validateur multi-format (.so ELF, .apk, binaires)."""

    VALID_EXTENSIONS = {'.so', '.apk', '.bin', '.elf', '.a', '.o'}

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
    def is_valid_apk(path: str) -> bool:
        """Verifier APK (ZIP avec AndroidManifest.xml)."""
        try:
            if not zipfile.is_zipfile(path):
                return False
            with zipfile.ZipFile(path, 'r') as z:
                return 'AndroidManifest.xml' in z.namelist()
        except Exception:
            return False

    @staticmethod
    def detect_target_type(path: str) -> Optional[str]:
        """Detecter le type de cible par magic bytes et extension."""
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
        """Determiner l'architecture du binaire (ELF only)."""
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
    """Selection de cible avec detection automatique et entree manuelle.

    Supporte .so, .apk et autres formats binaires.
    Detection recursive, selection interactive si cibles multiples.
    """

    def __init__(self, start_path: str = "."):
        self.start_path = Path(start_path)
        self.validator = TargetValidator()

    def find_targets(self, recursive: bool = True,
                     target_types: Optional[List[str]] = None) -> List[Tuple[str, str]]:
        """Trouver toutes les cibles valides (.so, .apk, etc).

        Args:
            recursive: Recherche recursive dans les sous-repertoires.
            target_types: Types a chercher ['so', 'apk']. None = tous.

        Returns:
            Liste de tuples (chemin, type).
        """
        if target_types is None:
            target_types = ['so', 'apk']

        targets = []
        patterns = [f"*.{ext}" for ext in target_types]

        for pattern in patterns:
            glob_fn = self.start_path.rglob if recursive else self.start_path.glob
            for path in glob_fn(pattern):
                if path.is_file():
                    target_type = self.validator.detect_target_type(str(path))
                    if target_type:
                        targets.append((str(path), target_type))

        return sorted(targets, key=lambda x: x[0])

    def find_so_targets(self, recursive: bool = True) -> List[str]:
        """Trouver tous les fichiers .so valides (compatibilite).

        Returns:
            Liste de chemins .so tries.
        """
        targets = self.find_targets(recursive=recursive, target_types=['so'])
        return [t[0] for t in targets]

    def validate_manual_path(self, path: str) -> Optional[str]:
        """Valider un chemin de fichier entre manuellement.

        Accepte:
        - Chemins relatifs, absolus, ~, variables d'environnement
        - Extensions: .so, .apk, .bin, .elf, etc

        Rejette:
        - Fichiers inexistants, liens symboliques, repertoires
        - Fichiers illisibles, formats non reconnus
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

        target_type = self.validator.detect_target_type(abs_path)
        if not target_type:
            if not self.validator.is_valid_so(abs_path):
                return None

        return abs_path

    def get_file_info(self, path: str) -> Tuple[str, str, str, str]:
        """Recuperer les informations d'un fichier cible.

        Returns:
            (nom, arch, taille_formatee, rw)
        """
        name = os.path.basename(path)
        target_type = self.validator.detect_target_type(path) or "Inconnu"
        writable = "Oui" if self.validator.is_writable(path) else "Non"

        if target_type == "ELF":
            arch = self.validator.get_arch(path) or "Inconnu"
        else:
            arch = target_type

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

    def select_interactive(self, targets: List[Tuple[str, str]]) -> Optional[str]:
        """Selection interactive (fallback, NON TUI-safe).

        WARNING: Utilise print() et input() qui conflictent
        avec curses TUI. Utiliser validate_manual_path() avec
        le mode saisie TUI a la place.
        """
        if not targets:
            return None

        for i, (target, target_type) in enumerate(targets, 1):
            arch = self.validator.get_arch(target) if target_type == "ELF" else target_type
            writable = "Oui" if self.validator.is_writable(target) else "Non"
            try:
                size_bytes = os.path.getsize(target)
                size = f"{size_bytes / 1024 / 1024:.2f} Mo"
            except OSError:
                size = "N/A"

            print(f"[{i}] {target}")
            print(f"    Type: {target_type} | Arch: {arch} | RW: {writable} | Taille: {size}")

        try:
            choice = int(input(f"\nSelectionner cible [1-{len(targets)}]: "))
            if 1 <= choice <= len(targets):
                return targets[choice - 1][0]
        except (ValueError, IndexError):
            pass

        return None
