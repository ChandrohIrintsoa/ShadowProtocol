"""
ShadowProtocol - Gestionnaire de Fichiers

Gere les fichiers cibles, les sauvegardes, le dossier ☠️,
la detection multi-cibles, l'effacement radical, et le nettoyage.
"""

import os
import shutil
from pathlib import Path
from typing import List, Optional, Tuple


class FileManager:
    """Gestionnaire de fichiers patches, backups, et organisation de sortie.

    Fonctionnalites:
    - Creation et gestion du dossier ☠️ pour les fichiers traites
    - Deplacement/copie des fichiers patches vers ☠️
    - Detection automatique de cibles multiples dans un chemin
    - Effacement radical des cibles et cache/log
    - Nettoyage des fichiers temporaires
    """

    SKULL_FOLDER = "\U0001f480"

    def __init__(self, target_path: str):
        """Initialiser le gestionnaire pour une cible.

        Args:
            target_path: Chemin vers le fichier cible
        """
        self.target_path = Path(target_path)
        self.target_dir = self.target_path.parent
        self.skull_dir = self.target_dir / self.SKULL_FOLDER

    def create_skull_folder(self) -> bool:
        """Creer le dossier ☠️ pour les fichiers traites.

        Returns:
            True si cree/existant, False si erreur
        """
        try:
            self.skull_dir.mkdir(exist_ok=True, mode=0o755)
            return True
        except Exception:
            return False

    def move_to_skull(self, source_path: str) -> Optional[str]:
        """Deplacer un fichier vers le dossier ☠️.

        Le fichier est deplace au meme chemin relatif que la cible
        mais dans le sous-dossier ☠️.

        Args:
            source_path: Chemin du fichier a deplacer

        Returns:
            Chemin dans ☠️, ou None si erreur
        """
        if not self.create_skull_folder():
            return None

        try:
            source = Path(source_path)
            dest = self.skull_dir / source.name

            # Gerer les noms en conflit
            if dest.exists():
                stem = source.stem
                suffix = source.suffix
                counter = 1
                while dest.exists():
                    dest = self.skull_dir / f"{stem}_{counter}{suffix}"
                    counter += 1

            shutil.move(str(source), str(dest))
            return str(dest)
        except Exception:
            return None

    def copy_to_skull(self, source_path: str) -> Optional[str]:
        """Copier un fichier vers le dossier ☠️ (garde l'original).

        Args:
            source_path: Chemin du fichier a copier

        Returns:
            Chemin dans ☠️, ou None si erreur
        """
        if not self.create_skull_folder():
            return None

        try:
            source = Path(source_path)
            dest = self.skull_dir / source.name

            if dest.exists():
                stem = source.stem
                suffix = source.suffix
                counter = 1
                while dest.exists():
                    dest = self.skull_dir / f"{stem}_{counter}{suffix}"
                    counter += 1

            shutil.copy2(str(source), str(dest))
            return str(dest)
        except Exception:
            return None

    @staticmethod
    def find_targets_in_path(path: str,
                             extensions: Optional[List[str]] = None) -> List[Tuple[str, str]]:
        """Trouver tous les fichiers cibles dans un chemin.

        Args:
            path: Repertoire ou chemin de fichier
            extensions: Extensions a chercher (.so, .apk, etc)

        Returns:
            Liste de tuples (chemin_fichier, type)
        """
        if extensions is None:
            extensions = ['so', 'apk', 'elf', 'bin']

        targets = []
        path_obj = Path(path)

        if path_obj.is_file():
            ext = path_obj.suffix[1:] if path_obj.suffix else 'unknown'
            targets.append((str(path_obj), ext))
        elif path_obj.is_dir():
            for ext in extensions:
                for match in path_obj.rglob(f"*.{ext}"):
                    if match.is_file() and match.name != "SKIP_ME":
                        targets.append((str(match), ext))

        return sorted(targets, key=lambda x: x[0])

    @staticmethod
    def auto_select_target(targets: List[Tuple[str, str]]) -> Optional[str]:
        """Selection automatique: 1 cible = auto, 0 = None, >1 = None (besoin choix user).

        Args:
            targets: Liste de (chemin, type)

        Returns:
            Chemin si 1 seule cible, None sinon
        """
        if not targets:
            return None
        if len(targets) == 1:
            return targets[0][0]
        return None

    def radical_erase(self, keep_skull: bool = True) -> Tuple[int, int]:
        """Effacer radicalement les fichiers cibles et les cache/log.

        Args:
            keep_skull: Si True, garder les fichiers dans ☠️

        Returns:
            (nb_fichiers_supprimes, nb_erreurs)
        """
        deleted = 0
        errors = 0

        try:
            # Supprimer la cible originale
            if self.target_path.exists():
                self.target_path.unlink()
                deleted += 1
        except Exception:
            errors += 1

        # Supprimer les fichiers de cache
        cache_patterns = ['.shadowprotocol_session', '*.pyc', '__pycache__',
                          '*.shadowprotocol_tmp']
        for pattern in cache_patterns:
            try:
                if '*' in pattern:
                    for match in self.target_dir.glob(pattern):
                        if match.is_dir():
                            shutil.rmtree(match, ignore_errors=True)
                            deleted += 1
                        else:
                            match.unlink(missing_ok=True)
                            deleted += 1
                else:
                    target_file = self.target_dir / pattern
                    if target_file.exists():
                        target_file.unlink()
                        deleted += 1
            except Exception:
                errors += 1

        # Supprimer les logs dans le repertoire
        try:
            for log_file in self.target_dir.glob("*.log"):
                log_file.unlink()
                deleted += 1
        except Exception:
            errors += 1

        # Supprimer le dossier ☠️ si demande
        if not keep_skull and self.skull_dir.exists():
            try:
                shutil.rmtree(self.skull_dir, ignore_errors=True)
                deleted += 1
            except Exception:
                errors += 1

        return (deleted, errors)

    def cleanup_logs(self, pattern: str = "*.log") -> int:
        """Nettoyer les logs d'activite.

        Args:
            pattern: Pattern des fichiers log

        Returns:
            Nombre de logs supprimes
        """
        count = 0
        for log_file in self.target_dir.glob(pattern):
            try:
                log_file.unlink()
                count += 1
            except Exception:
                pass
        return count

    def get_skull_contents(self) -> List[str]:
        """Lister les fichiers dans le dossier ☠️.

        Returns:
            Liste des chemins de fichiers
        """
        if not self.skull_dir.exists():
            return []
        return [str(f) for f in self.skull_dir.iterdir() if f.is_file()]

    def skull_exists(self) -> bool:
        """Verifier si le dossier ☠️ existe."""
        return self.skull_dir.exists()
