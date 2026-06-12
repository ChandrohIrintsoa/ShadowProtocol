"""
ShadowProtocol - Gestionnaire de Fichiers

Gere les fichiers cibles, les sauvegardes, le dossier ☠️,
l'effacement radical, et le nettoyage.
"""

import shutil
from pathlib import Path
from typing import Optional, Tuple


class FileManager:
    """Gestionnaire de fichiers patches, backups, et organisation de sortie.

    Fonctionnalites:
    - Creation et gestion du dossier ☠️ pour les fichiers traites
    - Deplacement des fichiers patches vers ☠️
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
