"""
ShadowProtocol - Configuration Globale

Regroupement des parametres et chemins avec surcharge
par variables d'environnement.
"""

import os
import tempfile
from pathlib import Path


class Config:
    """Configuration globale avec surcharge env."""

    DEFAULTS = {
        'results_dir': Path('./results'),
        'temp_dir': Path(tempfile.gettempdir()) / 'shadowprotocol',
        'logs_dir': Path('./logs'),
        'apk_editor_jar': Path.home() / '.shadowprotocol' / 'APKEditor.jar',
        'radare2_timeout': 60,
        'max_visions': 30,
        'max_log_size': 50 * 1024 * 1024,  # 50MB
        'patch_from': '0x30',
        'patch_to': '0x20',
        'pattern_regex': r'add\s+x\d+,\s*x\d+,\s*0x30',
        # Rituel D: repertoire de sortie par defaut (memoire du telephone)
        'd_output_dir': '/storage/emulated/0/MT2/ShadowProtocol',
    }

    @classmethod
    def get(cls, key: str, default=None):
        """Recuperer une valeur de config (env > DEFAULTS > default)."""
        env_key = f"SHADOWPROTOCOL_{key.upper()}"
        if env_key in os.environ:
            return os.environ[env_key]
        return cls.DEFAULTS.get(key, default)

    @classmethod
    def init(cls):
        """Creer les repertoires par defaut."""
        for key in ['results_dir', 'temp_dir', 'logs_dir']:
            path = cls.get(key)
            if isinstance(path, Path):
                try:
                    path.mkdir(parents=True, exist_ok=True, mode=0o755)
                except (PermissionError, OSError):
                    if key == 'temp_dir':
                        path = Path.home() / '.cache' / 'shadowprotocol'
                        path.mkdir(parents=True, exist_ok=True, mode=0o755)
