"""
ShadowProtocol - Configuration Globale

Regroupement des parametres et chemins avec surcharge
par variables d'environnement.
"""

import os
from pathlib import Path

class Config:
    """Configuration globale avec surcharge env."""

    DEFAULTS = {
        'results_dir': Path('./results'),
        'temp_dir': Path('/tmp/shadowprotocol'),
        'logs_dir': Path('./logs'),
        'apk_editor_jar': Path.home() / '.shadowprotocol' / 'APKEditor.jar',
        'radare2_timeout': 60,
        'max_visions': 30,
        'max_log_size': 50 * 1024 * 1024,  # 50MB
        'patch_from': '0x30',
        'patch_to': '0x20',
        'pattern_regex': r'add\s+x\d+,\s*x\d+,\s*0x30',
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
                path.mkdir(parents=True, exist_ok=True)
