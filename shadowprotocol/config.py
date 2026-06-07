"""
ShadowProtocol Configuration System

Global configuration with environment variable overrides.
Centralizes hardcoded paths and settings into one place.
"""

import os
from pathlib import Path


class Config:
    """Global configuration with env var overrides."""

    DEFAULTS = {
        'results_dir': Path('./results'),
        'temp_dir': Path('/tmp/shadowprotocol'),
        'logs_dir': Path('./logs'),
        'apk_editor_jar': Path.home() / '.shadowprotocol' / 'APKEditor.jar',
        'radare2_timeout': 30,  # seconds
        'max_log_size': 50 * 1024 * 1024,  # 50MB
    }

    @classmethod
    def get(cls, key: str, default=None):
        """Get config value with env var override.

        Environment variables take the form: SHADOWPROTOCOL_<KEY>
        For example: SHADOWPROTOCOL_RESULTS_DIR=/custom/path

        Args:
            key: Configuration key name.
            default: Default value if key not found.

        Returns:
            Configuration value (from env var, or DEFAULTS, or provided default).
        """
        env_key = f"SHADOWPROTOCOL_{key.upper()}"
        if env_key in os.environ:
            return os.environ[env_key]
        return cls.DEFAULTS.get(key, default)

    @classmethod
    def init(cls):
        """Create default directories if they don't exist."""
        for key in ['results_dir', 'temp_dir', 'logs_dir']:
            path = cls.get(key)
            if isinstance(path, Path):
                path.mkdir(parents=True, exist_ok=True)
