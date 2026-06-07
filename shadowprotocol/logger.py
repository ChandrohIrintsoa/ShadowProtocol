"""
ShadowProtocol - Journalisseur (Logger)

Systeme de journalisation thread-safe avec horodatage,
callbacks pour mise a jour temps reel du TUI, et
persistance optionnelle dans un fichier de log.
"""

import os
import threading
from datetime import datetime
from typing import Callable, Optional


class LoggerHandler:
    """Journalisseur thread-safe avec callback et fichier persistant.

    Niveaux de log:
        info    -> [*]  (cyan)
        success -> [+]  (vert)
        error   -> [!]  (rouge)
        warning -> [W]  (jaune)
        debug   -> [D]  (gris)
    """

    def __init__(self, callback: Optional[Callable] = None,
                 log_file: Optional[str] = None):
        self.callback = callback
        self.lock = threading.Lock()
        self._log_file = log_file

    def _format(self, prefix: str, message: str) -> str:
        timestamp = datetime.now().strftime("%H:%M:%S")
        return f"[{timestamp}] {prefix} {message}"

    def _write_to_file(self, formatted_msg: str) -> None:
        if self._log_file:
            try:
                log_dir = os.path.dirname(self._log_file)
                if log_dir:
                    os.makedirs(log_dir, exist_ok=True)
                with open(self._log_file, "a", encoding="utf-8") as f:
                    f.write(formatted_msg + "\n")
            except OSError:
                pass

    def _emit(self, prefix: str, message: str):
        msg = self._format(prefix, message)
        with self.lock:
            self._write_to_file(msg)
            if self.callback:
                self.callback(msg)

    def info(self, message: str):
        self._emit("[*]", message)

    def success(self, message: str):
        self._emit("[+]", message)

    def error(self, message: str):
        self._emit("[!]", message)

    def warning(self, message: str):
        self._emit("[W]", message)

    def debug(self, message: str):
        self._emit("[D]", message)
