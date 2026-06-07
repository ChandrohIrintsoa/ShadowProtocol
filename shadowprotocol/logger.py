"""
Logger Handler - Thread-safe logging system with timestamps
Callback-based architecture for real-time UI updates
+ Persistent log file support
"""

import os
import threading
from datetime import datetime
from typing import Callable, Optional


class LoggerHandler:
    """Thread-safe log handler with callback and file persistence support.

    Provides multiple log levels (info, success, error, warning, debug)
    each with a distinctive prefix for color-coded display.
    All operations are protected by a threading.Lock to ensure
    safe concurrent access from mode execution threads.
    Optionally writes all messages to a log file for persistence.
    """

    def __init__(self, callback: Optional[Callable] = None, log_file: Optional[str] = None):
        """Initialize logger with optional callback for UI updates.

        Args:
            callback: Function called with each formatted log message.
                      Typically UIManager.add_log() for real-time display.
            log_file: Optional path to a log file for persistent logging.
                      If None, logging is callback-only (no file output).
        """
        self.callback = callback
        self.lock = threading.Lock()
        self._log_file = log_file

    def _format(self, prefix: str, message: str) -> str:
        """Format a message with timestamp and level prefix.

        Args:
            prefix: Log level prefix (e.g. '[*]', '[+]', '[!]')
            message: The log message text

        Returns:
            Formatted string: '[HH:MM:SS] prefix message'
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        return f"[{timestamp}] {prefix} {message}"

    def _write_to_file(self, formatted_msg: str) -> None:
        """Append a formatted message to the log file if configured.

        Args:
            formatted_msg: The fully formatted log message.
        """
        if self._log_file:
            try:
                log_dir = os.path.dirname(self._log_file)
                if log_dir:
                    os.makedirs(log_dir, exist_ok=True)
                with open(self._log_file, "a", encoding="utf-8") as f:
                    f.write(formatted_msg + "\n")
            except OSError:
                pass

    def info(self, message: str):
        """Log informational message (cyan prefix [*])"""
        msg = self._format("[*]", message)
        with self.lock:
            self._write_to_file(msg)
            if self.callback:
                self.callback(msg)

    def success(self, message: str):
        """Log success message (green prefix [+])"""
        msg = self._format("[+]", message)
        with self.lock:
            self._write_to_file(msg)
            if self.callback:
                self.callback(msg)

    def error(self, message: str):
        """Log error message (red prefix [!])"""
        msg = self._format("[!]", message)
        with self.lock:
            self._write_to_file(msg)
            if self.callback:
                self.callback(msg)

    def warning(self, message: str):
        """Log warning message (yellow prefix [W])"""
        msg = self._format("[W]", message)
        with self.lock:
            self._write_to_file(msg)
            if self.callback:
                self.callback(msg)

    def debug(self, message: str):
        """Log debug message (dim yellow prefix [D])"""
        msg = self._format("[D]", message)
        with self.lock:
            self._write_to_file(msg)
            if self.callback:
                self.callback(msg)
