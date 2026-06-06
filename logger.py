"""
Logger Handler - Thread-safe logging system with timestamps
Callback-based architecture for real-time UI updates
"""

import threading
from datetime import datetime
from typing import Callable, Optional


class LoggerHandler:
    """Thread-safe log handler with callback support.

    Provides multiple log levels (info, success, error, warning, debug)
    each with a distinctive prefix for color-coded display.
    All operations are protected by a threading.Lock to ensure
    safe concurrent access from mode execution threads.
    """

    def __init__(self, callback: Optional[Callable] = None):
        """Initialize logger with optional callback for UI updates.

        Args:
            callback: Function called with each formatted log message.
                      Typically UIManager.add_log() for real-time display.
        """
        self.callback = callback
        self.lock = threading.Lock()

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

    def info(self, message: str):
        """Log informational message (cyan prefix [*])"""
        msg = self._format("[*]", message)
        with self.lock:
            if self.callback:
                self.callback(msg)

    def success(self, message: str):
        """Log success message (green prefix [+])"""
        msg = self._format("[+]", message)
        with self.lock:
            if self.callback:
                self.callback(msg)

    def error(self, message: str):
        """Log error message (red prefix [!])"""
        msg = self._format("[!]", message)
        with self.lock:
            if self.callback:
                self.callback(msg)

    def warning(self, message: str):
        """Log warning message (yellow prefix [W])"""
        msg = self._format("[W]", message)
        with self.lock:
            if self.callback:
                self.callback(msg)

    def debug(self, message: str):
        """Log debug message (dim yellow prefix [D])"""
        msg = self._format("[D]", message)
        with self.lock:
            if self.callback:
                self.callback(msg)
