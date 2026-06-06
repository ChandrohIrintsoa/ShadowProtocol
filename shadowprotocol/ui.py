"""
UI Module - Terminal Interface with Curses + ANSI Fallback
Live logging display + Progress bar + Responsive layout
Supports modes A-F
"""

import sys
import os
import time
import curses
import select
import threading
from collections import deque
from typing import Optional

try:
    import termios
    import tty
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False


class CursesUI:
    """Curses-based terminal UI with live logging and progress bar.

    Layout (responsive to terminal size):

    + ShadowProtocol v3.0 | Mode: MODE A | Running... ==========+
    ---------------------------------------------------------------
     > LIVE OUTPUT
    ---------------------------------------------------------------
     [10:25:32] [*] MODE A: Initialisation systeme...
     [10:25:33] [*] Chargement binaire...
     ...
    ---------------------------------------------------------------
     [████████████████████░░░░░░░░░░░░░░░░░░░░░] 65% MODE A 10/14
     [q] Quit | Modes: [a] [b] [c] [d] [e] [f]
    """

    MAX_LOG_LINES = 50

    def __init__(self, stdscr):
        """Initialize CursesUI with curses configuration.

        Args:
            stdscr: The curses standard screen object
        """
        self.stdscr = stdscr
        self.lock = threading.Lock()

        # Curses configuration
        curses.curs_set(0)       # Hide cursor
        curses.noecho()          # Don't echo input
        stdscr.nodelay(True)     # Non-blocking input
        stdscr.keypad(True)      # Enable special keys

        # Color pairs (5 levels)
        self._has_colors = curses.has_colors()
        if self._has_colors:
            curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)    # Info
            curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Success
            curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)     # Error
            curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Warning
            curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)    # Progress

        # State
        self.height, self.width = stdscr.getmaxyx()
        self.log_buffer = deque(maxlen=self.MAX_LOG_LINES)
        self.progress_pct = 0
        self.progress_text = ""
        self.mode_label = "IDLE"
        self.status_label = "Ready"
        self.running = True

    # -- State update methods (thread-safe) ----------------------------

    def update_dimensions(self) -> bool:
        """Check and update terminal dimensions if resized.

        Returns:
            True if dimensions changed, False otherwise.
        """
        try:
            new_h, new_w = self.stdscr.getmaxyx()
            if (new_h, new_w) != (self.height, self.width):
                self.height = new_h
                self.width = new_w
                return True
        except curses.error:
            pass
        return False

    def add_log(self, message: str):
        """Add a log message to the buffer (thread-safe).

        The buffer holds up to MAX_LOG_LINES entries;
        oldest entries are automatically removed.
        """
        with self.lock:
            self.log_buffer.append(message)

    def set_progress(self, current: int, total: int, label: str = ""):
        """Update progress bar (thread-safe).

        Args:
            current: Current step number
            total: Total number of steps
            label: Mode label (e.g. 'MODE A')
        """
        with self.lock:
            self.progress_pct = int((current / total * 100)) if total > 0 else 0
            self.progress_text = f"{label} {current}/{total}"

    def set_mode(self, mode: str):
        """Update mode label in header."""
        with self.lock:
            self.mode_label = mode

    def set_status(self, status: str):
        """Update status label in header."""
        with self.lock:
            self.status_label = status[:30]

    # -- Drawing methods -----------------------------------------------

    def _draw_header(self):
        """Draw dynamic header with mode + status."""
        content = f" ShadowProtocol v3.0 | Mode: {self.mode_label} | {self.status_label} "
        pad_len = max(0, self.width - len(content) - 2)
        line = f"\u2554{content}{'\u2550' * pad_len}\u2557"
        try:
            self.stdscr.addstr(0, 0, line[:self.width],
                               curses.color_pair(1) | curses.A_BOLD)
        except curses.error:
            pass

    def _draw_log_section(self):
        """Draw LIVE OUTPUT section with auto-scrolling logs."""
        try:
            # Guard: need at least 5 rows for log section to make sense
            if self.height < 5:
                return

            # Separator below header
            self.stdscr.addstr(1, 0, "\u2500" * self.width,
                               curses.color_pair(4) | curses.A_DIM)

            # LIVE OUTPUT label
            self.stdscr.addstr(2, 0, " \u25b6 LIVE OUTPUT",
                               curses.color_pair(2) | curses.A_BOLD)

            # Separator below label
            self.stdscr.addstr(3, 0, "\u2500" * self.width,
                               curses.color_pair(4) | curses.A_DIM)

            # Log area: from line 4 to (height - 5)
            log_start_y = 4
            # Fix: ensure log_height is at least 1, and clamp to available space
            log_height = max(1, min(self.height - 10, self.height - 5))

            # Show only the most recent logs that fit
            log_list = list(self.log_buffer)
            start_idx = max(0, len(log_list) - log_height)

            for i, log_msg in enumerate(log_list[start_idx:]):
                y = log_start_y + i
                if y >= self.height - 5:
                    break

                # Color based on log prefix
                color = curses.color_pair(1)  # Cyan default (info)
                if "[+]" in log_msg:
                    color = curses.color_pair(2)  # Green (success)
                elif "[!]" in log_msg:
                    color = curses.color_pair(3)  # Red (error)
                elif "[W]" in log_msg:
                    color = curses.color_pair(4)  # Yellow (warning)
                elif "[D]" in log_msg:
                    color = curses.color_pair(4) | curses.A_DIM  # Dim yellow

                truncated = log_msg[:self.width - 2]
                try:
                    self.stdscr.addstr(y, 1, truncated, color)
                except curses.error:
                    pass

        except curses.error:
            pass

    def _draw_progress(self):
        """Draw progress bar with step counter."""
        try:
            if self.height < 6:
                return

            # Separator above progress
            sep_y = self.height - 4
            self.stdscr.addstr(sep_y, 0, "\u2500" * self.width,
                               curses.color_pair(4) | curses.A_DIM)

            # Progress bar
            bar_y = self.height - 3
            bar_width = max(self.width - 25, 10)
            filled = int(bar_width * self.progress_pct / 100)
            bar_visual = "\u2588" * filled + "\u2591" * (bar_width - filled)

            progress_line = f" [{bar_visual}] {self.progress_pct:3d}%"
            if self.progress_text:
                progress_line += f" {self.progress_text}"

            self.stdscr.addstr(bar_y, 0, progress_line[:self.width],
                               curses.color_pair(5))
        except curses.error:
            pass

    def _draw_footer(self):
        """Draw footer with controls hint."""
        try:
            footer_y = self.height - 1
            footer = " [q] Quit | Modes: [a] [b] [c] [d] [e] [f]"
            self.stdscr.addstr(footer_y, 0, footer[:self.width],
                               curses.color_pair(4) | curses.A_DIM)
        except curses.error:
            pass

    # -- Core methods --------------------------------------------------

    def refresh(self):
        """Full display refresh (thread-safe).

        Called in the main loop to redraw the entire screen.
        All drawing is protected by the lock to prevent
        concurrent modifications from mode threads.
        """
        with self.lock:
            try:
                self.stdscr.erase()
                self._draw_header()
                self._draw_log_section()
                self._draw_progress()
                self._draw_footer()
                self.stdscr.refresh()
            except curses.error:
                pass

    def get_input(self) -> Optional[str]:
        """Get keyboard input (non-blocking).

        Returns:
            Lowercase character if key pressed, None otherwise.
        """
        try:
            ch = self.stdscr.getch()
            if ch != -1:
                return chr(ch).lower()
        except Exception:
            pass
        return None

    def stop(self):
        """Stop UI and restore terminal state.

        Restores echo, disables cbreak, and calls endwin().
        Safe to call multiple times.
        """
        self.running = False
        try:
            curses.echo()
            curses.nocbreak()
            self.stdscr.keypad(False)
            curses.endwin()
        except Exception:
            pass


class ANSIUI:
    """Fallback ANSI terminal UI (if curses unavailable).

    Provides the same visual layout as CursesUI but using
    ANSI escape sequences for terminal control.
    Supports non-blocking input via select() on stdin.
    """

    MAX_LOG_LINES = 30

    def __init__(self):
        """Initialize ANSIUI with terminal settings for non-blocking input."""
        self.lock = threading.Lock()
        self.log_buffer = deque(maxlen=self.MAX_LOG_LINES)
        self.progress_pct = 0
        self.progress_text = ""
        self.mode_label = "IDLE"
        self.status_label = "Ready"
        self.running = True

        # Set terminal to cbreak mode for non-blocking input
        self._old_settings = None
        if HAS_TERMIOS:
            try:
                self._old_settings = termios.tcgetattr(sys.stdin.fileno())
                tty.setcbreak(sys.stdin.fileno())
            except Exception:
                pass

    def update_dimensions(self) -> bool:
        """Check terminal size (informational only for ANSI mode)."""
        try:
            os.get_terminal_size()
            return True
        except Exception:
            return False

    def add_log(self, message: str):
        """Add a log message to the buffer (thread-safe)."""
        with self.lock:
            self.log_buffer.append(message)

    def set_progress(self, current: int, total: int, label: str = ""):
        """Update progress bar (thread-safe)."""
        with self.lock:
            self.progress_pct = int((current / total * 100)) if total > 0 else 0
            self.progress_text = f"{label} {current}/{total}"

    def set_mode(self, mode: str):
        """Update mode label in header."""
        with self.lock:
            self.mode_label = mode

    def set_status(self, status: str):
        """Update status label in header."""
        with self.lock:
            self.status_label = status[:30]

    def refresh(self):
        """Full display refresh using ANSI escape codes."""
        with self.lock:
            # Clear screen and move to top
            print("\033[2J\033[H", end="", flush=True)

            # Header
            content = f" ShadowProtocol v3.0 | Mode: {self.mode_label} | {self.status_label} "
            pad = max(0, 60 - len(content))
            print(f"\033[96m\u2554{content}{'\u2550' * pad}\u2557\033[0m")

            # Separator
            print("\033[33m" + "\u2500" * 80 + "\033[0m")

            # LIVE OUTPUT label
            print("\033[92m \u25b6 LIVE OUTPUT\033[0m")

            # Separator
            print("\033[33m" + "\u2500" * 80 + "\033[0m")

            # Logs
            for line in self.log_buffer:
                if "[+]" in line:
                    print(f"\033[92m {line}\033[0m")
                elif "[!]" in line:
                    print(f"\033[91m {line}\033[0m")
                elif "[W]" in line:
                    print(f"\033[93m {line}\033[0m")
                elif "[D]" in line:
                    print(f"\033[2m\033[93m {line}\033[0m")
                elif "[*]" in line:
                    print(f"\033[96m {line}\033[0m")
                else:
                    print(f"\033[97m {line}\033[0m")

            # Separator
            print("\033[33m" + "\u2500" * 80 + "\033[0m")

            # Progress bar
            bar_width = 40
            filled = int(bar_width * self.progress_pct / 100)
            bar = f"[{'\u2588' * filled}{'\u2591' * (bar_width - filled)}] {self.progress_pct:3d}%"
            if self.progress_text:
                bar += f" {self.progress_text}"
            print(f"\033[97m {bar}\033[0m")

            # Footer
            print("\033[93m [q] Quit | Modes: [a] [b] [c] [d] [e] [f]\033[0m")

    def get_input(self) -> Optional[str]:
        """Non-blocking input using select() on stdin.

        Returns:
            Lowercase character if key pressed, None otherwise.
        """
        try:
            if select.select([sys.stdin], [], [], 0)[0]:
                ch = sys.stdin.read(1)
                if ch:
                    return ch.lower()
        except Exception:
            pass
        return None

    def stop(self):
        """Restore terminal settings and stop UI.

        Restores the original terminal attributes that were
        saved during initialization (cbreak mode revert).
        """
        self.running = False
        if HAS_TERMIOS and self._old_settings is not None:
            try:
                termios.tcsetattr(sys.stdin.fileno(),
                                  termios.TCSADRAIN,
                                  self._old_settings)
            except Exception:
                pass
