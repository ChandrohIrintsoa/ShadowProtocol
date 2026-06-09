"""
UI Module - Terminal Interface with Curses + ANSI Fallback
Live logging display + Progress bar + Responsive layout + Manual input mode
Supports modes A-F
"""

import sys
import os
import curses
import select
import threading
import termios
import tty
from collections import deque
from typing import Optional, Callable

class CursesUI:
    """Curses-based terminal UI with live logging, progress bar, and manual input.

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
     [1] Target | [q] Quit | Modes: [a] [b] [c] [d] [e] [f]

    Input mode (when active):
     > Path: /home/user/libapp.so_
    """

    MAX_LOG_LINES = 50

    def __init__(self, stdscr):
        """Initialize CursesUI with curses configuration.

        Args:
            stdscr: The curses standard screen object
        """
        self.stdscr = stdscr
        self.lock = threading.Lock()
        self.log_lock = threading.Lock()  # Separate lock for log writes

        # Curses configuration
        curses.curs_set(0)       # Hide cursor (shown during input mode)
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

        # Manual input mode state
        self._input_active = False
        self._input_prompt = ""
        self._input_buffer = ""
        self._input_callback = None  # Callable[[str], None]

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
        with self.log_lock:
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

    # -- Manual input mode ---------------------------------------------

    def enter_input_mode(self, prompt: str, callback: Callable[[str], None]):
        """Enter manual input mode for text entry (e.g. file path, offset).

        Activates a text input line displayed OUTSIDE the log table area.
        Typed characters are captured and shown in real-time.
        Pressing Enter submits the input; Escape cancels.

        Args:
            prompt: The prompt label (e.g. 'Path:', 'Offset:')
            callback: Function called with the entered text on Enter.
        """
        with self.lock:
            self._input_active = True
            self._input_prompt = prompt
            self._input_buffer = ""
            self._input_callback = callback
        # Show cursor during input
        try:
            curses.curs_set(1)
        except curses.error:
            pass

    def exit_input_mode(self):
        """Exit manual input mode and hide cursor."""
        with self.lock:
            self._input_active = False
            self._input_prompt = ""
            self._input_buffer = ""
            self._input_callback = None
        # Hide cursor again
        try:
            curses.curs_set(0)
        except curses.error:
            pass

    @property
    def is_input_active(self) -> bool:
        """Check if manual input mode is active."""
        return self._input_active

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

            # Log area: from line 4 to (height - 6)
            # Reserve more space at bottom for input mode line
            log_start_y = 4
            log_end_y = self.height - 6
            if self._input_active:
                log_end_y = self.height - 7  # Extra space for input line
            log_height = max(1, log_end_y - log_start_y)

            # Show only the most recent logs that fit
            log_list = list(self.log_buffer)
            start_idx = max(0, len(log_list) - log_height)

            for i, log_msg in enumerate(log_list[start_idx:]):
                y = log_start_y + i
                if y >= log_end_y:
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

    def _draw_input_line(self):
        """Draw the manual input line when in input mode (outside log table)."""
        if not self._input_active:
            return

        try:
            input_y = self.height - 5
            # Draw a separator above the input line
            self.stdscr.addstr(input_y, 0, "\u2500" * self.width,
                               curses.color_pair(4) | curses.A_DIM)

            # Draw the input prompt and buffer
            input_y2 = self.height - 4
            display = f" {self._input_prompt}{self._input_buffer}_"
            self.stdscr.addstr(input_y2, 0, display[:self.width],
                               curses.color_pair(1) | curses.A_BOLD)
        except curses.error:
            pass

    def _draw_progress(self):
        """Draw progress bar with step counter."""
        # Don't draw progress bar when in input mode (it overlaps)
        if self._input_active:
            return

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
            if self._input_active:
                footer = " [Enter] Confirm | [Esc] Cancel | [Backspace] Delete"
            else:
                footer = " [1] Target | [q] Quit | Modes: [a] [b] [c] [d] [e] [f]"
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
                self._draw_input_line()
                self._draw_progress()
                self._draw_footer()
                self.stdscr.refresh()
            except curses.error:
                pass

    def get_input(self) -> Optional[str]:
        """Get keyboard input (non-blocking).

        In normal mode, returns lowercase character for single-key commands.
        In input mode, captures typed characters into the buffer.
        Enter submits, Escape cancels.

        Returns:
            Lowercase character if key pressed (normal mode), None otherwise.
            In input mode, returns None (handled internally).
        """
        try:
            ch = self.stdscr.getch()
            if ch == -1:
                return None

            # If in input mode, handle character capture
            if self._input_active:
                self._handle_input_char(ch)
                return None

            return chr(ch).lower()
        except Exception:
            pass
        return None

    def _handle_input_char(self, ch: int):
        """Handle a character in input mode.

        Args:
            ch: The curses key code.
        """
        if ch == curses.KEY_ENTER or ch == 10 or ch == 13:
            # Enter pressed - submit input
            result = self._input_buffer
            callback = self._input_callback
            self.exit_input_mode()
            if callback and result.strip():
                callback(result.strip())
        elif ch == 27:  # Escape
            self.exit_input_mode()
        elif ch == curses.KEY_BACKSPACE or ch == 127 or ch == 8:
            # Backspace - delete last char
            with self.lock:
                self._input_buffer = self._input_buffer[:-1]
        elif ch == curses.KEY_RESIZE:
            pass  # Handled by update_dimensions()
        elif 32 <= ch <= 126:
            # Printable character
            with self.lock:
                self._input_buffer += chr(ch)

    def stop(self):
        """Stop UI and restore terminal state.

        Restores echo, disables cbreak, and calls endwin().
        Safe to call multiple times.
        """
        self.running = False
        self._input_active = False
        try:
            curses.echo()
            curses.nocbreak()
            self.stdscr.keypad(False)
            curses.curs_set(1)  # Restore cursor
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
        self.log_lock = threading.Lock()  # Separate lock for log writes
        self.log_buffer = deque(maxlen=self.MAX_LOG_LINES)
        self.progress_pct = 0
        self.progress_text = ""
        self.mode_label = "IDLE"
        self.status_label = "Ready"
        self.running = True

        # Manual input mode state
        self._input_active = False
        self._input_prompt = ""
        self._input_buffer = ""
        self._input_callback = None

        # Set terminal to cbreak mode for non-blocking input
        self._old_settings = None
        try:
            self._old_settings = termios.tcgetattr(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
        except Exception:
            pass

    def update_dimensions(self) -> bool:
        """Check terminal size and return True only if dimensions changed."""
        try:
            new_size = os.get_terminal_size()
            if not hasattr(self, '_last_size') or self._last_size != new_size:
                self._last_size = new_size
                return True
            return False
        except Exception:
            return False

    def add_log(self, message: str):
        """Add a log message to the buffer (thread-safe)."""
        with self.log_lock:
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

    def enter_input_mode(self, prompt: str, callback: Callable[[str], None]):
        """Enter manual input mode (ANSI fallback)."""
        with self.lock:
            self._input_active = True
            self._input_prompt = prompt
            self._input_buffer = ""
            self._input_callback = callback

    def exit_input_mode(self):
        """Exit manual input mode."""
        with self.lock:
            self._input_active = False
            self._input_prompt = ""
            self._input_buffer = ""
            self._input_callback = None

    @property
    def is_input_active(self) -> bool:
        """Check if manual input mode is active."""
        return self._input_active

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
                elif "[*]" in line:
                    print(f"\033[96m {line}\033[0m")
                else:
                    print(f"\033[97m {line}\033[0m")

            # Separator
            print("\033[33m" + "\u2500" * 80 + "\033[0m")

            # Input line (if active) - displayed OUTSIDE log area
            if self._input_active:
                print(f"\033[96m > {self._input_prompt}{self._input_buffer}_\033[0m")
                print("\033[33m" + "\u2500" * 80 + "\033[0m")
            else:
                # Progress bar
                bar_width = 40
                filled = int(bar_width * self.progress_pct / 100)
                bar = f"[{'\u2588' * filled}{'\u2591' * (bar_width - filled)}] {self.progress_pct:3d}%"
                if self.progress_text:
                    bar += f" {self.progress_text}"
                print(f"\033[97m {bar}\033[0m")

            # Footer
            if self._input_active:
                print("\033[93m [Enter] Confirm | [Esc] Cancel | [Backspace] Delete\033[0m")
            else:
                print("\033[93m [1] Target | [q] Quit | Modes: [a] [b] [c] [d] [e] [f]\033[0m")

    def get_input(self) -> Optional[str]:
        """Non-blocking input using select() on stdin.

        In input mode, captures characters into the buffer.
        Enter submits, Escape cancels.

        Returns:
            Lowercase character if key pressed (normal mode), None otherwise.
        """
        try:
            if select.select([sys.stdin], [], [], 0)[0]:
                ch = sys.stdin.read(1)
                if not ch:
                    return None

                # If in input mode, handle character capture
                if self._input_active:
                    self._handle_ansi_input_char(ch)
                    return None

                return ch.lower()
        except Exception:
            pass
        return None

    def _handle_ansi_input_char(self, ch: str):
        """Handle a character in input mode (ANSI fallback).

        Args:
            ch: The character read from stdin.
        """
        if ch == '\n' or ch == '\r':
            # Enter pressed
            result = self._input_buffer
            callback = self._input_callback
            self.exit_input_mode()
            if callback and result.strip():
                callback(result.strip())
        elif ch == '\x1b':
            # Escape
            self.exit_input_mode()
        elif ch == '\x7f' or ch == '\x08':
            # Backspace
            with self.lock:
                self._input_buffer = self._input_buffer[:-1]
        elif ch.isprintable():
            with self.lock:
                self._input_buffer += ch

    def stop(self):
        """Restore terminal settings and stop UI.

        Restores the original terminal attributes that were
        saved during initialization (cbreak mode revert).
        """
        self.running = False
        self._input_active = False
        if self._old_settings is not None:
            try:
                termios.tcsetattr(sys.stdin.fileno(),
                                  termios.TCSADRAIN,
                                  self._old_settings)
            except Exception:
                pass
