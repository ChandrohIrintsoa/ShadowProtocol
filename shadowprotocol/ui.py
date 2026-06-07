"""
UI Module - Terminal Interface with Curses + ANSI Fallback
Live logging display + Progress bar + Responsive layout
Supports modes A-F + Target selection + Manual path input within TUI

Layout:
  - Normal mode:    header + log area + progress + footer
  - Selection mode: header + target list (outside log table) + footer
  - Input mode:     header + text input field (outside log table) + footer
  - Only progress/execution logs go inside the log table
  - Menus and selections are always outside the log table
"""

import sys
import os
import time
import curses
import select
import threading
from collections import deque
from typing import Optional, List, Tuple

try:
    import termios
    import tty
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False


class CursesUI:
    """Curses-based terminal UI with live logging and progress bar.

    Layout (responsive to terminal size):

    NORMAL MODE:
    + ShadowProtocol v3.0 | Mode: MODE A | Running... ==========+
    ---------------------------------------------------------------
     > LIVE OUTPUT
    ---------------------------------------------------------------
     [10:25:32] [*] MODE A: Initialisation systeme...
     ...
    ---------------------------------------------------------------
     [████████████████████░░░░░░░░░░░░░░░░░░░░░] 65% MODE A 10/14
     [q] Quit | [1] Auto-select | [2] Manual path | Modes: [a-f]

    SELECTION MODE:
    + ShadowProtocol v3.0 | SELECT TARGET =======================+
    ---------------------------------------------------------------
     > SELECT TARGET (.so files found)
    ---------------------------------------------------------------
     [1] path/to/libfoo.so      Arch: ARM64 | RW: Y | Size: 4.29MB
     [2] path/to/libbar.so      Arch: ARM64 | RW: N | Size: 1.02MB
    ---------------------------------------------------------------
     [1-N] Select | [q] Cancel

    INPUT MODE (manual path):
    + ShadowProtocol v3.0 | ENTER PATH ==========================+
    ---------------------------------------------------------------
     > ENTER TARGET PATH
    ---------------------------------------------------------------
     Path: /home/user/decompiled/lib/arm64-v8a/libil2cpp.so_
     (valid ELF .so file, APK, or APKS)
    ---------------------------------------------------------------
     [Enter] Confirm | [Esc/q] Cancel | [Backspace] Delete
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
        curses.curs_set(0)       # Hide cursor (shown manually in input mode)
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
            curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLACK)   # Target list
            curses.init_pair(7, curses.COLOR_CYAN, curses.COLOR_BLACK)    # Target highlight

        # State
        self.height, self.width = stdscr.getmaxyx()
        self.log_buffer = deque(maxlen=self.MAX_LOG_LINES)
        self.progress_pct = 0
        self.progress_text = ""
        self.mode_label = "IDLE"
        self.status_label = "Ready"
        self.running = True

        # Selection mode state
        self.selection_mode = False
        self.selection_items: List[Tuple[int, str, str, str, float]] = []
        self.selection_prompt = ""
        self.selection_scroll_offset = 0

        # Input mode state (for manual path entry)
        self.input_mode = False
        self.input_buffer = ""
        self.input_prompt = ""
        self.input_hint = ""
        self.input_error = ""
        self._cursor_visible = True
        self._cursor_blink_counter = 0

    # -- State update methods (thread-safe) ----------------------------

    def update_dimensions(self) -> bool:
        """Check and update terminal dimensions if resized."""
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

    def enter_selection_mode(self, items: List[Tuple[int, str, str, str, float]],
                             prompt: str = "Select target"):
        """Enter target selection mode (auto-detected list)."""
        with self.lock:
            self.selection_mode = True
            self.selection_items = items
            self.selection_prompt = prompt
            self.selection_scroll_offset = 0
            # Exit input mode if active
            self.input_mode = False
            self.input_buffer = ""

    def exit_selection_mode(self):
        """Exit selection mode and return to normal log display."""
        with self.lock:
            self.selection_mode = False
            self.selection_items = []
            self.selection_prompt = ""
            self.selection_scroll_offset = 0

    def is_in_selection_mode(self) -> bool:
        """Check if UI is in selection mode."""
        return self.selection_mode

    def enter_input_mode(self, prompt: str = "Enter path", hint: str = ""):
        """Enter text input mode for manual path entry.

        The UI shows a text input field OUTSIDE the log table,
        with a blinking cursor and inline validation hints.

        Args:
            prompt: Prompt text (e.g. "Enter target path")
            hint: Hint text shown below the input (e.g. "valid ELF .so, APK, or APKS")
        """
        with self.lock:
            self.input_mode = True
            self.input_buffer = ""
            self.input_prompt = prompt
            self.input_hint = hint
            self.input_error = ""
            self._cursor_visible = True
            self._cursor_blink_counter = 0
            # Exit selection mode if active
            self.selection_mode = False
            self.selection_items = []

    def exit_input_mode(self):
        """Exit input mode and return to normal log display."""
        with self.lock:
            self.input_mode = False
            self.input_buffer = ""
            self.input_prompt = ""
            self.input_hint = ""
            self.input_error = ""

    def is_in_input_mode(self) -> bool:
        """Check if UI is in input mode."""
        return self.input_mode

    def get_input_buffer(self) -> str:
        """Get the current text in the input buffer."""
        return self.input_buffer

    def set_input_error(self, error: str):
        """Set an error message to display in input mode."""
        with self.lock:
            self.input_error = error

    # -- Drawing methods -----------------------------------------------

    def _draw_header(self):
        """Draw dynamic header with mode + status."""
        if self.input_mode:
            content = f" ShadowProtocol v3.0 | MANUAL PATH "
        elif self.selection_mode:
            content = f" ShadowProtocol v3.0 | SELECT TARGET "
        else:
            content = f" ShadowProtocol v3.0 | Mode: {self.mode_label} | {self.status_label} "
        pad_len = max(0, self.width - len(content) - 2)
        line = f"\u2554{content}{'\u2550' * pad_len}\u2557"
        try:
            self.stdscr.addstr(0, 0, line[:self.width],
                               curses.color_pair(1) | curses.A_BOLD)
        except curses.error:
            pass

    def _draw_log_section(self):
        """Draw LIVE OUTPUT section with auto-scrolling logs.

        Only called in normal (non-selection, non-input) mode.
        """
        try:
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

    def _draw_selection_section(self):
        """Draw target selection list (OUTSIDE the log table)."""
        try:
            if self.height < 5:
                return

            # Separator below header
            self.stdscr.addstr(1, 0, "\u2500" * self.width,
                               curses.color_pair(4) | curses.A_DIM)

            # Selection title
            title = f" \u25b6 {self.selection_prompt} ({len(self.selection_items)} found)"
            self.stdscr.addstr(2, 0, title,
                               curses.color_pair(2) | curses.A_BOLD)

            # Separator below title
            self.stdscr.addstr(3, 0, "\u2500" * self.width,
                               curses.color_pair(4) | curses.A_DIM)

            # Target list area
            list_start_y = 4
            available_lines = max(1, self.height - 5 - list_start_y)

            # Each item takes 2 lines (path + details)
            items_per_page = max(1, available_lines // 2)

            if self.selection_scroll_offset >= len(self.selection_items):
                self.selection_scroll_offset = max(0, len(self.selection_items) - items_per_page)

            visible_items = self.selection_items[self.selection_scroll_offset:]

            y = list_start_y
            for idx, path, arch, rw, size_mb in visible_items:
                if y >= self.height - 5:
                    break

                # Item number and path
                max_path_len = self.width - 8
                display_path = path
                if len(display_path) > max_path_len:
                    display_path = "..." + path[-(max_path_len - 3):]

                item_line = f" [{idx}] {display_path}"
                try:
                    self.stdscr.addstr(y, 1, item_line[:self.width - 2],
                                       curses.color_pair(7) | curses.A_BOLD)
                except curses.error:
                    pass

                y += 1
                if y >= self.height - 5:
                    break

                # Details line
                detail_line = f"     Arch: {arch} | RW: {rw} | Size: {size_mb:.2f}MB"
                try:
                    self.stdscr.addstr(y, 1, detail_line[:self.width - 2],
                                       curses.color_pair(6) | curses.A_DIM)
                except curses.error:
                    pass

                y += 1

            # Scroll indicator
            if len(self.selection_items) > items_per_page:
                showing = f" (showing {self.selection_scroll_offset + 1}-{min(self.selection_scroll_offset + items_per_page, len(self.selection_items))} of {len(self.selection_items)}) "
                try:
                    self.stdscr.addstr(self.height - 5, 0, showing[:self.width],
                                       curses.color_pair(4) | curses.A_DIM)
                except curses.error:
                    pass

        except curses.error:
            pass

    def _draw_input_section(self):
        """Draw manual path input area (OUTSIDE the log table).

        Shows:
        - Prompt label
        - Text input field with blinking cursor
        - Hint text and error messages
        - All rendered in a clean dedicated area, not mixed with logs
        """
        try:
            if self.height < 5:
                return

            # Separator below header
            self.stdscr.addstr(1, 0, "\u2500" * self.width,
                               curses.color_pair(4) | curses.A_DIM)

            # Prompt title
            title = f" \u25b6 {self.input_prompt}"
            self.stdscr.addstr(2, 0, title,
                               curses.color_pair(2) | curses.A_BOLD)

            # Separator below title
            self.stdscr.addstr(3, 0, "\u2500" * self.width,
                               curses.color_pair(4) | curses.A_DIM)

            # Blink cursor
            self._cursor_blink_counter += 1
            if self._cursor_blink_counter % 10 == 0:
                self._cursor_visible = not self._cursor_visible

            # Input field - calculate available width
            input_label = " Path: "
            max_input_len = self.width - len(input_label) - 4
            display_buffer = self.input_buffer
            if len(display_buffer) > max_input_len:
                # Show the end of the path (most relevant)
                display_buffer = "..." + display_buffer[-(max_input_len - 3):]

            cursor_char = "\u2588" if self._cursor_visible else " "

            input_y = 5
            # Draw input label
            try:
                self.stdscr.addstr(input_y, 1, input_label,
                                   curses.color_pair(7) | curses.A_BOLD)
            except curses.error:
                pass

            # Draw input field background
            field_start = 1 + len(input_label)
            field_width = max_input_len + 2
            try:
                self.stdscr.addstr(input_y, field_start, " " * field_width,
                                   curses.color_pair(6))
            except curses.error:
                pass

            # Draw typed text
            try:
                self.stdscr.addstr(input_y, field_start + 1, display_buffer,
                                   curses.color_pair(6) | curses.A_BOLD)
            except curses.error:
                pass

            # Draw cursor
            cursor_pos = field_start + 1 + len(display_buffer)
            if cursor_pos < self.width - 1:
                try:
                    self.stdscr.addch(input_y, cursor_pos, ord(cursor_char[0]),
                                      curses.color_pair(7) | curses.A_BOLD)
                except curses.error:
                    pass

            # Hint text
            if self.input_hint and input_y + 2 < self.height - 3:
                try:
                    self.stdscr.addstr(input_y + 2, 3, self.input_hint,
                                       curses.color_pair(4) | curses.A_DIM)
                except curses.error:
                    pass

            # Error message
            if self.input_error and input_y + 3 < self.height - 3:
                try:
                    self.stdscr.addstr(input_y + 3, 3, f"\u2716 {self.input_error}",
                                       curses.color_pair(3) | curses.A_BOLD)
                except curses.error:
                    pass

            # Path validation preview - show file info if path exists
            if self.input_buffer and input_y + 4 < self.height - 3:
                if os.path.exists(self.input_buffer):
                    size = os.path.getsize(self.input_buffer) / 1024 / 1024
                    info = f"\u2714 File found ({size:.2f} MB)"
                    try:
                        self.stdscr.addstr(input_y + 4, 3, info,
                                           curses.color_pair(2))
                    except curses.error:
                        pass
                else:
                    try:
                        self.stdscr.addstr(input_y + 4, 3, "\u2716 File not found",
                                           curses.color_pair(3) | curses.A_DIM)
                    except curses.error:
                        pass

        except curses.error:
            pass

    def _draw_progress(self):
        """Draw progress bar (only in normal mode)."""
        if self.selection_mode or self.input_mode:
            return

        try:
            if self.height < 6:
                return

            sep_y = self.height - 4
            self.stdscr.addstr(sep_y, 0, "\u2500" * self.width,
                               curses.color_pair(4) | curses.A_DIM)

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

            if self.input_mode:
                footer = " [Enter] Confirm | [Esc/q] Cancel | [Backspace] Delete"
            elif self.selection_mode:
                max_idx = len(self.selection_items) if self.selection_items else 0
                if max_idx > 0:
                    footer = f" [1-{max_idx}] Select | [q] Cancel | [\u2191\u2193] Scroll"
                else:
                    footer = " [q] Cancel (no targets found)"
            else:
                footer = " [q] Quit | [1] Auto-select | [2] Manual path | Modes: [a] [b] [c] [d] [e] [f]"

            self.stdscr.addstr(footer_y, 0, footer[:self.width],
                               curses.color_pair(4) | curses.A_DIM)
        except curses.error:
            pass

    # -- Core methods --------------------------------------------------

    def refresh(self):
        """Full display refresh (thread-safe)."""
        with self.lock:
            try:
                self.stdscr.erase()
                self._draw_header()
                if self.input_mode:
                    self._draw_input_section()
                elif self.selection_mode:
                    self._draw_selection_section()
                else:
                    self._draw_log_section()
                    self._draw_progress()
                self._draw_footer()
                self.stdscr.refresh()
            except curses.error:
                pass

    def get_input(self) -> Optional[str]:
        """Get keyboard input (non-blocking).

        In input mode, returns the raw character (preserving case for paths).
        Otherwise, returns lowercase character.

        Returns:
            Character if key pressed, None otherwise.
            Special keys: '\n' for Enter, '\x7f' for Backspace,
            '\x1b' for Escape.
        """
        try:
            ch = self.stdscr.getch()
            if ch != -1:
                if self.input_mode:
                    # In input mode, preserve case for file paths
                    if ch == curses.KEY_ENTER or ch == 10:
                        return '\n'
                    elif ch == curses.KEY_BACKSPACE or ch == 127 or ch == 8:
                        return '\x7f'
                    elif ch == 27:  # Escape
                        return '\x1b'
                    elif ch >= 32 and ch <= 126:
                        return chr(ch)  # Preserve case
                    return None
                else:
                    return chr(ch).lower()
        except Exception:
            pass
        return None

    def stop(self):
        """Stop UI and restore terminal state."""
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

    Supports: normal mode, selection mode, and manual path input mode.
    All menus/selections rendered OUTSIDE the log table.
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

        # Selection mode state
        self.selection_mode = False
        self.selection_items: List[Tuple[int, str, str, str, float]] = []
        self.selection_prompt = ""
        self.selection_scroll_offset = 0

        # Input mode state (for manual path entry)
        self.input_mode = False
        self.input_buffer = ""
        self.input_prompt = ""
        self.input_hint = ""
        self.input_error = ""

        # Set terminal to cbreak mode for non-blocking input
        self._old_settings = None
        if HAS_TERMIOS:
            try:
                self._old_settings = termios.tcgetattr(sys.stdin.fileno())
                tty.setcbreak(sys.stdin.fileno())
            except Exception:
                pass

    def update_dimensions(self) -> bool:
        """Check terminal size."""
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

    def enter_selection_mode(self, items: List[Tuple[int, str, str, str, float]],
                             prompt: str = "Select target"):
        """Enter target selection mode."""
        with self.lock:
            self.selection_mode = True
            self.selection_items = items
            self.selection_prompt = prompt
            self.selection_scroll_offset = 0
            self.input_mode = False
            self.input_buffer = ""

    def exit_selection_mode(self):
        """Exit selection mode and return to normal log display."""
        with self.lock:
            self.selection_mode = False
            self.selection_items = []
            self.selection_prompt = ""
            self.selection_scroll_offset = 0

    def is_in_selection_mode(self) -> bool:
        """Check if UI is in selection mode."""
        return self.selection_mode

    def enter_input_mode(self, prompt: str = "Enter path", hint: str = ""):
        """Enter text input mode for manual path entry."""
        with self.lock:
            self.input_mode = True
            self.input_buffer = ""
            self.input_prompt = prompt
            self.input_hint = hint
            self.input_error = ""
            self.selection_mode = False
            self.selection_items = []

    def exit_input_mode(self):
        """Exit input mode and return to normal log display."""
        with self.lock:
            self.input_mode = False
            self.input_buffer = ""
            self.input_prompt = ""
            self.input_hint = ""
            self.input_error = ""

    def is_in_input_mode(self) -> bool:
        """Check if UI is in input mode."""
        return self.input_mode

    def get_input_buffer(self) -> str:
        """Get the current text in the input buffer."""
        return self.input_buffer

    def set_input_error(self, error: str):
        """Set an error message to display in input mode."""
        with self.lock:
            self.input_error = error

    def refresh(self):
        """Full display refresh using ANSI escape codes."""
        with self.lock:
            # Clear screen and move to top
            print("\033[2J\033[H", end="", flush=True)

            # Header
            if self.input_mode:
                content = f" ShadowProtocol v3.0 | MANUAL PATH "
            elif self.selection_mode:
                content = f" ShadowProtocol v3.0 | SELECT TARGET "
            else:
                content = f" ShadowProtocol v3.0 | Mode: {self.mode_label} | {self.status_label} "
            pad = max(0, 60 - len(content))
            print(f"\033[96m\u2554{content}{'\u2550' * pad}\u2557\033[0m")

            # Separator
            print("\033[33m" + "\u2500" * 80 + "\033[0m")

            if self.input_mode:
                # Input title
                print(f"\033[92m \u25b6 {self.input_prompt}\033[0m")
                print("\033[33m" + "\u2500" * 80 + "\033[0m")

                # Input field with cursor
                cursor = "\u2588"
                print(f"\033[96m Path:\033[0m \033[1m{self.input_buffer}{cursor}\033[0m")

                # Hint
                if self.input_hint:
                    print(f"\033[90m {self.input_hint}\033[0m")

                # Error
                if self.input_error:
                    print(f"\033[91m \u2716 {self.input_error}\033[0m")

                # Path preview
                if self.input_buffer:
                    if os.path.exists(self.input_buffer):
                        size = os.path.getsize(self.input_buffer) / 1024 / 1024
                        print(f"\033[92m \u2714 File found ({size:.2f} MB)\033[0m")
                    else:
                        print(f"\033[91m \u2716 File not found\033[0m")

            elif self.selection_mode:
                # Selection title
                title = f"\033[92m \u25b6 {self.selection_prompt} ({len(self.selection_items)} found)\033[0m"
                print(title)
                print("\033[33m" + "\u2500" * 80 + "\033[0m")

                # Target list
                for idx, path, arch, rw, size_mb in self.selection_items:
                    max_path_len = 70
                    display_path = path
                    if len(display_path) > max_path_len:
                        display_path = "..." + path[-(max_path_len - 3):]
                    print(f"\033[96m [{idx}] {display_path}\033[0m")
                    print(f"\033[90m     Arch: {arch} | RW: {rw} | Size: {size_mb:.2f}MB\033[0m")

            else:
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
            if self.input_mode:
                print("\033[93m [Enter] Confirm | [Esc/q] Cancel | [Backspace] Delete\033[0m")
            elif self.selection_mode:
                max_idx = len(self.selection_items) if self.selection_items else 0
                if max_idx > 0:
                    print(f"\033[93m [1-{max_idx}] Select | [q] Cancel\033[0m")
                else:
                    print(f"\033[93m [q] Cancel (no targets found)\033[0m")
            else:
                print("\033[93m [q] Quit | [1] Auto-select | [2] Manual path | Modes: [a] [b] [c] [d] [e] [f]\033[0m")

    def get_input(self) -> Optional[str]:
        """Non-blocking input using select() on stdin.

        In input mode, preserves case for file paths.
        Special returns: '\n' Enter, '\x7f' Backspace, '\x1b' Escape.

        Returns:
            Character if key pressed, None otherwise.
        """
        try:
            if select.select([sys.stdin], [], [], 0)[0]:
                ch = sys.stdin.read(1)
                if ch:
                    if self.input_mode:
                        # Preserve case for path input
                        if ch == '\n' or ch == '\r':
                            return '\n'
                        elif ch == '\x7f' or ch == '\x08':
                            return '\x7f'
                        elif ch == '\x1b':
                            return '\x1b'
                        elif ord(ch) >= 32:
                            return ch  # Preserve case
                        return None
                    else:
                        return ch.lower()
        except Exception:
            pass
        return None

    def stop(self):
        """Restore terminal settings and stop UI."""
        self.running = False
        if HAS_TERMIOS and self._old_settings is not None:
            try:
                termios.tcsetattr(sys.stdin.fileno(),
                                  termios.TCSADRAIN,
                                  self._old_settings)
            except Exception:
                pass
