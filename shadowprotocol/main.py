#!/usr/bin/env python3
"""
ShadowProtocol v3.0 - Main Application
Fused version: TUI UI (v2) + Real Radare2 Functionality (v1)
+ Flutter Patcher + APK Editor + Manifest Patcher + Function Finder

Interactive terminal UI with live logging, progress bar, and clean shutdown
with real binary patching via Radare2 integration.

Target selection:
  [1] Auto-detect .so files in current directory (list selection)
  [2] Manually enter the path to target file (text input)
  Menus and selections appear OUTSIDE the log table.
"""

import os
import sys
import time
import signal
import curses
import threading
from typing import Optional, List

from .logger import LoggerHandler
from .modes import get_mode, BaseMode
from .ui import CursesUI, ANSIUI
from .target_selector import TargetSelector


VALID_MODES = ('A', 'B', 'C', 'D', 'E', 'F')

MODES_REQUIRING_TARGET = ('A', 'B', 'C')


class ShadowProtocolApp:
    """Main application orchestrator.

    Manages the application lifecycle:
    - UI initialization (curses with ANSI fallback)
    - User input handling (a/b/c/d/e/f for modes, 1/2 for target, q to quit)
    - Mode execution in separate threads
    - Target binary selection via TUI (auto-detect or manual path)
    - Graceful shutdown with cleanup
    - Terminal resize adaptation
    """

    def __init__(self):
        """Initialize application with default state and signal handlers."""
        self.ui = None
        self.logger = None
        self.current_mode: Optional[BaseMode] = None
        self.mode_thread: Optional[threading.Thread] = None
        self.running = True
        self.stop_requested = False
        self._requested_mode: Optional[str] = None

        # Target selection
        self.target_selector = TargetSelector()
        self.current_target: Optional[str] = None
        self.current_offset: Optional[str] = None

        # Selection state for TUI-based selection
        self._selection_targets: Optional[List[str]] = None
        self._selection_digit_buffer = ""

        # Signal handlers for external interrupts
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame):
        """Handle system signals (SIGINT, SIGTERM)."""
        self.stop_requested = True
        self.running = False

    def display_welcome(self):
        """Display welcome messages with mode instructions."""
        self.logger.success("=== ShadowProtocol v3.0 - Fusion TUI + Radare2 ===")
        self.logger.info("Press [1] to auto-detect and select a target")
        self.logger.info("Press [2] to manually enter target path")
        self.logger.info("Press [a], [b], [c] for binary patching modes")
        self.logger.info("Press [d] for Flutter Patcher mode")
        self.logger.info("Press [e] for Find Functions mode")
        self.logger.info("Press [f] for Manifest Patcher mode")
        self.logger.info("Press [q] at any time to stop cleanly")
        self.logger.warning("Radare2 and r2pipe are required for full functionality")

    def _start_mode(self, mode_name: str):
        """Start a processing mode in a separate daemon thread.

        Args:
            mode_name: 'A', 'B', 'C', 'D', 'E', or 'F'
        """
        if mode_name.upper() in MODES_REQUIRING_TARGET and not self.current_target:
            self.logger.warning("Please select a target first (option [1] or [2])")
            return

        try:
            self.current_mode = get_mode(
                mode_name,
                self.logger.info,
                self.ui.set_progress,
                binary_path=self.current_target,
                offset=self.current_offset if mode_name.upper() == 'A' else None
            )
            self.ui.set_mode(f"MODE {mode_name.upper()}")
            self.ui.set_status("Running...")

            self.mode_thread = threading.Thread(
                target=self._execute_mode_thread,
                daemon=True
            )
            self.mode_thread.start()
        except ValueError as e:
            self.logger.error(str(e))

    def _execute_mode_thread(self):
        """Execute mode in background thread and update status on completion."""
        try:
            success = self.current_mode.execute()
            if success:
                self.ui.set_status("Completed")
                self.logger.success("Mode execution completed successfully")
            else:
                self.ui.set_status("Stopped")
                self.logger.warning("Mode execution stopped")
        except Exception as e:
            self.logger.error(f"Mode error: {e}")
            self.ui.set_status("Error")

    # -- Target selection: auto-detect ---------------------------------

    def select_target_interactive(self):
        """Start TUI-based target selection (auto-detect .so files).

        Instead of using print/input (which breaks the TUI),
        this method searches for .so files and enters the UI's
        selection mode. The main loop handles input for selection.
        """
        self.logger.info("Searching for .so files...")
        targets = self.target_selector.find_targets()

        if not targets:
            self.logger.warning("No .so files found. Use [2] to enter path manually.")
            return

        self.logger.info(f"{len(targets)} target(s) detected")
        self._selection_targets = targets

        # Format targets for TUI display
        formatted = self.target_selector.format_target_list(targets)

        # Enter TUI selection mode
        self.ui.enter_selection_mode(formatted, prompt="Select target (.so)")
        self._selection_digit_buffer = ""

    def _handle_selection_input(self, ch: str) -> bool:
        """Handle input during TUI target selection mode.

        Processes number input (1-N) to select a target,
        and 'q' to cancel selection.
        """
        if not self._selection_targets:
            self.ui.exit_selection_mode()
            return True

        max_idx = len(self._selection_targets)

        if ch == 'q':
            self.ui.exit_selection_mode()
            self.logger.info("Target selection cancelled")
            return True

        if ch.isdigit():
            self._selection_digit_buffer += ch
            try:
                idx = int(self._selection_digit_buffer)
                if 1 <= idx <= max_idx:
                    selected = self.target_selector.get_target_by_index(
                        self._selection_targets, idx
                    )
                    self.ui.exit_selection_mode()
                    self._selection_targets = None
                    self._selection_digit_buffer = ""

                    if selected:
                        self.current_target = selected
                        arch = self.target_selector.validator.get_arch(selected) or "Unknown"
                        self.logger.success(f"Target selected: {selected} ({arch})")
                    return True
                elif idx * 10 > max_idx:
                    self._selection_digit_buffer = ""
                    self.logger.warning(f"Invalid selection. Use [1-{max_idx}]")
                    return True
            except ValueError:
                self._selection_digit_buffer = ""

        return True

    # -- Target selection: manual path ---------------------------------

    def select_target_manual(self):
        """Start TUI-based manual path input.

        The user types the file path directly in the TUI.
        This is useful when .so files are in a different directory
        or the auto-detection doesn't find the desired target.
        """
        self.ui.enter_input_mode(
            prompt="Enter target path",
            hint="Supported: ELF .so, .apk, .apks files  |  Tab completion not available"
        )

    def _handle_input_mode(self, ch: str) -> bool:
        """Handle input during manual path entry mode.

        The user types characters that appear in the TUI input field.
        Enter confirms the path, Escape/q cancels.

        Args:
            ch: The raw key pressed (case preserved for paths)

        Returns:
            True to continue, False to quit application
        """
        if ch == '\n':
            # Enter pressed - confirm path
            path = self.ui.get_input_buffer().strip()
            if not path:
                self.ui.set_input_error("Path cannot be empty")
                return True

            # Expand ~ to home directory
            path = os.path.expanduser(path)

            # Resolve relative path
            if not os.path.isabs(path):
                path = os.path.abspath(path)

            # Validate the path
            if not os.path.exists(path):
                self.ui.set_input_error(f"File not found: {path}")
                return True

            if os.path.isdir(path):
                # If directory, try to find .so files inside
                self.ui.exit_input_mode()
                self.logger.info(f"Directory detected, searching for .so files in: {path}")
                self.target_selector = TargetSelector(start_path=path)
                targets = self.target_selector.find_targets()
                if targets:
                    self._selection_targets = targets
                    formatted = self.target_selector.format_target_list(targets)
                    self.logger.info(f"{len(targets)} target(s) found in directory")
                    self.ui.enter_selection_mode(formatted, prompt=f"Select from {path}")
                    self._selection_digit_buffer = ""
                else:
                    self.logger.warning(f"No .so files found in: {path}")
                return True

            # Valid file path - set as target
            self.ui.exit_input_mode()
            self.current_target = path

            # Show file info
            arch = self.target_selector.validator.get_arch(path) or "Unknown"
            size = os.path.getsize(path) / 1024 / 1024
            ext = os.path.splitext(path)[1].lower()

            if ext in ('.apk', '.apks'):
                self.logger.success(f"Target selected: {path} ({size:.2f} MB, {ext})")
            elif self.target_selector.validator.is_valid_so(path):
                writable = "RW" if self.target_selector.validator.is_writable(path) else "RO"
                self.logger.success(f"Target selected: {path} ({arch}, {writable}, {size:.2f} MB)")
            else:
                self.logger.success(f"Target selected: {path} ({size:.2f} MB)")
                self.logger.warning("File is not a valid ELF binary - some modes may not work")

            return True

        elif ch == '\x7f':
            # Backspace - delete last character
            buf = self.ui.get_input_buffer()
            if buf:
                self.ui.input_buffer = buf[:-1]
                self.ui.input_error = ""
            return True

        elif ch == '\x1b':
            # Escape - cancel input
            self.ui.exit_input_mode()
            self.logger.info("Manual path entry cancelled")
            return True

        elif ch == 'q' and not self.ui.get_input_buffer():
            # q on empty buffer = cancel
            self.ui.exit_input_mode()
            self.logger.info("Manual path entry cancelled")
            return True

        elif len(ch) == 1 and ord(ch) >= 32:
            # Regular printable character - add to buffer
            self.ui.input_buffer += ch
            self.ui.input_error = ""
            return True

        return True

    # -- Main input router ---------------------------------------------

    def handle_input(self, ch: str) -> bool:
        """Handle keyboard input from the main loop.

        Routes input to the appropriate handler based on current UI mode:
        - Input mode (manual path entry) → _handle_input_mode
        - Selection mode (auto-detect list) → _handle_selection_input
        - Normal mode → key commands (1, 2, a-f, q)

        Args:
            ch: The key pressed

        Returns:
            False if the application should quit, True otherwise.
        """
        # If in input mode, route to input handler (preserve case)
        if self.ui.is_in_input_mode():
            return self._handle_input_mode(ch)

        # If in selection mode, route to selection handler
        if self.ui.is_in_selection_mode():
            return self._handle_selection_input(ch)

        # Normal mode
        if ch == 'q' or ch == '\x03':  # 'q' or Ctrl+C
            self.logger.info("Shutdown requested by user...")
            return False
        elif ch == '1':
            self.select_target_interactive()
        elif ch == '2':
            self.select_target_manual()
        elif ch in ('a', 'b', 'c', 'd', 'e', 'f'):
            if self.mode_thread and self.mode_thread.is_alive():
                self.logger.warning("A process is already running")
            else:
                self.logger.info(f"Starting MODE {ch.upper()}...")
                if ch.upper() == 'A':
                    self.logger.info("For MODE A, provide offset via parameter")
                self._start_mode(ch)
        else:
            self.logger.warning(f"Unknown key: {ch}")
        return True

    def _cleanup(self):
        """Cleanup resources before exit."""
        if self.logger:
            self.logger.info("Clean shutdown in progress...")

        if self.current_mode:
            self.current_mode.stop()

        if self.mode_thread and self.mode_thread.is_alive():
            if self.logger:
                self.logger.warning("Interrupting current process...")
            self.mode_thread.join(timeout=5)

            if self.mode_thread.is_alive():
                if self.logger:
                    self.logger.error("Timeout - forcing stop")

        if self.ui:
            self.ui.refresh()
            time.sleep(0.3)

        if self.logger:
            self.logger.success("Cleanup complete - Goodbye!")

        if self.ui:
            self.ui.refresh()
            time.sleep(0.5)
            self.ui.stop()

    def _main_loop(self):
        """Common main loop logic shared by CursesUI and ANSIUI.

        Core event loop:
        1. Refreshes the display
        2. Detects terminal resize
        3. Processes keyboard input (handles all modes)
        4. Monitors mode thread completion
        5. Sleeps briefly to reduce CPU usage
        """
        self.display_welcome()

        # Auto-run mode if specified via CLI argument
        if self._requested_mode:
            self._start_mode(self._requested_mode)

        try:
            while self.running and not self.stop_requested:
                # Refresh display
                self.ui.refresh()

                # Check terminal resize
                if self.ui.update_dimensions():
                    self.logger.debug("Terminal resized")

                # Handle keyboard input (non-blocking)
                ch = self.ui.get_input()
                if ch:
                    if not self.handle_input(ch):
                        break

                # Check if mode thread has finished
                if self.mode_thread and not self.mode_thread.is_alive():
                    self.mode_thread = None
                    if self.running and not self.stop_requested:
                        self.ui.set_mode("IDLE")
                        self.ui.set_status("Ready")

                # Small delay to avoid excessive CPU usage
                time.sleep(0.05)

        except KeyboardInterrupt:
            if self.logger:
                self.logger.warning("Keyboard interrupt detected")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error: {e}")
        finally:
            try:
                self._cleanup()
            except Exception:
                pass

    def run(self, mode: Optional[str] = None):
        """Run the application.

        Args:
            mode: Optional mode to auto-run ('A'-'F').
                  If None, starts in interactive mode.
        """
        self._requested_mode = mode

        try:
            # Primary: curses-based UI
            curses.wrapper(self._curses_main)
        except KeyboardInterrupt:
            print("\n[!] Stopped by user")
        except Exception:
            # Fallback: ANSI-based UI
            try:
                self.ui = ANSIUI()
                self.logger = LoggerHandler(callback=self.ui.add_log)
                self._main_loop()
            except KeyboardInterrupt:
                print("\n[!] Stopped by user")
            except Exception as e:
                print(f"\n[!] Error: {e}")
                sys.exit(1)

    def _curses_main(self, stdscr):
        """Initialize CursesUI and run main loop."""
        self.ui = CursesUI(stdscr)
        self.logger = LoggerHandler(callback=self.ui.add_log)
        self._main_loop()
        return self.ui


def main():
    """Entry point for the shadowprotocol command.

    Usage:
        shadowprotocol          - Interactive mode (choose a/b/c/d/e/f)
        shadowprotocol A        - Run MODE A directly
        shadowprotocol B        - Run MODE B directly
        shadowprotocol C        - Run MODE C directly
        shadowprotocol D        - Run MODE D (Flutter Patcher) directly
        shadowprotocol E        - Run MODE E (Find Functions) directly
        shadowprotocol F        - Run MODE F (Manifest Patcher) directly
    """
    app = ShadowProtocolApp()

    if len(sys.argv) > 1:
        mode = sys.argv[1].upper()
        if mode in VALID_MODES:
            app.run(mode)
        else:
            print(f"Unknown mode: {mode}")
            print("Usage: shadowprotocol [A|B|C|D|E|F]")
            sys.exit(1)
    else:
        app.run()


if __name__ == "__main__":
    main()
