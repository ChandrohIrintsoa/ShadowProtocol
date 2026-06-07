#!/usr/bin/env python3
"""
ShadowProtocol v3.0 - Main Application
Fused version: TUI UI (v2) + Real Radare2 Functionality (v1)
+ Flutter Patcher + APK Editor + Manifest Patcher + Function Finder

Interactive terminal UI with live logging, progress bar, and clean shutdown
with real binary patching via Radare2 integration.

Target selection uses the TUI system (not print/input) so that
menus and selections appear OUTSIDE the log table.
"""

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
    - User input handling (a/b/c/d/e/f for modes, 1 for target, q to quit)
    - Mode execution in separate threads
    - Target binary selection via TUI (not print/input)
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
        """Handle system signals (SIGINT, SIGTERM).

        Sets flags to break the main loop and initiate cleanup.
        """
        self.stop_requested = True
        self.running = False

    def display_welcome(self):
        """Display welcome messages with mode instructions."""
        self.logger.success("=== ShadowProtocol v3.0 - Fusion TUI + Radare2 ===")
        self.logger.info("Press [1] to select a target")
        self.logger.info("Press [a], [b], [c] for binary patching modes")
        self.logger.info("Press [d] for Flutter Patcher mode")
        self.logger.info("Press [e] for Find Functions mode")
        self.logger.info("Press [f] for Manifest Patcher mode")
        self.logger.info("Press [q] at any time to stop cleanly")
        self.logger.warning("Radare2 and r2pipe are required for full functionality")

    def _start_mode(self, mode_name: str):
        """Start a processing mode in a separate daemon thread.

        Creates the mode instance via factory, sets the UI mode/status,
        and launches execution in a background thread.

        Args:
            mode_name: 'A', 'B', 'C', 'D', 'E', or 'F'
        """
        if mode_name.upper() in MODES_REQUIRING_TARGET and not self.current_target:
            self.logger.warning("Please select a target first (option [1])")
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
        """Execute mode in background thread and update status on completion.

        Called as the thread target. Updates the UI status to
        'Completed', 'Stopped', or 'Error' based on the result.
        """
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

    def select_target_interactive(self):
        """Start TUI-based target selection.

        Instead of using print/input (which breaks the TUI),
        this method:
        1. Searches for .so files
        2. Formats the target list for TUI display
        3. Enters the UI's selection mode
        4. The main loop handles input for selection
        """
        self.logger.info("Searching for .so files...")
        targets = self.target_selector.find_targets()

        if not targets:
            self.logger.warning("No .so files found")
            return

        self.logger.info(f"{len(targets)} target(s) detected")
        self._selection_targets = targets

        # Format targets for TUI display
        formatted = self.target_selector.format_target_list(targets)

        # Enter TUI selection mode - the target list is rendered
        # OUTSIDE the log table, in its own clean area
        self.ui.enter_selection_mode(formatted, prompt="Select target (.so)")
        self._selection_digit_buffer = ""

    def _handle_selection_input(self, ch: str) -> bool:
        """Handle input during TUI target selection mode.

        This processes number input (1-N) to select a target,
        and 'q' to cancel selection. The selection happens entirely
        within the TUI, not via print/input.

        Args:
            ch: The key pressed (lowercase)

        Returns:
            True to continue, False to quit application
        """
        if not self._selection_targets:
            self.ui.exit_selection_mode()
            return True

        max_idx = len(self._selection_targets)

        if ch == 'q':
            # Cancel selection
            self.ui.exit_selection_mode()
            self.logger.info("Target selection cancelled")
            return True

        # Handle digit input for target selection
        if ch.isdigit():
            self._selection_digit_buffer += ch

            # Check if the buffer forms a valid index
            try:
                idx = int(self._selection_digit_buffer)
                if 1 <= idx <= max_idx:
                    # Valid selection - commit it
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
                    # The number is already too large, reset buffer
                    self._selection_digit_buffer = ""
                    self.logger.warning(f"Invalid selection. Use [1-{max_idx}]")
                    return True
                # Otherwise, wait for more digits (e.g., typing "1" then "5" for 15)
            except ValueError:
                self._selection_digit_buffer = ""

        # Non-digit, non-q key during selection - ignore
        return True

    def handle_input(self, ch: str) -> bool:
        """Handle keyboard input from the main loop.

        Args:
            ch: The key pressed (lowercase)

        Returns:
            False if the application should quit, True otherwise.
        """
        # If in selection mode, route input to selection handler
        if self.ui.is_in_selection_mode():
            return self._handle_selection_input(ch)

        if ch == 'q' or ch == '\x03':  # 'q' or Ctrl+C
            self.logger.info("Shutdown requested by user...")
            return False
        elif ch == '1':
            self.select_target_interactive()
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
        """Cleanup resources before exit.

        - Stops the current mode execution
        - Waits for mode thread with 5-second timeout
        - Displays final messages
        - Restores terminal state
        """
        if self.logger:
            self.logger.info("Clean shutdown in progress...")

        # Signal mode to stop
        if self.current_mode:
            self.current_mode.stop()

        # Wait for mode thread to finish
        if self.mode_thread and self.mode_thread.is_alive():
            if self.logger:
                self.logger.warning("Interrupting current process...")
            self.mode_thread.join(timeout=5)

            if self.mode_thread.is_alive():
                if self.logger:
                    self.logger.error("Timeout - forcing stop")

        # Final display refresh to show cleanup messages
        if self.ui:
            self.ui.refresh()
            time.sleep(0.3)

        if self.logger:
            self.logger.success("Cleanup complete - Goodbye!")

        # Final refresh and terminal restore
        if self.ui:
            self.ui.refresh()
            time.sleep(0.5)
            self.ui.stop()

    def _main_loop(self):
        """Common main loop logic shared by CursesUI and ANSIUI.

        This is the core event loop that:
        1. Refreshes the display
        2. Detects terminal resize
        3. Processes keyboard input (handles selection mode and normal mode)
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

        Attempts to use curses for the best terminal experience.
        Falls back to ANSI escape sequences if curses is unavailable.

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
        """Initialize CursesUI and run main loop.

        Called by curses.wrapper which handles terminal
        setup and teardown automatically.

        Args:
            stdscr: The curses standard screen object
        """
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
