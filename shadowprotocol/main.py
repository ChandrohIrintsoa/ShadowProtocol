#!/usr/bin/env python3
"""
ShadowProtocol v3.0 - Main Application
Fused version: TUI UI (v2) + Real Radare2 Functionality (v1)
+ Flutter Patcher + APK Editor + Manifest Patcher + Function Finder

Interactive terminal UI with live logging, progress bar, and clean shutdown
with real binary patching via Radare2 integration.
Manual path entry for target selection.
"""

import sys
import os
import time
import signal
import curses
import threading
from datetime import datetime
from typing import Optional

from .logger import LoggerHandler
from .modes import get_mode, BaseMode
from .ui import CursesUI, ANSIUI
from .target_selector import TargetSelector
from .validator import DependencyValidator


VALID_MODES = ('A', 'B', 'C', 'D', 'E', 'F')

MODES_REQUIRING_TARGET = ('A', 'B', 'C')


class ShadowProtocolApp:
    """Main application orchestrator.

    Manages the application lifecycle:
    - UI initialization (curses with ANSI fallback)
    - User input handling (a/b/c/d/e/f for modes, q to quit)
    - Mode execution in separate threads
    - Target binary selection (manual path entry)
    - Offset collection for MODE A
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
        self._dry_run = False

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
        self.logger.info("Press [1] to enter target path manually")
        self.logger.info("Press [2] to enter PPTool offset (for MODE A)")
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

        if mode_name.upper() == 'A' and not self.current_offset:
            self.logger.warning("Please provide an offset first (option [2])")
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

    def _request_target_path(self):
        """Request manual target path entry via TUI input mode."""
        if self.ui.is_input_active:
            return  # Already in input mode

        self.logger.info("Enter the path to the target .so file:")
        self.ui.enter_input_mode("Path: ", self._on_target_path_entered)

    def _on_target_path_entered(self, path: str):
        """Callback when user submits a target path.

        Args:
            path: The file path entered by the user.
        """
        validated = self.target_selector.validate_manual_path(path)

        if validated:
            self.current_target = validated
            info = self.target_selector.get_file_info(validated)
            self.logger.success(f"Target selected: {validated}")
            self.logger.info(f"  {info}")
        else:
            self.logger.error(f"Invalid target: {path}")
            self.logger.info("The file must exist and be a valid ELF binary (.so)")

    def _request_offset(self):
        """Request PPTool offset entry via TUI input mode (for MODE A)."""
        if self.ui.is_input_active:
            return  # Already in input mode

        if not self.current_target:
            self.logger.warning("Please select a target first (option [1])")
            return

        self.logger.info("Enter the PPTool offset (format: 0x...):")
        self.ui.enter_input_mode("Offset: ", self._on_offset_entered)

    def _on_offset_entered(self, offset: str):
        """Callback when user submits an offset.

        Args:
            offset: The offset string entered by the user.
        """
        import re
        if re.match(r'^0x[0-9a-fA-F]+$', offset):
            self.current_offset = offset
            self.logger.success(f"Offset set: {offset}")
        else:
            self.logger.error(f"Invalid offset format: {offset}")
            self.logger.info("Expected format: 0x... (e.g. 0x1234)")

    def handle_input(self, ch: str) -> bool:
        """Handle keyboard input from the main loop.

        Args:
            ch: The key pressed (lowercase)

        Returns:
            False if the application should quit, True otherwise.
        """
        if ch == 'q' or ch == '\x03':  # 'q' or Ctrl+C
            self.logger.info("Shutdown requested by user...")
            return False
        elif ch == '1':
            self._request_target_path()
        elif ch == '2':
            self._request_offset()
        elif ch in ('a', 'b', 'c', 'd', 'e', 'f'):
            if self.mode_thread and self.mode_thread.is_alive():
                self.logger.warning("A process is already running")
            else:
                self.logger.info(f"Starting MODE {ch.upper()}...")
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
        3. Processes keyboard input
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
        # Validate deps before UI start
        required = [mode] if mode else ['A', 'B', 'C']
        ok, messages = DependencyValidator.validate_all(required)

        for msg in messages:
            print(msg)

        if not ok:
            print("\n[!] Missing dependencies. Install and retry.")
            sys.exit(1)

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
                log_file = self._get_log_file_path()
                self.logger = LoggerHandler(callback=self.ui.add_log, log_file=log_file)
                self.logger.success("=== Session started (ANSI fallback) ===")
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
        log_file = self._get_log_file_path()
        self.logger = LoggerHandler(callback=self.ui.add_log, log_file=log_file)
        self.logger.success("=== Session started ===")
        self._main_loop()
        return self.ui

    def _get_log_file_path(self) -> str:
        """Generate a timestamped log file path in logs/ directory."""
        os.makedirs('logs', exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"logs/session_{timestamp}.log"


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
        shadowprotocol --check-deps - Validate system dependencies
        shadowprotocol --dry-run A  - Dry-run MODE A (preview changes)
    """
    app = ShadowProtocolApp()

    if len(sys.argv) > 1:
        arg = sys.argv[1]

        # --check-deps: validate dependencies only
        if arg == '--check-deps':
            modes = sys.argv[2:] if len(sys.argv) > 2 else []
            ok, messages = DependencyValidator.validate_all(modes)
            for msg in messages:
                print(msg)
            if not ok:
                print("\n[!] Missing dependencies. Install and retry.")
                sys.exit(1)
            else:
                print("\n[+] All dependencies satisfied.")
                sys.exit(0)

        # --dry-run: preview mode without applying changes
        if arg == '--dry-run':
            mode_arg = sys.argv[2].upper() if len(sys.argv) > 2 else None
            if mode_arg and mode_arg in VALID_MODES:
                print(f"[*] DRY RUN MODE {mode_arg} - No changes will be applied")
                app._dry_run = True
                app.run(mode_arg)
            else:
                print("Usage: shadowprotocol --dry-run [A|B|C|D|E|F]")
                sys.exit(1)
            return

        mode = arg.upper()
        if mode in VALID_MODES:
            app.run(mode)
        else:
            print(f"Unknown mode: {mode}")
            print("Usage: shadowprotocol [A|B|C|D|E|F]")
            print("        shadowprotocol --check-deps")
            print("        shadowprotocol --dry-run [A|B|C|D|E|F]")
            sys.exit(1)
    else:
        app.run()


if __name__ == "__main__":
    main()
