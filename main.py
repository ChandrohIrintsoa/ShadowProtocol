#!/usr/bin/env python3
"""
ShadowProtocol v3.0 - Main Application
Fused version: TUI UI (v2) + Real Radare2 Functionality (v1)

Interactive terminal UI with live logging, progress bar, and clean shutdown
with real binary patching via Radare2 integration.
"""

import sys
import time
import signal
import curses
import threading
from typing import Optional

from .logger import LoggerHandler
from .modes import get_mode, BaseMode
from .ui import CursesUI, ANSIUI
from .target_selector import TargetSelector


class ShadowProtocolApp:
    """Main application orchestrator.

    Manages the application lifecycle:
    - UI initialization (curses with ANSI fallback)
    - User input handling (a/b/c for modes, q to quit)
    - Mode execution in separate threads
    - Target binary selection
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
        self.logger.info("Appuyez sur [1] pour sélectionner une cible")
        self.logger.info("Appuyez sur [a], [b], ou [c] pour lancer les modes")
        self.logger.info("Appuyez sur [q] à tout moment pour arrêter proprement")
        self.logger.warning("Radare2 et r2pipe sont requis pour la fonctionnalité réelle")

    def _start_mode(self, mode_name: str):
        """Start a processing mode in a separate daemon thread.

        Creates the mode instance via factory, sets the UI mode/status,
        and launches execution in a background thread.

        Args:
            mode_name: 'A', 'B', or 'C'
        """
        if not self.current_target and mode_name.upper() in ('A', 'B', 'C'):
            self.logger.warning("Veuillez sélectionner une cible d'abord (option [1])")
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
                self.logger.success("Exécution du mode terminée avec succès")
            else:
                self.ui.set_status("Stopped")
                self.logger.warning("Exécution du mode arrêtée")
        except Exception as e:
            self.logger.error(f"Erreur mode: {e}")
            self.ui.set_status("Error")

    def select_target_interactive(self):
        """Interactive target selection"""
        self.logger.info("Recherche des fichiers .so...")
        targets = self.target_selector.find_targets()
        
        if not targets:
            self.logger.warning("Aucun fichier .so trouvé")
            return
        
        self.logger.info(f"{len(targets)} cible(s) détectée(s)")
        selected = self.target_selector.select_interactive(targets)
        
        if selected:
            self.current_target = selected
            size = self.target_selector.validator.get_arch(selected) or "Unknown"
            self.logger.success(f"Cible sélectionnée: {selected} ({size})")
        else:
            self.logger.warning("Sélection annulée")

    def handle_input(self, ch: str) -> bool:
        """Handle keyboard input from the main loop.

        Args:
            ch: The key pressed (lowercase)

        Returns:
            False if the application should quit, True otherwise.
        """
        if ch == 'q' or ch == '\x03':  # 'q' or Ctrl+C
            self.logger.info("Arrêt demandé par utilisateur...")
            return False
        elif ch == '1':
            self.select_target_interactive()
        elif ch in ('a', 'b', 'c'):
            if self.mode_thread and self.mode_thread.is_alive():
                self.logger.warning("Un traitement est déjà en cours")
            else:
                self.logger.info(f"Lancement MODE {ch.upper()}...")
                # For MODE A, we could prompt for offset here
                if ch.upper() == 'A':
                    self.logger.info("Pour MODE A, fournir l'offset via paramètre")
                self._start_mode(ch)
        else:
            self.logger.warning(f"Touche inconnue: {ch}")
        return True

    def _cleanup(self):
        """Cleanup resources before exit.

        - Stops the current mode execution
        - Waits for mode thread with 5-second timeout
        - Displays final messages
        - Restores terminal state
        """
        if self.logger:
            self.logger.info("Arrêt propre en cours...")

        # Signal mode to stop
        if self.current_mode:
            self.current_mode.stop()

        # Wait for mode thread to finish
        if self.mode_thread and self.mode_thread.is_alive():
            if self.logger:
                self.logger.warning("Interruption du traitement en cours...")
            self.mode_thread.join(timeout=5)

            if self.mode_thread.is_alive():
                if self.logger:
                    self.logger.error("Timeout - forcage arrêt")

        # Final display refresh to show cleanup messages
        if self.ui:
            self.ui.refresh()
            time.sleep(0.3)

        if self.logger:
            self.logger.success("Nettoyage complète - Au revoir!")

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
                    self.logger.debug("Terminal redimensionné")

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
                self.logger.warning("Interruption clavier détectée")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erreur: {e}")
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
            mode: Optional mode to auto-run ('A', 'B', or 'C').
                  If None, starts in interactive mode.
        """
        self._requested_mode = mode

        try:
            # Primary: curses-based UI
            curses.wrapper(self._curses_main)
        except KeyboardInterrupt:
            print("\n[!] Arrêt par utilisateur")
        except Exception:
            # Fallback: ANSI-based UI
            try:
                self.ui = ANSIUI()
                self.logger = LoggerHandler(callback=self.ui.add_log)
                self._main_loop()
            except KeyboardInterrupt:
                print("\n[!] Arrêt par utilisateur")
            except Exception as e:
                print(f"\n[!] Erreur: {e}")
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
        shadowprotocol          - Interactive mode (choose a/b/c)
        shadowprotocol A        - Run MODE A directly
        shadowprotocol B        - Run MODE B directly
        shadowprotocol C        - Run MODE C directly
    """
    app = ShadowProtocolApp()

    if len(sys.argv) > 1:
        mode = sys.argv[1].upper()
        if mode in ('A', 'B', 'C'):
            app.run(mode)
        else:
            print(f"Mode inconnue: {mode}")
            print("Utilisation: shadowprotocol [A|B|C]")
            sys.exit(1)
    else:
        app.run()


if __name__ == "__main__":
    main()
