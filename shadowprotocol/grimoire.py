"""
ShadowProtocol - Le Grimoire (TUI 5 Chapitres)

Interface terminale structuree en 5 blocs horizontaux:

  Chapitre I   : SHADOWPROTOCOL (banniere)
  Chapitre II  : Les 6 Rituels (menu A/B/C/D/E/F/Q)
  Chapitre III : L'Esprit Cible (info binaire)
  Chapitre IV  : Les Visions (30 lignes, defilantes)
  Chapitre V   : Les Transmutations (resultats patch)

Basee sur curses avec fallback ANSI.
Etendue pour supporter les 6 rituels (A-F).
"""

import sys
import os
import curses
import select
import threading
import termios
import tty
from collections import deque
from typing import Optional, Callable, List, Tuple

class GrimoireUI:
    """Interface du Grimoire - 5 Chapitres fixes avec curses.

    Layout vertical (adapte a la taille du terminal):

    +--------------------------------------------------+
    | CHAPITRE I : SHADOWPROTOCOL                       |
    +--------------------------------------------------+
    | CHAPITRE II : Les 6 Rituels                       |
    |   [A] Invocation Precise  [B] Balayage d'Ame      |
    |   [C] Canal R2 Brut       [D] Patcheur Flutter    |
    |   [E] Quete Fonctions     [F] Patcheur Manifeste  |
    |   [Q] Fermer le Grimoire                          |
    +--------------------------------------------------+
    | CHAPITRE III : L'Esprit Cible                     |
    |   Nom : libapp.so   Nature : ARM64               |
    |   Poids : 4.2 Mo    Canal r2 : Ouvert            |
    |   Esprits detectes :                              |
    |   [1] libapp.so  [2] libfoo.so                   |
    +--------------------------------------------------+
    | CHAPITRE IV : Les Visions (30 lignes)             |
    |   [10:17:01] Le canal s'ouvre...                  |
    |   [10:17:02] 42 runes decouvertes                 |
    +--------------------------------------------------+
    | CHAPITRE V : Les Transmutations                   |
    |   0x123456 | add x0,x22,0x30 -> 0x20 OK          |
    |   Total des ames transmutees : 42                 |
    +--------------------------------------------------+
    """

    MAX_VISIONS = 30
    SEPARATOR = "\u2591" * 60

    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.lock = threading.Lock()
        self.log_lock = threading.Lock()

        # Configuration curses
        curses.curs_set(0)
        curses.noecho()
        stdscr.nodelay(True)
        stdscr.keypad(True)

        # Couleurs
        self._has_colors = curses.has_colors()
        if self._has_colors:
            curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)     # Info
            curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)    # Succes
            curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)      # Erreur
            curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)   # Avertissement
            curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)     # Progression
            curses.init_pair(6, curses.COLOR_MAGENTA, curses.COLOR_BLACK)  # Mystique
            curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLACK)    # Normal

        # Etat
        self.height, self.width = stdscr.getmaxyx()
        self.vision_buffer = deque(maxlen=self.MAX_VISIONS)
        self.transmutations: List[Tuple[str, str, str, bool]] = []
        self.progress_pct = 0
        self.progress_text = ""
        self.mode_label = "EN VEILLE"
        self.running = True

        # Info cible
        self.target_name = "Aucun"
        self.target_arch = "---"
        self.target_size = "---"
        self.target_r2_status = "Ferme"
        self.detected_targets: List[str] = []

        # Mode saisie
        self._input_active = False
        self._input_prompt = ""
        self._input_buffer = ""
        self._input_callback = None

        # Mode Rituel C - sous-menu
        self._c_menu_active = False
        self._c_choice = ""
        self._c_awaiting_cmd = False

    # -- Mise a jour d'etat (thread-safe) ------------------------------

    def update_dimensions(self) -> bool:
        """Verifier et mettre a jour les dimensions du terminal."""
        try:
            new_h, new_w = self.stdscr.getmaxyx()
            if (new_h, new_w) != (self.height, self.width):
                self.height = new_h
                self.width = new_w
                return True
        except curses.error:
            pass
        return False

    def add_vision(self, message: str):
        """Ajouter une vision au tampon (thread-safe)."""
        with self.log_lock:
            self.vision_buffer.append(message)

    # Alias pour compatibilite
    def add_log(self, message: str):
        """Alias: ajouter un message de log (compatibilite v3)."""
        self.add_vision(message)

    def add_transmutation(self, offset: str, original: str,
                         patched: str, success: bool):
        """Ajouter une transmutation au Chapitre V."""
        with self.lock:
            self.transmutations.append((offset, original, patched, success))

    def clear_transmutations(self):
        """Vider les transmutations."""
        with self.lock:
            self.transmutations.clear()

    def set_progress(self, current: int, total: int, label: str = ""):
        """Mettre a jour la barre de progression."""
        with self.lock:
            self.progress_pct = int((current / total * 100)) if total > 0 else 0
            self.progress_text = f"{label} {current}/{total}"

    def set_mode(self, mode: str):
        """Mettre a jour le label de mode."""
        with self.lock:
            self.mode_label = mode

    # Alias pour compatibilite
    def set_status(self, status: str):
        """Mettre a jour le statut (compatibilite v3). Alias vers set_mode."""
        self.set_mode(status)
    def set_target_info(self, name: str, arch: str, size: str,
                        r2_status: str, detected: List[str] = None):
        """Mettre a jour les infos de la cible (Chapitre III)."""
        with self.lock:
            self.target_name = name
            self.target_arch = arch
            self.target_size = size
            self.target_r2_status = r2_status
            self.detected_targets = detected or []

    # -- Mode saisie ----------------------------------------------------

    def enter_input_mode(self, prompt: str, callback: Callable[[str], None]):
        """Activer le mode saisie de texte."""
        with self.lock:
            self._input_active = True
            self._input_prompt = prompt
            self._input_buffer = ""
            self._input_callback = callback
        try:
            curses.curs_set(1)
        except curses.error:
            pass

    def exit_input_mode(self):
        """Desactiver le mode saisie."""
        with self.lock:
            self._input_active = False
            self._input_prompt = ""
            self._input_buffer = ""
            self._input_callback = None
        try:
            curses.curs_set(0)
        except curses.error:
            pass

    @property
    def is_input_active(self) -> bool:
        return self._input_active

    # -- Dessin des chapitres -------------------------------------------

    def _color(self, pair: int, bold: bool = False) -> int:
        """Obtenir l'attribut de couleur curses."""
        attr = curses.color_pair(pair)
        if bold:
            attr |= curses.A_BOLD
        return attr

    def _safe_addstr(self, y: int, x: int, text: str, attr: int = 0):
        """Ecrire sans lever d'erreur hors limites."""
        try:
            self.stdscr.addstr(y, x, text[:self.width - x], attr)
        except curses.error:
            pass

    def _draw_separator(self, y: int):
        """Dessiner une ligne de separation."""
        sep = "\u2591" * min(self.width, 60)
        self._safe_addstr(y, 0, sep, self._color(6) | curses.A_DIM)

    def _draw_chapitre_i(self, y: int) -> int:
        """Chapitre I : SHADOWPROTOCOL - Banniere."""
        self._draw_separator(y)
        y += 1
        title = "SHADOWPROTOCOL - Le Grimoire v4.0"
        pad = max(0, (self.width - len(title) - 4) // 2)
        display = " " * pad + title + " " * pad
        self._safe_addstr(y, 0, display, self._color(6, bold=True))
        y += 1
        self._draw_separator(y)
        return y + 1

    def _draw_chapitre_ii(self, y: int) -> int:
        """Chapitre II : Les 6 Rituels - Menu."""
        self._safe_addstr(y, 0, "  Chapitre II : Les 6 Rituels",
                          self._color(1, bold=True))
        y += 1

        if self._c_menu_active:
            # Sous-menu Rituel C
            self._safe_addstr(y, 2, "[1] Scruter & Ecrire   [2] Analyser (aaa)",
                              self._color(4))
            y += 1
            self._safe_addstr(y, 2, "[3] Desassembler (pd)  [4] Voir l'Hex (px)",
                              self._color(4))
            y += 1
            self._safe_addstr(y, 2, "[5] Sections (iS)      [6] Cordes (iz)",
                              self._color(4))
            y += 1
            self._safe_addstr(y, 2, "[7] Croisements (axt)  [8] Ecrire asm (wa)",
                              self._color(4))
            y += 1
            self._safe_addstr(y, 2, "[9] Patch hex (wx)     [0] Quitter & Sauver",
                              self._color(4))
        else:
            self._safe_addstr(y, 2,
                              "[A] Invocation Precise  [B] Balayage d'Ame",
                              self._color(2))
            y += 1
            self._safe_addstr(y, 2,
                              "[C] Canal R2 Brut       [D] Patcheur Flutter",
                              self._color(2))
            y += 1
            self._safe_addstr(y, 2,
                              "[E] Quete Fonctions     [F] Patcheur Manifeste",
                              self._color(2))
            y += 1
            self._safe_addstr(y, 2,
                              "[Q] Fermer le Grimoire",
                              self._color(3))

        y += 1
        self._draw_separator(y)
        return y + 1

    def _draw_chapitre_iii(self, y: int) -> int:
        """Chapitre III : L'Esprit Cible."""
        self._safe_addstr(y, 0, "  Chapitre III : L'Esprit Cible",
                          self._color(1, bold=True))
        y += 1

        line1 = f"    Nom : {self.target_name}        Nature : {self.target_arch}"
        self._safe_addstr(y, 0, line1, self._color(7))
        y += 1

        line2 = f"    Poids : {self.target_size}        Canal r2 : {self.target_r2_status}"
        self._safe_addstr(y, 0, line2, self._color(7))
        y += 1

        if self.detected_targets:
            targets_str = "    Esprits detectes : "
            for i, t in enumerate(self.detected_targets[:5], 1):
                targets_str += f"[{i}] {os.path.basename(t)}  "
            self._safe_addstr(y, 0, targets_str, self._color(4))
            y += 1

        self._draw_separator(y)
        return y + 1

    def _draw_chapitre_iv(self, y: int, available_lines: int) -> int:
        """Chapitre IV : Les Visions (30 lignes, defilantes)."""
        self._safe_addstr(y, 0, "  Chapitre IV : Les Visions",
                          self._color(1, bold=True))
        y += 1

        # Zone de visions
        vision_height = max(1, available_lines - 2)
        visions = list(self.vision_buffer)
        start_idx = max(0, len(visions) - vision_height)

        for i, vision in enumerate(visions[start_idx:]):
            if y >= self.height - 6:
                break

            # Coloration selon le prefix
            color = self._color(1)  # Cyan par defaut
            if "[+]" in vision:
                color = self._color(2)  # Vert
            elif "[!]" in vision:
                color = self._color(3)  # Rouge
            elif "[W]" in vision:
                color = self._color(4)  # Jaune
            elif "[D]" in vision:
                color = self._color(4) | curses.A_DIM

            self._safe_addstr(y, 1, vision[:self.width - 2], color)
            y += 1

        # Barre de progression si pas en mode saisie
        if not self._input_active and self.progress_pct > 0:
            bar_width = max(self.width - 30, 10)
            filled = int(bar_width * self.progress_pct / 100)
            bar = "\u2588" * filled + "\u2591" * (bar_width - filled)
            prog_line = f"  [{bar}] {self.progress_pct:3d}%"
            if self.progress_text:
                prog_line += f" {self.progress_text}"
            self._safe_addstr(y, 0, prog_line[:self.width],
                              self._color(5))
            y += 1

        self._draw_separator(y)
        return y + 1

    def _draw_chapitre_v(self, y: int) -> int:
        """Chapitre V : Les Transmutations."""
        self._safe_addstr(y, 0, "  Chapitre V : Les Transmutations",
                          self._color(1, bold=True))
        y += 1

        # Afficher les dernieres transmutations (max 4 lignes)
        recent = self.transmutations[-4:] if self.transmutations else []
        for offset, original, patched, success in recent:
            mark = "\u2713" if success else "\u2717"
            if success:
                line = f"    \u2022 {offset} | {original} \u2192 {patched} {mark}"
                color = self._color(2)
            else:
                line = f"    \u2022 {offset} | {original} ECHEC {mark}"
                color = self._color(3)
            self._safe_addstr(y, 0, line, color)
            y += 1

        if self.transmutations:
            total = sum(1 for _, _, _, s in self.transmutations if s)
            total_line = f"    Total des ames transmutees : {total}"
            self._safe_addstr(y, 0, total_line, self._color(6, bold=True))
            y += 1
        else:
            self._safe_addstr(y, 2, "Aucune transmutation enregistree",
                              self._color(7) | curses.A_DIM)
            y += 1

        self._draw_separator(y)
        return y + 1

    def _draw_input_line(self, y: int):
        """Dessiner la ligne de saisie si active."""
        if not self._input_active:
            return
        display = f"  > {self._input_prompt}{self._input_buffer}_"
        self._safe_addstr(y, 0, display, self._color(1, bold=True))

    def _draw_footer(self):
        """Dessiner le pied de page avec les controles."""
        footer_y = self.height - 1
        if self._c_menu_active:
            footer = " [0-9] Pouvoir r2 | [Esc] Retour"
        elif self._input_active:
            footer = " [Entree] Confirmer | [Esc] Annuler | [Retour] Effacer"
        else:
            footer = " [1] Cible | [2] Sigil | [A-F] Rituel | [Q] Quitter"
        self._safe_addstr(footer_y, 0, footer, self._color(4) | curses.A_DIM)

    # -- Rafraichissement -----------------------------------------------

    def refresh(self):
        """Rafraichissement complet de l'affichage."""
        with self.lock:
            try:
                self.stdscr.erase()

                # Calcul dynamique des hauteurs de chapitres
                y = 0

                # Chapitre I : 3 lignes
                y = self._draw_chapitre_i(y)

                # Chapitre II : 3-6 lignes selon sous-menu C
                y = self._draw_chapitre_ii(y)

                # Chapitre III : 4-5 lignes
                y = self._draw_chapitre_iii(y)

                # Chapitre V (en bas) : on reserve l'espace
                chap5_lines = 3 + min(len(self.transmutations), 4)
                chap5_lines = min(chap5_lines, 7)
                footer_y = self.height - 1

                # Chapitre IV prend l'espace restant
                chap4_available = footer_y - y - chap5_lines - 1
                if chap4_available < 5:
                    chap4_available = 5

                y = self._draw_chapitre_iv(y, chap4_available)

                # Chapitre V
                self._draw_chapitre_v(y)

                # Ligne de saisie
                if self._input_active:
                    input_y = max(0, footer_y - 1)
                    self._draw_input_line(input_y)

                # Footer
                self._draw_footer()

                self.stdscr.refresh()
            except curses.error:
                pass

    # -- Entree clavier -------------------------------------------------

    def get_input(self) -> Optional[str]:
        """Obtenir l'entree clavier (non-bloquant).

        En mode normal: retourne le caractere minuscule.
        En mode saisie: capture les caracteres dans le tampon.
        En mode Rituel C: capture les choix du sous-menu.
        """
        try:
            ch = self.stdscr.getch()
            if ch == -1:
                return None

            if self._input_active:
                self._handle_input_char(ch)
                return None

            return chr(ch).lower()
        except Exception:
            pass
        return None

    def _handle_input_char(self, ch: int):
        """Gerer un caractere en mode saisie."""
        if ch == curses.KEY_ENTER or ch == 10 or ch == 13:
            result = self._input_buffer
            callback = self._input_callback
            self.exit_input_mode()
            if callback and result.strip():
                callback(result.strip())
        elif ch == 27:  # Escape
            self.exit_input_mode()
            if self._c_menu_active:
                self._c_menu_active = False
        elif ch == curses.KEY_BACKSPACE or ch == 127 or ch == 8:
            with self.lock:
                self._input_buffer = self._input_buffer[:-1]
        elif ch == curses.KEY_RESIZE:
            pass
        elif 32 <= ch <= 126:
            with self.lock:
                self._input_buffer += chr(ch)

    @property
    def c_menu_active(self) -> bool:
        return self._c_menu_active

    @c_menu_active.setter
    def c_menu_active(self, value: bool):
        with self.lock:
            self._c_menu_active = value

    def stop(self):
        """Arreter le TUI et restaurer le terminal."""
        self.running = False
        self._input_active = False
        self._c_menu_active = False
        try:
            curses.echo()
            curses.nocbreak()
            self.stdscr.keypad(False)
            curses.curs_set(1)
            curses.endwin()
        except Exception:
            pass

class GrimoireANSI:
    """Interface du Grimoire en fallback ANSI (si curses indisponible).

    Meme structure 5 chapitres mais avec sequences d'echappement ANSI.
    """

    MAX_VISIONS = 30

    # Codes ANSI
    CYAN = '\033[96m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    GREY = '\033[90m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    SEP = "\u2591" * 60

    def __init__(self):
        self.lock = threading.Lock()
        self.log_lock = threading.Lock()
        self.vision_buffer = deque(maxlen=self.MAX_VISIONS)
        self.transmutations: List[Tuple[str, str, str, bool]] = []
        self.progress_pct = 0
        self.progress_text = ""
        self.mode_label = "EN VEILLE"
        self.running = True

        self.target_name = "Aucun"
        self.target_arch = "---"
        self.target_size = "---"
        self.target_r2_status = "Ferme"
        self.detected_targets: List[str] = []

        self._input_active = False
        self._input_prompt = ""
        self._input_buffer = ""
        self._input_callback = None
        self._c_menu_active = False

        self._old_settings = None
        try:
            self._old_settings = termios.tcgetattr(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
        except Exception:
            pass

    def update_dimensions(self) -> bool:
        try:
            new_size = os.get_terminal_size()
            if not hasattr(self, '_last_size') or self._last_size != new_size:
                self._last_size = new_size
                return True
            return False
        except Exception:
            return False

    def add_vision(self, message: str):
        with self.log_lock:
            self.vision_buffer.append(message)

    # Alias pour compatibilite
    def add_log(self, message: str):
        """Alias: ajouter un message de log (compatibilite v3)."""
        self.add_vision(message)

    def add_transmutation(self, offset: str, original: str,
                         patched: str, success: bool):
        with self.lock:
            self.transmutations.append((offset, original, patched, success))

    def clear_transmutations(self):
        with self.lock:
            self.transmutations.clear()

    def set_progress(self, current: int, total: int, label: str = ""):
        with self.lock:
            self.progress_pct = int((current / total * 100)) if total > 0 else 0
            self.progress_text = f"{label} {current}/{total}"

    def set_mode(self, mode: str):
        with self.lock:
            self.mode_label = mode

    def set_status(self, status: str):
        """Compatibilite v3. Alias vers set_mode."""
        self.set_mode(status)

    def set_target_info(self, name: str, arch: str, size: str,
                        r2_status: str, detected: List[str] = None):
        with self.lock:
            self.target_name = name
            self.target_arch = arch
            self.target_size = size
            self.target_r2_status = r2_status
            self.detected_targets = detected or []

    def enter_input_mode(self, prompt: str, callback: Callable[[str], None]):
        with self.lock:
            self._input_active = True
            self._input_prompt = prompt
            self._input_buffer = ""
            self._input_callback = callback

    def exit_input_mode(self):
        with self.lock:
            self._input_active = False
            self._input_prompt = ""
            self._input_buffer = ""
            self._input_callback = None

    @property
    def is_input_active(self) -> bool:
        return self._input_active

    @property
    def c_menu_active(self) -> bool:
        return self._c_menu_active

    @c_menu_active.setter
    def c_menu_active(self, value: bool):
        with self.lock:
            self._c_menu_active = value

    def _colorize(self, text: str, color: str, bold: bool = False) -> str:
        prefix = self.BOLD if bold else ""
        return f"{prefix}{color}{text}{self.RESET}"

    def refresh(self):
        """Rafraichissement complet via ANSI."""
        with self.lock:
            print("\033[2J\033[H", end="", flush=True)

            # Chapitre I
            print(self._colorize(self.SEP, self.MAGENTA))
            print(self._colorize("  SHADOWPROTOCOL - Le Grimoire v4.0", self.MAGENTA, bold=True))
            print(self._colorize(self.SEP, self.MAGENTA))

            # Chapitre II
            print(self._colorize("  Chapitre II : Les 6 Rituels", self.CYAN, bold=True))
            if self._c_menu_active:
                print(self._colorize("  [1] Scruter & Ecrire   [2] Analyser (aaa)", self.YELLOW))
                print(self._colorize("  [3] Desassembler (pd)  [4] Voir l'Hex (px)", self.YELLOW))
                print(self._colorize("  [5] Sections (iS)      [6] Cordes (iz)", self.YELLOW))
                print(self._colorize("  [7] Croisements (axt)  [8] Ecrire asm (wa)", self.YELLOW))
                print(self._colorize("  [9] Patch hex (wx)     [0] Quitter & Sauver", self.YELLOW))
            else:
                print(self._colorize("  [A] Invocation Precise  [B] Balayage d'Ame", self.GREEN))
                print(self._colorize("  [C] Canal R2 Brut       [D] Patcheur Flutter", self.GREEN))
                print(self._colorize("  [E] Quete Fonctions     [F] Patcheur Manifeste", self.GREEN))
                print(self._colorize("  [Q] Fermer le Grimoire", self.RED))
            print(self._colorize(self.SEP, self.MAGENTA))

            # Chapitre III
            print(self._colorize("  Chapitre III : L'Esprit Cible", self.CYAN, bold=True))
            print(f"    Nom : {self.target_name}        Nature : {self.target_arch}")
            print(f"    Poids : {self.target_size}        Canal r2 : {self.target_r2_status}")
            if self.detected_targets:
                ts = "    Esprits : "
                for i, t in enumerate(self.detected_targets[:5], 1):
                    ts += f"[{i}] {os.path.basename(t)}  "
                print(self._colorize(ts, self.YELLOW))
            print(self._colorize(self.SEP, self.MAGENTA))

            # Chapitre IV
            print(self._colorize("  Chapitre IV : Les Visions", self.CYAN, bold=True))
            visions = list(self.vision_buffer)
            for v in visions[-20:]:
                if "[+]" in v:
                    print(self._colorize(f"  {v}", self.GREEN))
                elif "[!]" in v:
                    print(self._colorize(f"  {v}", self.RED))
                elif "[W]" in v:
                    print(self._colorize(f"  {v}", self.YELLOW))
                else:
                    print(self._colorize(f"  {v}", self.CYAN))

            # Progression
            if not self._input_active and self.progress_pct > 0:
                bar_w = 30
                filled = int(bar_w * self.progress_pct / 100)
                bar = "\u2588" * filled + "\u2591" * (bar_w - filled)
                print(f"  [{bar}] {self.progress_pct:3d}% {self.progress_text}")

            print(self._colorize(self.SEP, self.MAGENTA))

            # Chapitre V
            print(self._colorize("  Chapitre V : Les Transmutations", self.CYAN, bold=True))
            recent = self.transmutations[-4:] if self.transmutations else []
            for offset, original, patched, success in recent:
                mark = "\u2713" if success else "\u2717"
                if success:
                    print(self._colorize(
                        f"    \u2022 {offset} | {original} \u2192 {patched} {mark}",
                        self.GREEN))
                else:
                    print(self._colorize(
                        f"    \u2022 {offset} | {original} ECHEC {mark}",
                        self.RED))
            if self.transmutations:
                total = sum(1 for _, _, _, s in self.transmutations if s)
                print(self._colorize(
                    f"    Total des ames transmutees : {total}",
                    self.MAGENTA, bold=True))
            else:
                print(self._colorize("    Aucune transmutation", self.GREY))
            print(self._colorize(self.SEP, self.MAGENTA))

            # Ligne de saisie
            if self._input_active:
                print(self._colorize(
                    f"  > {self._input_prompt}{self._input_buffer}_",
                    self.CYAN, bold=True))

            # Footer
            if self._c_menu_active:
                print(self._colorize(" [0-9] Pouvoir r2 | [Esc] Retour", self.YELLOW))
            elif self._input_active:
                print(self._colorize(" [Entree] Confirmer | [Esc] Annuler", self.YELLOW))
            else:
                print(self._colorize(" [1] Cible | [2] Sigil | [A-F] Rituel | [Q] Quitter", self.YELLOW))

    def get_input(self) -> Optional[str]:
        try:
            if select.select([sys.stdin], [], [], 0)[0]:
                ch = sys.stdin.read(1)
                if not ch:
                    return None
                if self._input_active:
                    self._handle_ansi_input(ch)
                    return None
                return ch.lower()
        except Exception:
            pass
        return None

    def _handle_ansi_input(self, ch: str):
        if ch == '\n' or ch == '\r':
            result = self._input_buffer
            callback = self._input_callback
            self.exit_input_mode()
            if callback and result.strip():
                callback(result.strip())
        elif ch == '\x1b':
            self.exit_input_mode()
            if self._c_menu_active:
                self._c_menu_active = False
        elif ch == '\x7f' or ch == '\x08':
            with self.lock:
                self._input_buffer = self._input_buffer[:-1]
        elif ch.isprintable():
            with self.lock:
                self._input_buffer += ch

    def stop(self):
        self.running = False
        self._input_active = False
        self._c_menu_active = False
        if self._old_settings is not None:
            try:
                termios.tcsetattr(sys.stdin.fileno(),
                                  termios.TCSADRAIN,
                                  self._old_settings)
            except Exception:
                pass
