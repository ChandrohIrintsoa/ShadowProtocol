"""
ShadowProtocol v4.0 - Main Application
Le Grimoire de Transmutation Binaire

Orchestrateur principal de l'application:
- Initialisation du TUI (curses avec fallback ANSI)
- Gestion des entrees utilisateur
- Execution des rituels dans des threads separes
- Selection de cible binaire (chemin manuel + detection auto)
- Collecte d'offset pour Rituel A
- Dictionnaire de mots-cles pour Rituel A/B
- Effacement radical des cibles et cache/log
- Sous-menu interactif pour Rituel C (pouvoirs Radare2)
- Arret gracieux avec nettoyage
"""

import sys
import os
import re
import time
import signal
import curses
import threading
from datetime import datetime
from typing import Optional

from .config import Config
from .logger import LoggerHandler
from .r2handler import Radare2Handler
from .target import TargetSelector
from .rituals import get_ritual, BaseRitual, RituelC
from .keyword_analyzer import KeywordDictionary
from .file_manager import FileManager
from .grimoire import GrimoireUI, GrimoireANSI

VALID_MODES = ('A', 'B', 'C', 'D', 'E', 'F')
MODES_REQUIRING_TARGET = ('A', 'B', 'C', 'E')


class ShadowProtocolApp:
    """Orchestrateur principal du Grimoire ShadowProtocol."""

    def __init__(self):
        self.ui = None
        self.logger = None
        self.current_ritual: Optional[BaseRitual] = None
        self.ritual_thread: Optional[threading.Thread] = None
        self.running = True
        self.stop_requested = False
        self._requested_mode: Optional[str] = None

        # Cible
        self.target_selector = TargetSelector()
        self.current_target: Optional[str] = None
        self.current_offset: Optional[str] = None
        self.r2_handler: Optional[Radare2Handler] = None

        # Detection automatique des .so
        self._auto_detected: list = []

        # Dictionnaire de mots-cles
        self.keyword_dict: Optional[KeywordDictionary] = None

        # Rituel D: chemin d'input et repertoire de sortie
        # Par defaut: memoire du telephone (/storage/emulated/0/MT2/ShadowProtocol)
        self._d_output_dir: Optional[str] = '/storage/emulated/0/MT2/ShadowProtocol'

        # Handlers de signaux
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame):
        """Gerer les signaux systeme (SIGINT, SIGTERM)."""
        self.stop_requested = True
        self.running = False

    def display_welcome(self):
        """Afficher les messages d'accueil."""
        self.logger.success("Le Grimoire ShadowProtocol s'ouvre...")
        self.logger.info("Forge pour alterer les esprits de pierre (binaires .so)")
        self.logger.info("par l'invocation de Radare2")
        self.logger.info("")
        self.logger.info("[1] Entrer le chemin de l'esprit cible (.so / .apk / repertoire)")
        self.logger.info("[2] Entrer le sigil hex (offset pptool, pour Rituel A)")
        self.logger.info("[3] Charger un dictionnaire de mots-cles (.txt)")
        self.logger.info("[5] Ajouter des mots-cles manuellement")
        self.logger.info("[4] Effacer radicalement les cibles et cache/log")
        self.logger.info("[A] Rituel A - L'Invocation Precise (+ dictionnaire)")
        self.logger.info("[B] Rituel B - Le Balayage d'Ame (+ dictionnaire)")
        self.logger.info("[C] Rituel C - La Connexion Directe (canal R2 brut)")
        self.logger.info("[D] Rituel D - Les Transmutations Blutter")
        self.logger.info("[E] Rituel E - La Quete des Fonctions")
        self.logger.info("[F] Rituel F - Le Patcheur de Manifeste")
        self.logger.info("[Q] Fermer le Grimoire")
        self.logger.warning("Radare2 et r2pipe sont requis pour les Rituels A-C")

    def _auto_detect_targets(self):
        """Detecter automatiquement les fichiers .so a l'ouverture."""
        self._auto_detected = self.target_selector.find_so_targets(recursive=True)
        if self._auto_detected:
            self.logger.info(f"{len(self._auto_detected)} esprit(s) detecte(s) aux alentours")
            for t in self._auto_detected:
                self.logger.info(f"  -> {t}")
            self.ui.set_target_info(
                "---", "---", "---", "Ferme",
                self._auto_detected
            )

    def _open_r2(self, path: str) -> bool:
        """Ouvrir un handler Radare2 pour la cible."""
        if self.r2_handler:
            try:
                self.r2_handler.close()
            except Exception:
                pass

        self.r2_handler = Radare2Handler(path)
        name, arch, size, rw = self.target_selector.get_file_info(path)
        self.ui.set_target_info(name, arch, size, "Pret", self._auto_detected)
        return True

    def _start_ritual(self, mode_name: str):
        """Demarrer un rituel dans un thread daemon."""
        if mode_name.upper() in MODES_REQUIRING_TARGET and not self.current_target:
            self.logger.warning("Selectionnez un esprit cible d'abord (option [1])")
            return

        if mode_name.upper() == 'A' and not self.current_offset and not self.keyword_dict:
            self.logger.warning("Fournissez un sigil hex (option [2]) ou un dictionnaire (option [3])")
            return

        try:
            self.ui.clear_transmutations()

            if mode_name.upper() in ('A', 'B', 'C', 'E'):
                self._open_r2(self.current_target)

            ritual = get_ritual(
                mode_name,
                self._log_with_transmutation,
                self.ui.set_progress,
                r2_handler=self.r2_handler,
                offset=self.current_offset if mode_name.upper() == 'A' else None,
                binary_path=self.current_target if mode_name.upper() in ('D', 'E', 'F') else None,
                keyword_dict=self.keyword_dict if mode_name.upper() in ('A', 'B') else None,
                output_dir=self._d_output_dir if mode_name.upper() == 'D' else None,
            )
            self.current_ritual = ritual
            self.ui.set_mode(f"RITUEL {mode_name.upper()}")

            self.ritual_thread = threading.Thread(
                target=self._execute_ritual_thread,
                daemon=True
            )
            self.ritual_thread.start()
        except ValueError as e:
            self.logger.error(str(e))

    def _log_with_transmutation(self, message: str):
        """Callback de log qui detecte et enregistre les transmutations."""
        self.logger.info(message)

        match = re.search(
            r'(0x[0-9a-fA-F]+)\s*\|\s*(add\s+x\d+,\s*x\d+,\s*0x30)\s*->\s*(0x20)\s*(OK|ECHEC)',
            message
        )
        if match:
            offset = match.group(1)
            original = match.group(2)
            patched_val = match.group(3)
            status = match.group(4) == "OK"
            self.ui.add_transmutation(offset, original, patched_val, status)

    def _execute_ritual_thread(self):
        """Executer le rituel dans un thread et mettre a jour le statut."""
        try:
            success = self.current_ritual.execute()
            if success:
                self.ui.set_mode("TERMINE")
                self.logger.success("Rituel execute avec succes")
            else:
                self.ui.set_mode("ARRETE")
                self.logger.warning("Rituel interrompu ou echoue")
        except Exception as e:
            self.logger.error(f"Erreur rituel: {e}")
            self.ui.set_mode("ERREUR")

    def _request_target_path(self):
        """Demander le chemin de la cible via le TUI."""
        if self.ui.is_input_active:
            return
        self.logger.info("Entrez le chemin vers le fichier cible (.so / .apk) ou repertoire (libapp+libflutter):")
        self.ui.enter_input_mode("Chemin: ", self._on_target_path_entered)

    def _on_target_path_entered(self, path: str):
        """Callback quand l'utilisateur soumet un chemin de cible."""
        expanded = os.path.expanduser(path)
        expanded = os.path.expandvars(expanded)

        # Mode D: accepter les repertoires contenant libapp.so + libflutter.so
        if os.path.isdir(expanded):
            libapp = os.path.join(expanded, 'libapp.so')
            libflutter = os.path.join(expanded, 'libflutter.so')
            if os.path.isfile(libapp) and os.path.isfile(libflutter):
                self.current_target = os.path.abspath(expanded)
                self.logger.success(f"Repertoire Flutter valide: {self.current_target}")
                self.logger.info("  libapp.so et libflutter.so detectes")
                return
            else:
                self.logger.error(f"Repertoire sans libapp.so/libflutter.so: {path}")
                self.logger.info("Le repertoire doit contenir libapp.so et libflutter.so")
                return

        validated = self.target_selector.validate_manual_path(path)
        if validated:
            self.current_target = validated
            name, arch, size, rw = self.target_selector.get_file_info(validated)
            self.logger.success(f"Esprit cible: {validated}")
            self.logger.info(f"  Nom: {name} | Nature: {arch} | Poids: {size} | RW: {rw}")
            self._open_r2(validated)
        else:
            if os.path.isfile(path):
                self.current_target = os.path.abspath(path)
                self.logger.success(f"Fichier selectionne: {self.current_target}")
                self._open_r2(self.current_target)
            else:
                self.logger.error(f"Esprit invalide: {path}")
                self.logger.info("Le fichier doit exister et etre un binaire ELF (.so) ou APK")

    def _request_offset(self):
        """Demander l'offset pptool via le TUI (pour Rituel A)."""
        if self.ui.is_input_active:
            return
        if not self.current_target:
            self.logger.warning("Selectionnez un esprit cible d'abord (option [1])")
            return
        self.logger.info("Entrez le sigil hexadecimal (offset pptool, format: 0x...):")
        self.ui.enter_input_mode("Offset: ", self._on_offset_entered)

    def _on_offset_entered(self, offset: str):
        """Callback quand l'utilisateur soumet un offset."""
        if re.match(r'^0x[0-9a-fA-F]+$', offset):
            self.current_offset = offset
            self.logger.success(f"Sigil defini: {offset}")
        else:
            self.logger.error(f"Format de sigil invalide: {offset}")
            self.logger.info("Format attendu: 0x... (ex: 0x123456)")

    def _request_dictionary(self):
        """Demander le chemin du dictionnaire de mots-cles."""
        if self.ui.is_input_active:
            return
        self.logger.info("Entrez le chemin vers le fichier dictionnaire (.txt):")
        self.logger.info("Format: mots-cles separes par virgule ou un par ligne")
        self.ui.enter_input_mode("Dictionnaire: ", self._on_dictionary_entered)

    def _on_dictionary_entered(self, path: str):
        """Callback quand l'utilisateur soumet un chemin de dictionnaire."""
        expanded = os.path.expanduser(path)
        expanded = os.path.expandvars(expanded)

        if not os.path.isfile(expanded):
            self.logger.error(f"Fichier non trouve: {path}")
            return

        kw_dict = KeywordDictionary(expanded)
        if kw_dict.is_loaded():
            self.keyword_dict = kw_dict
            self.logger.success(f"Dictionnaire charge: {len(kw_dict)} mot(s)-cle(s)")
            for kw in kw_dict.get_keywords():
                self.logger.info(f"  -> {kw}")
        else:
            self.logger.error("Echec du chargement du dictionnaire")

    def _request_manual_keywords(self):
        """Ajouter des mots-cles manuellement."""
        if self.ui.is_input_active:
            return
        self.logger.info("Entrez les mots-cles (separes par virgule ou espace):")
        self.logger.info('Exemple: "mot1", "mot2" ou mot1, mot2')
        self.ui.enter_input_mode("Mots-cles: ", self._on_manual_keywords_entered)

    def _on_manual_keywords_entered(self, input_str: str):
        """Callback quand l'utilisateur ajoute des mots-cles manuellement."""
        if not self.keyword_dict:
            self.keyword_dict = KeywordDictionary()

        added = self.keyword_dict.add_keywords_from_input(input_str)
        self.logger.success(f"{added} mot(s)-cle(s) ajoute(s) (total: {len(self.keyword_dict)})")

    def _radical_erase(self):
        """Effacer radicalement les cibles et le cache/log."""
        if not self.current_target:
            self.logger.warning("Aucune cible selectionnee a effacer")
            return

        fm = FileManager(self.current_target)
        self.logger.warning(f"EFFACEMENT RADICAL de: {self.current_target}")
        self.logger.info("Suppression des cibles et cache/log...")

        deleted, errors = fm.radical_erase(keep_skull=True)

        self.logger.success(f"{deleted} element(s) supprime(s), {errors} erreur(s)")

        # Nettoyer aussi les logs generaux
        log_count = fm.cleanup_logs()
        if log_count > 0:
            self.logger.info(f"{log_count} fichier(s) log supprime(s)")

        # Reinitialiser
        self.current_target = None
        self.current_offset = None
        self.r2_handler = None
        self.ui.set_target_info("---", "---", "---", "Ferme", [])

    def _handle_c_menu_choice(self, ch: str):
        """Gerer les choix du sous-menu Rituel C."""
        if ch == '0':
            self.logger.info("Canal R2 ferme")
            self.ui.c_menu_active = False
            self.ui.set_mode("EN VEILLE")
            return

        param_choices = {
            '1': ("Adresse & ASM (ex: s 0x1000; wa add x0,x22,0x20): ", "seek_write"),
            '3': ("Adresse + nb lignes (ex: pd 20 @ 0x1000): ", "pd"),
            '4': ("Adresse + nb octets (ex: px 64 @ 0x1000): ", "px"),
            '7': ("Adresse cible (ex: 0x1000): ", "axt"),
            '8': ("Instruction ASM (ex: add x0,x22,0x20): ", "wa"),
            '9': ("Hex + adresse (ex: 90909090 @ 0x1000): ", "wx"),
        }

        no_param_choices = {
            '2': "aaa",
            '5': "iS",
            '6': "iz",
        }

        if ch in no_param_choices:
            self._execute_c_ritual(ch, no_param_choices[ch])
        elif ch in param_choices:
            prompt, _ = param_choices[ch]
            self.logger.info(f"Pouvoir {ch} selectionne. Entrez les parametres:")
            self.ui.enter_input_mode(prompt, lambda cmd, c=ch: self._execute_c_ritual(c, cmd))
        else:
            self.logger.warning(f"Pouvoir inconnu: {ch}")

    def _execute_c_ritual(self, choix: str, cmd: str):
        """Executer le Rituel C avec le pouvoir et la commande choisis."""
        if not self.current_target:
            self.logger.warning("Aucun esprit cible charge")
            return

        self._open_r2(self.current_target)
        ritual = RituelC(
            self._log_with_transmutation,
            self.ui.set_progress,
            r2_handler=self.r2_handler
        )
        ritual.set_pouvoir(choix, cmd)
        self.current_ritual = ritual
        self.ui.set_mode("RITUEL C")
        self.ui.c_menu_active = False

        self.ritual_thread = threading.Thread(
            target=self._execute_ritual_thread,
            daemon=True
        )
        self.ritual_thread.start()

    def handle_input(self, ch: str) -> bool:
        """Gerer les entrees clavier."""
        if self.ui.c_menu_active:
            if ch == '\x1b':
                self.ui.c_menu_active = False
                self.logger.info("Retour au menu principal")
            elif ch in ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9'):
                self._handle_c_menu_choice(ch)
            else:
                self.logger.warning(f"Touche inconnue en mode C: {ch}")
            return True

        if ch == 'q' or ch == '\x03':
            self.logger.info("Fermeture du Grimoire demandee...")
            return False
        elif ch == '1':
            self._request_target_path()
        elif ch == '2':
            self._request_offset()
        elif ch == '3':
            # Menu dictionnaire
            self._request_dictionary()
        elif ch == '4':
            self._radical_erase()
        elif ch == '5':
            self._request_manual_keywords()
        elif ch == 'a':
            if self.ritual_thread and self.ritual_thread.is_alive():
                self.logger.warning("Un rituel est deja en cours")
            else:
                self.logger.info("Rituel A : L'Invocation Precise...")
                self._start_ritual('A')
        elif ch == 'b':
            if self.ritual_thread and self.ritual_thread.is_alive():
                self.logger.warning("Un rituel est deja en cours")
            else:
                self.logger.info("Rituel B : Le Balayage d'Ame...")
                self._start_ritual('B')
        elif ch == 'c':
            if self.ritual_thread and self.ritual_thread.is_alive():
                self.logger.warning("Un rituel est deja en cours")
            else:
                self.logger.info("Rituel C : La Connexion Directe")
                self.logger.info("Selectionnez un pouvoir Radare2:")
                self.ui.c_menu_active = True
        elif ch == 'd':
            if self.ritual_thread and self.ritual_thread.is_alive():
                self.logger.warning("Un rituel est deja en cours")
            else:
                self.logger.info("Rituel D : Les Transmutations Blutter...")
                self._start_ritual('D')
        elif ch == 'e':
            if self.ritual_thread and self.ritual_thread.is_alive():
                self.logger.warning("Un rituel est deja en cours")
            else:
                self.logger.info("Rituel E : La Quete des Fonctions...")
                self._start_ritual('E')
        elif ch == 'f':
            if self.ritual_thread and self.ritual_thread.is_alive():
                self.logger.warning("Un rituel est deja en cours")
            else:
                self.logger.info("Rituel F : Le Patcheur de Manifeste...")
                self._start_ritual('F')
        else:
            self.logger.warning(f"Touche inconnue: {ch}")
        return True

    def _cleanup(self):
        """Nettoyage avant la sortie."""
        if self.logger:
            self.logger.info("Fermeture du Grimoire en cours...")

        if self.current_ritual:
            self.current_ritual.stop()

        if self.ritual_thread and self.ritual_thread.is_alive():
            if self.logger:
                self.logger.warning("Interruption du rituel en cours...")
            self.ritual_thread.join(timeout=5)

            if self.ritual_thread.is_alive():
                if self.logger:
                    self.logger.error("Timeout - arret force")

        if self.r2_handler:
            try:
                self.r2_handler.close()
            except Exception:
                pass

        if self.ui:
            self.ui.refresh()
            time.sleep(0.3)

        if self.logger:
            self.logger.success("Grimoire ferme - Au revoir!")

        if self.ui:
            self.ui.refresh()
            time.sleep(0.5)
            self.ui.stop()

    def _main_loop(self):
        """Boucle principale partagee par GrimoireUI et GrimoireANSI."""
        self.display_welcome()
        self._auto_detect_targets()

        if not Radare2Handler.is_available():
            self.logger.warning("Radare2 non trouve - installez: apt install radare2")
        if not Radare2Handler.check_r2pipe():
            self.logger.warning("r2pipe non trouve - installez: pip install r2pipe")

        if self._requested_mode:
            self._start_ritual(self._requested_mode)

        try:
            while self.running and not self.stop_requested:
                self.ui.refresh()

                if self.ui.update_dimensions():
                    self.logger.debug("Terminal redimensionne")

                ch = self.ui.get_input()
                if ch:
                    if not self.handle_input(ch):
                        break

                if self.ritual_thread and not self.ritual_thread.is_alive():
                    self.ritual_thread = None
                    if self.running and not self.stop_requested:
                        self.ui.set_mode("EN VEILLE")

                time.sleep(0.05)

        except KeyboardInterrupt:
            if self.logger:
                self.logger.warning("Interruption clavier detectee")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erreur: {e}")
        finally:
            try:
                self._cleanup()
            except Exception:
                pass

    def run(self, mode: Optional[str] = None):
        """Lancer l'application."""
        self._requested_mode = mode

        if not Radare2Handler.is_available():
            print("[!] Radare2 (r2) non trouve sur le systeme")
            print("    Installez: sudo apt install radare2")
            print("    Termux:    pkg install radare2")
            print()

        if not Radare2Handler.check_r2pipe():
            print("[!] Module r2pipe non trouve")
            print("    Installez: pip install r2pipe")
            print()

        try:
            curses.wrapper(self._curses_main)
        except KeyboardInterrupt:
            print("\n[!] Arrete par l'utilisateur")
        except Exception:
            try:
                self.ui = GrimoireANSI()
                log_file = self._get_log_file_path()
                self.logger = LoggerHandler(callback=self.ui.add_vision, log_file=log_file)
                self.logger.success("Session demarree (fallback ANSI)")
                self._main_loop()
            except KeyboardInterrupt:
                print("\n[!] Arrete par l'utilisateur")
            except Exception as e:
                print(f"\n[!] Erreur: {e}")
                sys.exit(1)

    def _curses_main(self, stdscr):
        """Initialiser GrimoireUI et lancer la boucle principale."""
        self.ui = GrimoireUI(stdscr)
        log_file = self._get_log_file_path()
        self.logger = LoggerHandler(callback=self.ui.add_vision, log_file=log_file)
        self.logger.success("Le Grimoire s'ouvre...")
        self._main_loop()
        return self.ui

    def _get_log_file_path(self) -> str:
        """Generer un chemin de fichier log avec horodatage."""
        Config.init()
        logs_dir = str(Config.get('logs_dir'))
        os.makedirs(logs_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(logs_dir, f"grimoire_{timestamp}.log")


def main():
    """Point d'entree pour la commande shadowprotocol."""
    app = ShadowProtocolApp()

    if len(sys.argv) > 1:
        arg = sys.argv[1]

        if arg in ('--check', '--check-deps'):
            modes = sys.argv[2:] if len(sys.argv) > 2 else []
            from .validator import DependencyValidator
            ok, messages = DependencyValidator.validate_all(modes)
            for msg in messages:
                print(msg)
            if not ok:
                print("\n[!] Dependances manquantes. Installez et reessayez.")
                sys.exit(1)
            else:
                print("\n[+] Toutes les dependances sont satisfaites.")
                sys.exit(0)

        if arg == '--dry-run':
            mode_arg = sys.argv[2].upper() if len(sys.argv) > 2 else None
            if mode_arg and mode_arg in VALID_MODES:
                print(f"[*] DRY RUN RITUEL {mode_arg} - Aucun changement ne sera applique")
                app.run(mode_arg)
            else:
                print("Usage: shadowprotocol --dry-run [A|B|C|D|E|F]")
                sys.exit(1)
            return

        mode = arg.upper()
        if mode in VALID_MODES:
            app.run(mode)
        else:
            print(f"Rituel inconnu: {mode}")
            print("Usage: shadowprotocol [A|B|C|D|E|F]")
            print("       shadowprotocol --check")
            print("       shadowprotocol --dry-run [A|B|C|D|E|F]")
            sys.exit(1)
    else:
        app.run()


if __name__ == "__main__":
    main()
