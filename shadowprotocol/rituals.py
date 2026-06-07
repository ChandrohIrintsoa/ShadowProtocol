"""
ShadowProtocol - Les 6 Rituels (Modes A, B, C, D, E, F)

Rituel A : L'Invocation Precise - Patchage par offset via pptool
Rituel B : Le Balayage d'Ame - Scan automatique et patch global
Rituel C : La Connexion Directe - Canal brut avec Radare2
Rituel D : Le Patcheur Flutter - APK merge, blutter, PP/ASM patching
Rituel E : La Quete des Fonctions - ARM64 pattern search (v2/v3)
Rituel F : Le Patcheur de Manifeste - License check removal, extractNativeLibs
"""

import re
import threading
from abc import ABC, abstractmethod
from typing import Callable, List, Optional, Tuple

from .r2handler import Radare2Handler
from .results_writer import (
    write_offset_results,
    write_patch_results,
    write_function_results,
    write_generic_results,
)


class BaseRitual(ABC):
    """Classe de base pour les rituels de transmutation.

    Fournit une interface commune avec:
    - Signal d'arret thread-safe via threading.Event
    - Execution par etapes avec progression
    - Support d'interruption gracieuse
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 r2_handler: Optional[Radare2Handler] = None):
        self.log = log_callback
        self.progress = progress_callback
        self.r2 = r2_handler
        self._stop_event = threading.Event()

    @abstractmethod
    def execute(self) -> bool:
        """Executer le rituel.

        Returns:
            True si complete avec succes, False si arrete ou echoue.
        """
        pass

    @abstractmethod
    def get_label(self) -> str:
        """Retourner le label court du rituel (A, B, C, D, E, F)."""
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Retourner le nom complet du rituel."""
        pass

    def stop(self):
        """Signaler l'arret du rituel."""
        self._stop_event.set()

    def is_stopping(self) -> bool:
        """Verifier si un arret a ete demande."""
        return self._stop_event.is_set()

    def _run_steps(self, label: str, steps: List[Tuple[str, float]]) -> bool:
        """Executer une liste d'etapes avec progression.

        Chaque etape est un tuple (nom, duree_secondes).
        """
        for i, (step_name, duration) in enumerate(steps):
            if self.is_stopping():
                self.log(f"[!] RITUEL {label}: Arret detecte - nettoyage...")
                return False
            self.log(f"[{label}] {step_name}...")
            import time
            time.sleep(duration)
            self.progress(i + 1, len(steps), f"RITUEL {label}")
        return True


class RituelA(BaseRitual):
    """Rituel A - L'Invocation Precise

    L'operateur fournit un sigil hexadecimal (offset du pptool).
    Le grimoire scrute l'adresse, cherche l'incantation
    'add x?, x?, 0x30', et la reecrit en 0x20 si la rune est valide.
    Verification post-patch obligatoire par relecture du desassemblage.
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 r2_handler: Optional[Radare2Handler] = None,
                 offset: Optional[str] = None):
        super().__init__(log_callback, progress_callback, r2_handler)
        self.offset = offset
        self._result = None

    def get_label(self) -> str:
        return "A"

    def get_name(self) -> str:
        return "L'Invocation Precise"

    def validate_offset(self) -> Tuple[bool, str]:
        """Valider le format et l'existence du pattern a l'offset."""
        if not self.offset or not re.match(r'^0x[0-9a-fA-F]+$', self.offset):
            return (False, "Format d'offset invalide (attendu: 0x...)")

        if not self.r2:
            return (False, "Aucun binaire charge dans Radare2")

        self.log(f"Validation du sigil: {self.offset}")

        if not self.r2.open(write=False):
            return (False, "Erreur d'ouverture Radare2 (lecture)")

        try:
            found, instr, register = self.r2.check_pattern_at(self.offset)
            self.r2.close()

            if found:
                self.log(f"Incantation trouvee a {self.offset}: {instr}")
                return (True, f"Pattern confirme: {instr}")
            else:
                self.log(f"Aucune incantation 0x30 a {self.offset}")
                return (False, f"Pattern add x?,x?,0x30 non trouve a {self.offset}")
        except Exception as e:
            try:
                self.r2.close()
            except Exception:
                pass
            return (False, f"Erreur validation: {e}")

    def patch(self) -> Tuple[bool, str]:
        """Appliquer le patch 0x30 -> 0x20 a l'offset."""
        if not self.r2:
            return (False, "Aucun binaire charge")

        if not self.r2.open(write=True):
            return (False, "Erreur d'ouverture en ecriture")

        try:
            # Re-verifier le pattern avant patch
            found, instr, register = self.r2.check_pattern_at(self.offset)
            if not found:
                self.r2.close()
                return (False, f"Pattern non confirme a {self.offset}")

            # Extraire les registres de l'instruction
            pattern = re.compile(r'add\s+(x\d+),\s*(x\d+),\s*0x30', re.IGNORECASE)
            match = pattern.search(instr)
            if not match:
                self.r2.close()
                return (False, "Impossible d'extraire les registres")

            reg_dest = match.group(1)
            reg_src = match.group(2)

            self.log(f"Transmutation en cours: {instr} -> 0x20")

            # Appliquer le patch
            ok, msg = self.r2.patch_instruction(
                self.offset, reg_dest, reg_src, "0x20"
            )
            self.r2.close()

            if ok:
                self._result = (self.offset, instr, f"add {reg_dest},{reg_src},0x20", True)
                self.log(f"Transmutation reussie: {self.offset} | {instr} -> 0x20")
            else:
                self._result = (self.offset, instr, "", False)
                self.log(f"Echec transmutation: {msg}")

            return (ok, msg)
        except Exception as e:
            try:
                self.r2.close()
            except Exception:
                pass
            return (False, f"Erreur patch: {e}")

    def execute(self) -> bool:
        """Executer le Rituel A - Valider puis patcher."""
        self.log("Rituel A : L'Invocation Precise commence...")
        self._stop_event.clear()

        if not self.r2:
            self.log("Aucun esprit cible selectionne (option [1])")
            return False
        if not self.offset:
            self.log("Aucun sigil hex fourni (option [2])")
            return False

        # Phase 1: Validation du sigil
        self.log("Phase 1 : Validation du sigil hex...")
        self.progress(1, 2, "Rituel A")

        if self.is_stopping():
            self.log("Rituel A: Arrete avant validation")
            return False

        valid, msg = self.validate_offset()

        # Persister le resultat de validation
        offset_data = [{"offset": self.offset, "validated": valid, "pattern": "0x30"}]
        result_file = write_offset_results(offset_data, self.get_label(),
                                           extra_metadata={"binary": self.r2.binary_path if self.r2 else ""})
        self.log(f"[A] Resultats offset sauvegardes: {result_file}")

        if not valid:
            self.log(f"Validation echouee: {msg}")
            return False

        # Phase 2: Transmutation
        self.log("Phase 2 : Transmutation de l'incantation...")
        self.progress(2, 2, "Rituel A")

        if self.is_stopping():
            self.log("Rituel A: Arrete avant transmutation")
            return False

        ok, msg = self.patch()

        # Persister le resultat du patch
        patch_data = {self.offset: {"patched": ok, "instruction": "0x30->0x20"}}
        result_file = write_patch_results(patch_data, self.get_label(),
                                          extra_metadata={"binary": self.r2.binary_path if self.r2 else ""})
        self.log(f"[A] Resultats patch sauvegardes: {result_file}")

        if ok:
            self.log("Rituel A: Invocation terminee avec succes")
        else:
            self.log(f"Rituel A: Echec de la transmutation - {msg}")

        return ok


class RituelB(BaseRitual):
    """Rituel B - Le Balayage d'Ame

    Le grimoire sonde l'integralite de l'esprit de pierre,
    decouvre TOUTES les incantations 0x30 qui s'y cachent,
    et les transmute collectivement en 0x20.
    Bilan final des ames touchees.
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 r2_handler: Optional[Radare2Handler] = None):
        super().__init__(log_callback, progress_callback, r2_handler)
        self.targets: List[Tuple[str, str, str, str]] = []
        self._results = None

    def get_label(self) -> str:
        return "B"

    def get_name(self) -> str:
        return "Le Balayage d'Ame"

    def scan(self) -> List[Tuple[str, str, str, str]]:
        """Scanner l'integralite du binaire pour le pattern."""
        if not self.r2:
            self.log("Aucun esprit cible charge")
            return []

        self.log("Sonde l'integralite de l'esprit de pierre...")
        self.targets = self.r2.scan_all_pattern(
            log_callback=self.log,
            stop_event=self._stop_event
        )
        return self.targets

    def patch_all(self) -> Tuple[int, int, list]:
        """Transmuter collectivement toutes les cibles."""
        if not self.targets:
            self.log("Aucune ame a transmuter")
            return (0, 0, [])

        if not self.r2:
            self.log("Aucun esprit cible charge")
            return (0, len(self.targets), [])

        self.log(f"Transmutation collective de {len(self.targets)} ames...")
        patched, failed, details = self.r2.batch_patch(
            self.targets,
            new_val="0x20",
            log_callback=self.log,
            progress_callback=self.progress,
            stop_event=self._stop_event
        )
        self._results = details
        return (patched, failed, details)

    def execute(self) -> bool:
        """Executer le Rituel B - Scan puis transmutation globale."""
        self.log("Rituel B : Le Balayage d'Ame commence...")
        self._stop_event.clear()

        if not self.r2:
            self.log("Aucun esprit cible selectionne (option [1])")
            return False

        # Phase 1: Balayage
        self.log("Phase 1 : Balayage de l'esprit de pierre...")
        self.progress(1, 2, "Rituel B")

        if self.is_stopping():
            self.log("Rituel B: Arrete avant le balayage")
            return False

        targets = self.scan()

        # Persister les resultats du scan
        scan_data = [{"address": t[0], "instruction": t[1]} for t in targets]
        result_file = write_offset_results(scan_data, self.get_label(),
                                           extra_metadata={"total_targets": len(targets)})
        self.log(f"[B] Resultats scan sauvegardes: {result_file}")

        if not targets:
            self.log("Aucune incantation 0x30 detectee - rien a transmuter")
            return True

        self.log(f"{len(targets)} incantations detectees")

        # Phase 2: Transmutation collective
        self.log(f"Phase 2 : Transmutation de {len(targets)} ames...")
        self.progress(2, 2, "Rituel B")

        if self.is_stopping():
            self.log("Rituel B: Arrete avant la transmutation")
            return False

        patched, failed, details = self.patch_all()

        # Persister les resultats des patches
        patch_data = {t[0]: {"patched": True, "instruction": t[1]} for t in targets}
        result_file = write_patch_results(patch_data, self.get_label(),
                                          extra_metadata={"patched_count": patched,
                                                          "total_targets": len(targets)})
        self.log(f"[B] Resultats patch sauvegardes: {result_file}")

        self.log(f"Bilan des ames: {patched} transmutees / {failed} echecs / {len(targets)} cibles")

        return patched > 0


class RituelC(BaseRitual):
    """Rituel C - La Connexion Directe

    Aucun intermediaire. Le grimoire ouvre un canal brut
    avec Radare2. Un menu arcanique liste les pouvoirs r2.
    L'operateur choisit un pouvoir, le grimoire l'invoque.

    Pouvoirs disponibles:
    1. Scruter (Seek & Write) - s + wa
    2. Analyser (aaa) - Analyse complete
    3. Desassembler (pd) - Desassemblage
    4. Voir l'Hex (px) - Hexdump
    5. Sections (iS) - Sections du binaire
    6. Cordes (iz) - Chaines de caracteres
    7. Croisements (axt) - Cross-references
    8. Ecrire assembleur (wa) - Write assembly
    9. Patch hex (wx) - Patch hexadecimal
    0. Quitter & Sauvegarder
    """

    POUVOIRS = [
        ("1", "Scruter & Ecrire", "s {addr} ; wa {asm}"),
        ("2", "Analyser (aaa)", "aaa"),
        ("3", "Desassembler (pd)", "pd {n} @{addr}"),
        ("4", "Voir l'Hex (px)", "px {n} @{addr}"),
        ("5", "Sections (iS)", "iS"),
        ("6", "Cordes (iz)", "iz"),
        ("7", "Croisements (axt)", "axt {addr}"),
        ("8", "Ecrire assembleur (wa)", "wa {asm}"),
        ("9", "Patch hex (wx)", "wx {hex} @{addr}"),
        ("0", "Quitter & Sauvegarder", "q"),
    ]

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 r2_handler: Optional[Radare2Handler] = None):
        super().__init__(log_callback, progress_callback, r2_handler)
        self._selected_pouvoir: Optional[str] = None
        self._custom_cmd: Optional[str] = None
        self._output: str = ""

    def get_label(self) -> str:
        return "C"

    def get_name(self) -> str:
        return "La Connexion Directe"

    def set_pouvoir(self, choix: str, custom_cmd: str = ""):
        """Definir le pouvoir selectionne et ses parametres."""
        self._selected_pouvoir = choix
        self._custom_cmd = custom_cmd

    def execute(self) -> bool:
        """Executer le Rituel C - Canal brut Radare2."""
        self.log("Rituel C : La Connexion Directe s'ouvre...")
        self._stop_event.clear()

        if not self.r2:
            self.log("Aucun esprit cible charge")
            return False

        if self._selected_pouvoir == "0":
            self.log("Sauvegarde et fermeture du canal r2")
            return True

        if not self.r2.open(write=True):
            self.log("Erreur d'ouverture du canal Radare2")
            return False

        try:
            cmd = self._custom_cmd if self._custom_cmd else ""
            choix = self._selected_pouvoir

            if choix == "1":
                self.log("Pouvoir: Scruter & Ecrire")
            elif choix == "2":
                cmd = cmd or "aaa"
                self.log("Pouvoir: Analyse complete (aaa)")
            elif choix == "3":
                self.log("Pouvoir: Desassemblage (pd)")
            elif choix == "4":
                self.log("Pouvoir: Hexdump (px)")
            elif choix == "5":
                cmd = cmd or "iS"
                self.log("Pouvoir: Sections (iS)")
            elif choix == "6":
                cmd = cmd or "iz"
                self.log("Pouvoir: Cordes (iz)")
            elif choix == "7":
                self.log("Pouvoir: Cross-references (axt)")
            elif choix == "8":
                self.log("Pouvoir: Ecrire assembleur (wa)")
            elif choix == "9":
                self.log("Pouvoir: Patch hex (wx)")
            else:
                self.log(f"Pouvoir inconnu: {choix}")
                self.r2.close()
                return False

            if not cmd:
                self.r2.close()
                self.log("Aucune commande a executer")
                return True

            self.log(f"Invocation: {cmd}")
            ok, output, err = self.r2.execute(cmd)

            if ok:
                self._output = output
                for line in output.split('\n')[:50]:
                    if line.strip():
                        self.log(f"  {line}")
                self.log("Invocation terminee")
            else:
                self.log(f"Erreur d'invocation: {err}")

            # Persister les resultats
            result_file = write_generic_results(
                output if ok else f"Erreur: {err}",
                "raw_r2_session",
                extra_metadata={"command": cmd, "success": ok})
            self.log(f"[C] Resultats sauvegardes: {result_file}")

            self.r2.close()
            return ok

        except Exception as e:
            self.log(f"Erreur Rituel C: {e}")
            try:
                self.r2.close()
            except Exception:
                pass
            return False


class RituelD(BaseRitual):
    """Rituel D - Le Patcheur Flutter

    Integre la fonctionnalite de patchage Flutter:
    - Fusion APK (split APKs)
    - Extraction ARM64 depuis l'APK
    - Analyse Blutter
    - Patchage PP (0x20 <-> 0x30)
    - Recherche ASM avec regex
    - Remplacement dans l'APK
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 r2_handler: Optional[Radare2Handler] = None,
                 binary_path: str = None):
        super().__init__(log_callback, progress_callback, r2_handler)
        self.binary = binary_path

    def get_label(self) -> str:
        return "D"

    def get_name(self) -> str:
        return "Le Patcheur Flutter"

    def execute(self) -> bool:
        """Executer le Rituel D - Patcheur Flutter."""
        self.log("Rituel D : Le Patcheur Flutter s'ouvre...")
        self._stop_event.clear()

        if not self.binary:
            self.log("Aucun chemin APK fourni (option [1] avec chemin APK)")
            return False

        try:
            from .flutter.patcher import FlutterPatcher

            self.log("[D] Demarrage du patchage Flutter combine...")
            self.progress(1, 2, "Rituel D")

            if self.is_stopping():
                self.log("Rituel D: Arrete avant le patchage")
                return False

            patcher = FlutterPatcher(
                enable_pp_patch=True,
                enable_asm_patch=True,
                enable_true_patch=False,
                enable_false_patch=True,
            )
            result_path = patcher.process_combined(self.binary)

            self.progress(2, 2, "Rituel D")

            # Persister le resume
            result_file = write_generic_results(
                f"Patchage Flutter termine\nAPK: {result_path}",
                "flutter_patcher",
                extra_metadata={"apk_path": self.binary, "result_path": result_path})
            self.log(f"[D] Resultats sauvegardes: {result_file}")

            self.log("Rituel D: Patchage Flutter termine")
            return True

        except Exception as e:
            self.log(f"Rituel D: Erreur patchage Flutter: {e}")
            result_file = write_generic_results(
                f"Erreur patchage Flutter: {e}",
                "flutter_patcher_error",
                extra_metadata={"apk_path": self.binary, "error": str(e)})
            self.log(f"[D] Erreur journalisee: {result_file}")
            return False


class RituelE(BaseRitual):
    """Rituel E - La Quete des Fonctions

    Utilise r2pipe pour trouver les fonctions avec des patterns ARM64 specifiques:
    - v2: stp x29, x30, [x15, -0x10]! + add x0, x22, 0x30 (registre x0 specifique)
    - v3: stp x29, x30, [x15, -0x10]! + add x<d+>, x<d+>, 0x30 (n'importe quel registre)
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 r2_handler: Optional[Radare2Handler] = None,
                 binary_path: str = None):
        super().__init__(log_callback, progress_callback, r2_handler)
        self.binary = binary_path

    def get_label(self) -> str:
        return "E"

    def get_name(self) -> str:
        return "La Quete des Fonctions"

    def execute(self) -> bool:
        """Executer le Rituel E - Quete des Fonctions."""
        self.log("Rituel E : La Quete des Fonctions commence...")
        self._stop_event.clear()

        binary_path = self.binary or (self.r2.binary_path if self.r2 else None)
        if not binary_path:
            self.log("Aucun esprit cible selectionne (option [1])")
            return False

        try:
            from .flutter.find_functions import FunctionFinder

            self.log("[E] Recherche des patterns v2 (add x0, x22, 0x30)...")
            self.progress(1, 2, "Rituel E")

            if self.is_stopping():
                self.log("Rituel E: Arrete avant la recherche v2")
                return False

            finder = FunctionFinder(binary_path)

            v2_results = finder.find_v2()
            self.log(f"[+] v2: {len(v2_results)} fonctions trouvees")

            # Persister les resultats v2
            result_file = write_function_results(
                v2_results, "v2",
                extra_metadata={"binary": binary_path, "pattern": "add x0, x22, 0x30"})
            self.log(f"[E] Resultats v2 sauvegardes: {result_file}")

            self.progress(2, 2, "Rituel E")

            if self.is_stopping():
                self.log("Rituel E: Arrete avant la recherche v3")
                return True  # v2 deja complete

            self.log("[E] Recherche des patterns v3 (add x<d+>, x<d+>, 0x30)...")
            v3_results = finder.find_v3()
            self.log(f"[+] v3: {len(v3_results)} fonctions trouvees")

            # Persister les resultats v3
            result_file = write_function_results(
                v3_results, "v3",
                extra_metadata={"binary": binary_path, "pattern": "add x<d+>, x<d+>, 0x30"})
            self.log(f"[E] Resultats v3 sauvegardes: {result_file}")

            self.log(f"Rituel E: Quete terminee (v2: {len(v2_results)}, v3: {len(v3_results)})")
            return True

        except Exception as e:
            self.log(f"Rituel E: Erreur recherche fonctions: {e}")
            return False


class RituelF(BaseRitual):
    """Rituel F - Le Patcheur de Manifeste

    Patchage du manifeste APK:
    - Decompilation APK avec APKEditor
    - Suppression des recepteurs de verification de licence
    - Correction de l'attribut extractNativeLibs
    - Reconstruction de l'APK
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 r2_handler: Optional[Radare2Handler] = None,
                 binary_path: str = None):
        super().__init__(log_callback, progress_callback, r2_handler)
        self.binary = binary_path

    def get_label(self) -> str:
        return "F"

    def get_name(self) -> str:
        return "Le Patcheur de Manifeste"

    def execute(self) -> bool:
        """Executer le Rituel F - Patcheur de Manifeste."""
        self.log("Rituel F : Le Patcheur de Manifeste s'ouvre...")
        self._stop_event.clear()

        if not self.binary:
            self.log("Aucun chemin APK fourni (option [1] avec chemin APK)")
            return False

        try:
            from .flutter.manifest import process_manifest_patcher
            from .apk.editor import ensure_apkeditor

            self.log("[F] Localisation du JAR APKEditor...")
            self.progress(1, 2, "Rituel F")

            jar_file = ensure_apkeditor()
            if not jar_file:
                self.log("Rituel F: JAR APKEditor non disponible")
                return False

            if self.is_stopping():
                self.log("Rituel F: Arrete avant le patchage")
                return False

            self.log("[F] Patchage du AndroidManifest.xml...")
            self.progress(2, 2, "Rituel F")

            success = process_manifest_patcher(self.binary, jar_file)

            # Persister les resultats
            result_file = write_generic_results(
                f"Patchage manifeste {'reussi' if success else 'echoue'}\nAPK: {self.binary}",
                "manifest_patcher",
                extra_metadata={"apk_path": self.binary, "success": success})
            self.log(f"[F] Resultats sauvegardes: {result_file}")

            if success:
                self.log("Rituel F: Patchage manifeste termine")
            else:
                self.log("Rituel F: Patchage manifeste echoue")

            return success

        except Exception as e:
            self.log(f"Rituel F: Erreur patchage manifeste: {e}")
            return False


def get_ritual(mode_name: str, log_cb: Callable, progress_cb: Callable,
               r2_handler: Optional[Radare2Handler] = None,
               offset: Optional[str] = None,
               binary_path: Optional[str] = None) -> BaseRitual:
    """Fabrique: creer une instance de rituel par nom.

    Args:
        mode_name: 'A', 'B', 'C', 'D', 'E', ou 'F'
        log_cb: Callback de journalisation
        progress_cb: Callback de progression
        r2_handler: Handler Radare2 (optionnel)
        offset: Offset pour Rituel A
        binary_path: Chemin binaire pour Rituels D/E/F

    Returns:
        Instance du rituel correspondant

    Raises:
        ValueError: Si mode_name n'est pas A-F
    """
    mode_name = mode_name.upper()
    if mode_name == 'A':
        return RituelA(log_cb, progress_cb, r2_handler, offset)
    elif mode_name == 'B':
        return RituelB(log_cb, progress_cb, r2_handler)
    elif mode_name == 'C':
        return RituelC(log_cb, progress_cb, r2_handler)
    elif mode_name == 'D':
        return RituelD(log_cb, progress_cb, r2_handler, binary_path)
    elif mode_name == 'E':
        return RituelE(log_cb, progress_cb, r2_handler, binary_path)
    elif mode_name == 'F':
        return RituelF(log_cb, progress_cb, r2_handler, binary_path)
    else:
        raise ValueError(f"Rituel inconnu: {mode_name}")
