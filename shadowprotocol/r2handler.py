"""
ShadowProtocol - Handler Radare2 (r2pipe)

Encapsulation de r2pipe pour la manipulation binaire :
ouverture, execution de commandes, validation, patch, scan, batch_patch.
Fallback subprocess si r2pipe indisponible.
"""

import re
import shutil
from typing import Tuple, List

try:
    import r2pipe
    HAS_R2PIPE = True
except ImportError:
    HAS_R2PIPE = False


class Radare2Handler:
    """Manipulation binaire via Radare2.

    Utilise r2pipe pour l'integration API, avec fallback
    subprocess si r2pipe est indisponible.
    """

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.pipe = None
        self._use_r2pipe = HAS_R2PIPE

    @staticmethod
    def is_available() -> bool:
        """Verifier si Radare2 est installe sur le systeme."""
        return shutil.which("r2") is not None

    @staticmethod
    def check_r2pipe() -> bool:
        """Verifier si le module r2pipe est disponible."""
        return HAS_R2PIPE

    def open(self, write: bool = False) -> bool:
        """Ouvrir le binaire dans Radare2.

        Args:
            write: Ouvrir en mode ecriture.

        Returns:
            True si ouvert avec succes.
        """
        if not self._use_r2pipe:
            return False
        try:
            flags = ["-w", "-2"] if write else ["-2"]
            self.pipe = r2pipe.open(self.binary_path, flags=flags)
            return True
        except Exception:
            self.pipe = None
            return False

    def execute(self, cmd: str) -> Tuple[bool, str, str]:
        """Executer une commande r2.

        Args:
            cmd: La commande r2 a executer.

        Returns:
            (succes, sortie, erreur)
        """
        if not self.pipe:
            return (False, "", "r2pipe non initialise")
        try:
            result = self.pipe.cmd(cmd)
            if result is None:
                return (False, "", "r2 a retourne None")
            return (True, result or "", "")
        except Exception as e:
            return (False, "", f"erreur r2: {str(e)}")

    def validate_binary(self) -> Tuple[bool, str]:
        """Valider que le binaire est bien charge dans r2."""
        if not self.pipe:
            return (False, "r2pipe non initialise")
        try:
            result = self.pipe.cmd("i")
            if result and "arch" in result:
                return (True, result.split('\n')[0])
        except Exception as e:
            return (False, str(e))
        return (False, "Impossible d'analyser le binaire")

    def seek(self, offset: str) -> Tuple[bool, str]:
        """Se positionner a un offset donne."""
        ok, out, err = self.execute(f"s {offset}")
        if not ok:
            return (False, f"Erreur seek: {err}")
        return (True, f"Positionne a {offset}")

    def disasm_at(self, offset: str, count: int = 5) -> Tuple[bool, str]:
        """Desassembler a un offset donne."""
        self.execute(f"s {offset}")
        ok, disasm, err = self.execute(f"pd {count}")
        if not ok:
            return (False, f"Erreur desassemblage: {err}")
        return (True, disasm)

    def check_pattern_at(self, offset: str) -> Tuple[bool, str, str]:
        """Verifier la presence du pattern add x?, x?, 0x30 a un offset.

        Returns:
            (pattern_trouve, instruction_complete, registre_detecte)
        """
        ok, disasm = self.disasm_at(offset, 5)
        if not ok:
            return (False, "", "")

        pattern = re.compile(
            r'add\s+(x\d+),\s*(x\d+),\s*0x30', re.IGNORECASE
        )

        for line in disasm.split('\n'):
            match = pattern.search(line)
            if match:
                addr_match = re.search(r'(0x[0-9a-fA-F]+)', line)
                addr = addr_match.group(1) if addr_match else offset
                full_instr = f"add {match.group(1)},{match.group(2)},0x30"
                return (True, full_instr, match.group(1))

        return (False, "", "")

    def patch_instruction(self, offset: str, register: str,
                          src_reg: str, new_val: str) -> Tuple[bool, str]:
        """Patcher une instruction a un offset.

        Args:
            offset: Adresse de l'instruction.
            register: Registre destination (ex: x0).
            src_reg: Registre source (ex: x22).
            new_val: Nouvelle valeur immediate (ex: 0x20).

        Returns:
            (succes, message)
        """
        patch_cmd = f"wa add {register}, {src_reg}, {new_val}"
        self.execute(f"s {offset}")
        ok, _, err = self.execute(patch_cmd)
        if not ok:
            return (False, f"Erreur patch: {err}")

        # Verification post-patch
        ok2, verify, _ = self.disasm_at(offset, 1)
        if ok2 and new_val in verify:
            return (True, f"Patch verifie: add {register},{src_reg},{new_val}")
        elif ok2:
            return (False, "Patch applique mais verification echouee")
        return (False, "Impossible de verifier le patch")

    def scan_all_pattern(self, log_callback=None,
                         stop_event=None) -> List[tuple]:
        """Scanner l'integralite du binaire pour le pattern add x?,x?,0x30.

        Args:
            log_callback: Fonction de journalisation.
            stop_event: Evenement d'arret pour annulation.

        Returns:
            Liste de tuples (offset, instruction, registre_dest, registre_src)
        """
        targets = []

        if not self.open(write=False):
            return targets

        try:
            if log_callback:
                log_callback("Analyse complete du binaire en cours...")

            ok, _, _ = self.execute("aaa")
            if not ok:
                if log_callback:
                    log_callback("Analyse aaa echouee, tentative e aF...")
                self.execute("e aF")

            ok, func_list, err = self.execute("afl")
            if not ok or not func_list.strip():
                if log_callback:
                    log_callback(f"Liste fonctions indisponible: {err}")
                ok2, search_out, _ = self.execute("/ add x0, x22, 0x30")
                if ok2 and search_out.strip():
                    for line in search_out.split('\n'):
                        addr_match = re.search(r'(0x[0-9a-fA-F]+)', line)
                        if addr_match:
                            targets.append((
                                addr_match.group(1),
                                "add x0,x22,0x30",
                                "x0", "x22"
                            ))
                self.close()
                return targets

            func_addrs = []
            for line in func_list.split('\n'):
                parts = line.split()
                if len(parts) >= 3:
                    addr = parts[0]
                    if addr.startswith("0x"):
                        func_addrs.append(addr)

            if log_callback:
                log_callback(f"{len(func_addrs)} fonctions detectees, scan en cours...")

            pattern = re.compile(
                r'add\s+(x\d+),\s*(x\d+),\s*0x30', re.IGNORECASE
            )

            for i, func_addr in enumerate(func_addrs):
                if stop_event and stop_event.is_set():
                    break

                self.execute(f"s {func_addr}")
                ok, disasm, _ = self.execute("pdr")
                if not ok or not disasm:
                    continue

                for line in disasm.split('\n'):
                    match = pattern.search(line)
                    if match:
                        addr_match = re.search(r'(0x[0-9a-fA-F]+)', line)
                        if addr_match:
                            targets.append((
                                addr_match.group(1),
                                f"add {match.group(1)},{match.group(2)},0x30",
                                match.group(1),
                                match.group(2)
                            ))

                if log_callback and i % 50 == 0 and i > 0:
                    log_callback(f"Scan: {i}/{len(func_addrs)} fonctions, {len(targets)} cibles")

            self.close()
            if log_callback:
                log_callback(f"Scan termine: {len(targets)} cibles detectees")

        except Exception as e:
            if log_callback:
                log_callback(f"Erreur scan: {e}")
            try:
                self.close()
            except Exception:
                pass

        return targets

    def batch_patch(self, targets: list, new_val: str = "0x20",
                    log_callback=None, progress_callback=None,
                    stop_event=None) -> Tuple[int, int, list]:
        """Patcher en lot toutes les cibles detectees.

        Args:
            targets: Liste de (offset, instr, reg_dest, reg_src)
            new_val: Nouvelle valeur immediate.
            log_callback: Fonction de journalisation.
            progress_callback: Fonction (current, total, label).
            stop_event: Evenement d'arret.

        Returns:
            (nb_patche, nb_echec, details)
        """
        if not targets:
            return (0, 0, [])

        if not self.open(write=True):
            if log_callback:
                log_callback("Impossible d'ouvrir le binaire en ecriture")
            return (0, len(targets), [])

        patched = 0
        failed = 0
        details = []

        try:
            for i, (offset, instr, reg_dest, reg_src) in enumerate(targets, 1):
                if stop_event and stop_event.is_set():
                    break

                self.execute(f"s {offset}")
                patch_cmd = f"wa add {reg_dest}, {reg_src}, {new_val}"
                ok, _, err = self.execute(patch_cmd)

                # Verification post-patch
                self.execute(f"s {offset}")
                _, verify, _ = self.execute("pd 1")
                verified = new_val in verify

                if ok and verified:
                    patched += 1
                    details.append((offset, instr, f"add {reg_dest},{reg_src},{new_val}", True))
                    if log_callback:
                        log_callback(f"0x{offset} | {instr} -> {new_val} OK")
                else:
                    failed += 1
                    details.append((offset, instr, "", False))
                    if log_callback:
                        log_callback(f"0x{offset} | ECHEC patch")

                if progress_callback:
                    progress_callback(i, len(targets), "Transmutation")

                if log_callback and i % 10 == 0:
                    log_callback(f"{patched}/{len(targets)} ames transmutees")

        except Exception as e:
            if log_callback:
                log_callback(f"Erreur batch patch: {e}")
        finally:
            self.close()

        return (patched, failed, details)

    def close(self):
        """Fermer la session r2."""
        if self.pipe:
            try:
                self.pipe.quit()
            except Exception:
                pass
            finally:
                self.pipe = None
