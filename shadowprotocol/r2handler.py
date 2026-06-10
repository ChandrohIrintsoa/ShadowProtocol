"""
ShadowProtocol - Handler Radare2 (r2pipe)

Encapsulation de r2pipe pour la manipulation binaire :
ouverture, execution de commandes, validation, patch, scan, batch_patch.
Fallback subprocess si r2pipe indisponible.
"""

import re
import shutil
from typing import Tuple, List, Optional

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

    # Pattern flexible pour add x?, x?, 0x30 (tous registres ARM64)
    _ADD_0X30_PATTERN = re.compile(
        r'(0x[0-9a-fA-F]+)\s+.*?\badd\s+((?:x|w)\d+|sp|lr),\s*((?:x|w)\d+|sp|lr),\s*#?0x30',
        re.IGNORECASE
    )

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.pipe = None
        self._use_r2pipe = HAS_R2PIPE
        # Cache du dernier offset reel trouve par check_pattern_at
        self._last_found_offset: Optional[str] = None

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

    # ------------------------------------------------------------------
    # Recherche intelligente de pattern (fonction-aware)
    # ------------------------------------------------------------------

    def _find_containing_function(self, offset_int: int) -> Optional[str]:
        """Trouver la fonction qui contient l'offset via afi.

        Utilise 'afi @ offset' de radare2 pour identifier la fonction
        englobante. Retourne l'adresse de la fonction ou None.
        """
        if not self.pipe:
            return None
        try:
            self.execute(f"s {hex(offset_int)}")
            ok, info, _ = self.execute("afi")
            if ok and info.strip():
                for line in info.split('\n'):
                    low = line.lower().strip()
                    if low.startswith('offset:') or low.startswith('addr:'):
                        parts = line.split()
                        for p in parts:
                            if p.startswith('0x'):
                                try:
                                    int(p, 16)
                                    return p
                                except ValueError:
                                    continue
                # Fallback: chercher n'importe quel 0x dans la sortie
                addr_match = re.search(r'(0x[0-9a-fA-F]+)', info)
                if addr_match:
                    return addr_match.group(1)
        except Exception:
            pass
        return None

    def _disasm_function_at(self, func_addr: str) -> Optional[str]:
        """Desassembler toute la fonction a l'adresse donnee (pdr)."""
        if not self.pipe:
            return None
        try:
            self.execute(f"s {func_addr}")
            ok, disasm, _ = self.execute("pdr")
            if ok and disasm.strip():
                return disasm
            # Fallback: pd 200 si pdr echoue
            self.execute(f"s {func_addr}")
            ok, disasm, _ = self.execute("pd 200")
            if ok and disasm.strip():
                return disasm
        except Exception:
            pass
        return None

    def _search_pattern_in_disasm(self, disasm: str, search_start: int = 0,
                                   search_end: int = 0x7FFFFFFFFFFFFFFF,
                                   preferred_offset: int = 0) -> Tuple[bool, str, str, str]:
        """Chercher le pattern add x?, x?, 0x30 dans un disassemblage.

        Retourne (trouve, instruction_complete, registre_dest, offset_reel).
        Garde le match le plus proche de preferred_offset.
        """
        closest_match = None
        closest_distance = float('inf')
        closest_offset = ""

        for line in disasm.split('\n'):
            match = self._ADD_0X30_PATTERN.search(line)
            if match:
                try:
                    found_addr = match.group(1)
                    found_int = int(found_addr, 16)

                    if search_start <= found_int <= search_end:
                        distance = abs(found_int - preferred_offset)
                        if distance < closest_distance:
                            closest_distance = distance
                            closest_offset = found_addr
                            closest_match = (
                                True,
                                f"add {match.group(2)},{match.group(3)},0x30",
                                match.group(2)
                            )
                except (ValueError, IndexError):
                    continue

        if closest_match:
            return (closest_match[0], closest_match[1], closest_match[2], closest_offset)
        return (False, "", "", "")

    def check_pattern_at(self, offset: str) -> Tuple[bool, str, str]:
        """Verifier la presence du pattern add x?, x?, 0x30 a un offset.

        Recherche INTELLIGENTE & FONCTION-AWARE (multi-niveaux):

        1. NIVEAU FONCTION: Trouve la fonction contenant l'offset via afi,
           desassemble TOUTE la fonction (pdr), cherche le pattern dedans.
           C'est la methode la plus robuste car pptool donne l'offset dans
           la fonction, pas l'instruction exacte.

        2. NIVEAU PROXIMITE LARGE: pd 100 @ offset (±200 instructions)
           Couvre une zone plus large autour de l'offset.

        3. NIVEAU ETENDU: pd 250 @ offset-0x100 (±~500 instructions)
           Dernier recours pour les cas ou l'offset est loin du pattern.

        A chaque niveau, on garde le match le plus proche de l'offset fourni.
        L'offset reel du pattern trouve est mis en cache dans
        self._last_found_offset pour reutilisation par patch().

        Returns:
            (pattern_trouve, instruction_complete, registre_detecte)
        """
        if not self.pipe:
            return (False, "", "")

        self._last_found_offset = None

        try:
            offset_int = int(offset, 16) if isinstance(offset, str) else offset
        except (ValueError, TypeError):
            return (False, "", "")

        # ---- NIVEAU 1: Recherche dans la fonction contenant l'offset ----
        func_addr = self._find_containing_function(offset_int)
        if func_addr:
            disasm = self._disasm_function_at(func_addr)
            if disasm:
                found, instr, reg, real_off = self._search_pattern_in_disasm(
                    disasm, preferred_offset=offset_int
                )
                if found:
                    self._last_found_offset = real_off
                    return (found, instr, reg)

        # ---- NIVEAU 2: Proximite large - pd 100 @ offset ----
        ok, disasm = self.disasm_at(offset, 100)
        if ok and disasm:
            search_start = max(0, offset_int - 0x200)
            search_end = offset_int + 0x200
            found, instr, reg, real_off = self._search_pattern_in_disasm(
                disasm, search_start, search_end, offset_int
            )
            if found:
                self._last_found_offset = real_off
                return (found, instr, reg)

        # ---- NIVEAU 3: Etendu - pd 250 autour de l'offset ----
        extended_start = max(0, offset_int - 0x400)
        ok, disasm = self.disasm_at(hex(extended_start), 250)
        if ok and disasm:
            search_start = max(0, offset_int - 0x800)
            search_end = offset_int + 0x800
            found, instr, reg, real_off = self._search_pattern_in_disasm(
                disasm, search_start, search_end, offset_int
            )
            if found:
                self._last_found_offset = real_off
                return (found, instr, reg)

        # ---- NIVEAU 4: Tres etendu - pd 500 encore plus large ----
        wide_start = max(0, offset_int - 0x1000)
        ok, disasm = self.disasm_at(hex(wide_start), 500)
        if ok and disasm:
            search_start = max(0, offset_int - 0x2000)
            search_end = offset_int + 0x2000
            found, instr, reg, real_off = self._search_pattern_in_disasm(
                disasm, search_start, search_end, offset_int
            )
            if found:
                self._last_found_offset = real_off
                return (found, instr, reg)

        return (False, "", "")

    def get_last_found_offset(self) -> Optional[str]:
        """Retourner l'offset reel du dernier pattern trouve par check_pattern_at."""
        return self._last_found_offset

    # ------------------------------------------------------------------
    # Patch
    # ------------------------------------------------------------------

    def patch_instruction(self, offset: str, register: str,
                          src_reg: str, new_val: str) -> Tuple[bool, str]:
        """Patcher une instruction a un offset.

        Args:
            offset: Adresse de l'instruction (peut etre l'offset pptool ou reel).
            register: Registre destination (ex: x0).
            src_reg: Registre source (ex: x22).
            new_val: Nouvelle valeur immediate (ex: 0x20).

        Returns:
            (succes, message)
        """
        try:
            # Utiliser l'offset reel trouve par check_pattern_at si disponible
            actual_offset = self._last_found_offset or offset

            # Verifier le pattern a l'offset reel
            offset_int = int(actual_offset, 16) if isinstance(actual_offset, str) else actual_offset
            ok, disasm = self.disasm_at(hex(max(0, offset_int - 32)), 20)

            if ok:
                pattern = re.compile(
                    r'add\s+' + re.escape(register) + r',\s*' + re.escape(src_reg) + r',\s*#?0x30',
                    re.IGNORECASE
                )
                found = False
                patch_offset = actual_offset

                for line in disasm.split('\n'):
                    if pattern.search(line):
                        addr_match = re.search(r'(0x[0-9a-fA-F]+)', line)
                        if addr_match:
                            patch_offset = addr_match.group(1)
                            found = True
                            break

                if not found:
                    # Derniere chance: recherche elargie avec check_pattern_at
                    self._last_found_offset = None
                    found2, instr2, reg2 = self.check_pattern_at(actual_offset)
                    if found2 and self._last_found_offset:
                        patch_offset = self._last_found_offset
                        # Re-extraire les registres depuis l'instruction trouvee
                        reg_match = re.match(r'add\s+(\w+),\s*(\w+),', instr2, re.IGNORECASE)
                        if reg_match:
                            register = reg_match.group(1)
                            src_reg = reg_match.group(2)
                        found = True

                if not found:
                    return (False, "Pattern add x?,x?,0x30 non trouve a proximite")

                # Appliquer le patch
                self.execute(f"s {patch_offset}")
                patch_cmd = f"wa add {register}, {src_reg}, {new_val}"
                ok, output, err = self.execute(patch_cmd)

                if not ok or err:
                    return (False, f"Erreur patch Radare2: {err[:100] if err else output[:100]}")

                # Verification post-patch
                ok2, verify, _ = self.disasm_at(patch_offset, 2)
                if ok2:
                    if new_val in verify and "add" in verify:
                        return (True, f"Patch applique et verifie: {patch_offset}")
                    # Double-check: le registre est-il present?
                    if register in verify:
                        return (True, f"Patch applique: {patch_offset}")
                    return (False, "Instruction non patched correctement")

                return (False, "Impossible de verifier le patch")

            return (False, "Impossible d'acceder a l'instruction")

        except ValueError as e:
            return (False, f"Format d'offset invalide: {e}")
        except Exception as e:
            return (False, f"Erreur patch: {str(e)[:100]}")

    # ------------------------------------------------------------------
    # Scan global
    # ------------------------------------------------------------------

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
                r'add\s+(x\d+),\s*(x\d+),\s*#?0x30', re.IGNORECASE
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
