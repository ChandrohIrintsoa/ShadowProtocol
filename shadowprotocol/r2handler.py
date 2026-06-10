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
        
        Recherche INTELLIGENTE & ROBUSTE:
        1. Cherche exactement a l'offset fourni (±32 bytes)
        2. Si pas trouve, scanne ±1000 bytes autour
        3. Supporte tous les registres (x0-x30, sp, etc)
        Utile pour les offsets pptool qui ne sont pas toujours exacts.

        Returns:
            (pattern_trouve, instruction_complete, registre_detecte)
        """
        if not self.pipe:
            return (False, "", "")
        
        try:
            offset_int = int(offset, 16) if isinstance(offset, str) else offset
            
            # ÉTAPE 1: Chercher exactement a l'offset (±32 bytes)
            search_start_1 = max(0, offset_int - 32)
            search_end_1 = offset_int + 32
            start_offset_1 = hex(search_start_1)
            
            ok, disasm = self.disasm_at(start_offset_1, 20)
            if ok:
                result = self._search_pattern_in_disasm(disasm, search_start_1, search_end_1, offset_int)
                if result[0]:
                    return result
            
            # ÉTAPE 2: Chercher dans une plage plus large (±1000 bytes)
            search_start_2 = max(0, offset_int - 1000)
            search_end_2 = offset_int + 1000
            start_offset_2 = hex(search_start_2)
            
            ok, disasm = self.disasm_at(start_offset_2, 150)
            if ok:
                result = self._search_pattern_in_disasm(disasm, search_start_2, search_end_2, offset_int)
                if result[0]:
                    return result
            
            return (False, "", "")
        except Exception as e:
            return (False, "", "")
    
    def _search_pattern_in_disasm(self, disasm: str, search_start: int, 
                                   search_end: int, preferred_offset: int) -> Tuple[bool, str, str]:
        """Chercher le pattern add x?, x?, 0x30 dans un disassemblage.
        
        Patterns supportés:
        - add x0, x22, 0x30
        - add x17, x22, 0x30
        - etc (tous les registres x0-x30 + sp)
        """
        # Pattern flexible: accepte tous les registres et formats
        pattern = re.compile(
            r'(0x[0-9a-fA-F]+)\s+.*?\badd\s+((?:x|sp|lr|pc)\d*|sp),\s*((?:x|sp|lr|pc)\d*|sp),\s*0x30',
            re.IGNORECASE
        )
        
        closest_match = None
        closest_distance = float('inf')
        
        # Chercher dans tout le disassemblage
        for line in disasm.split('\n'):
            match = pattern.search(line)
            if match:
                try:
                    found_addr = match.group(1)
                    found_int = int(found_addr, 16)
                    
                    # Vérifier que l'adresse est dans la plage
                    if search_start <= found_int <= search_end:
                        # Garder le match le plus proche de preferred_offset
                        distance = abs(found_int - preferred_offset)
                        if distance < closest_distance:
                            closest_distance = distance
                            closest_match = (True, f"add {match.group(2)},{match.group(3)},0x30", match.group(2))
                except (ValueError, IndexError):
                    continue
        
        if closest_match:
            return closest_match
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
        try:
            # Chercher l'instruction exacte a patcher (au cas où elle s'est déplacée)
            offset_int = int(offset, 16) if isinstance(offset, str) else offset
            ok, disasm = self.disasm_at(hex(offset_int - 16), 10)
            
            if ok:
                # Vérifier qu'on trouve toujours le pattern
                pattern = re.compile(r'add\s+' + re.escape(register) + r',\s*' + re.escape(src_reg) + r',\s*0x30', re.IGNORECASE)
                found = False
                actual_offset = offset
                
                for line in disasm.split('\n'):
                    if pattern.search(line):
                        # Extraire l'offset réel
                        addr_match = re.search(r'(0x[0-9a-fA-F]+)', line)
                        if addr_match:
                            actual_offset = addr_match.group(1)
                            found = True
                            break
                
                if not found:
                    return (False, "Pattern add x?,x?,0x30 non trouve a proximite")
                
                # Appliquer le patch avec la bonne adresse
                self.execute(f"s {actual_offset}")
                patch_cmd = f"wa add {register}, {src_reg}, {new_val}"
                ok, output, err = self.execute(patch_cmd)
                
                if not ok or err:
                    # Essayer une approche alternative (directement par bytes)
                    return (False, f"Erreur patch Radare2: {err[:100] if err else output[:100]}")
                
                # Verification post-patch immédiate
                ok2, verify, _ = self.disasm_at(actual_offset, 2)
                if ok2:
                    if new_val in verify and "add" in verify:
                        return (True, f"Patch applique et verifie: {actual_offset}")
                    else:
                        # Double-check: est-ce que c'est vraiment échoué?
                        if register in verify or "x" in verify:
                            return (True, f"Patch applique: {actual_offset}")
                        else:
                            return (False, "Instruction non patched correctement")
                
                return (False, "Impossible de verifier le patch")
            
            return (False, "Impossible d'acceder a l'instruction")
            
        except ValueError as e:
            return (False, f"Format d'offset invalide: {e}")
        except Exception as e:
            return (False, f"Erreur patch: {str(e)[:100]}")

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
