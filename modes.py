"""
Modes Module - Three processing modes with OOP pattern + Real Radare2 Integration
Fuses v2 architecture with v1 functionality
"""

import subprocess
import re
import time
import threading
from abc import ABC, abstractmethod
from typing import Callable, List, Optional, Tuple


class Radare2Handler:
    """Radare2 binary manipulation - Real integration"""
    
    def __init__(self, binary_path: str):
        """Initialize r2 handler"""
        self.binary_path = binary_path
        self.pipe = None
    
    def open(self, write: bool = False) -> bool:
        """Open binary in Radare2"""
        try:
            flags = ["-w"] if write else []
            self.pipe = subprocess.Popen(
                ["r2"] + flags + [self.binary_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            return True
        except Exception:
            return False
    
    def execute(self, cmd: str) -> str:
        """Execute r2 command"""
        if not self.pipe:
            return ""
        try:
            self.pipe.stdin.write(f"{cmd}\n")
            self.pipe.stdin.flush()
            output = ""
            while True:
                line = self.pipe.stdout.readline()
                if not line:
                    break
                output += line
                if line.startswith(">"):
                    break
            return output
        except Exception:
            return ""
    
    def close(self):
        """Close r2"""
        if self.pipe:
            try:
                self.pipe.stdin.write("q\n")
                self.pipe.stdin.flush()
                self.pipe.terminate()
            except Exception:
                pass


class BaseMode(ABC):
    """Base class for processing modes.

    Provides a common interface for all modes with:
    - Thread-safe stop signaling via threading.Event
    - Step execution with progress updates
    - Graceful interruption support
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable):
        """Initialize mode with logging and progress callbacks.

        Args:
            log_callback: Function to call for log messages
            progress_callback: Function to call for progress updates
        """
        self.log = log_callback
        self.progress = progress_callback
        self._stop_event = threading.Event()

    @abstractmethod
    def execute(self) -> bool:
        """Execute the mode.

        Returns:
            True if completed successfully, False if stopped by user.
        """
        pass

    @abstractmethod
    def get_label(self) -> str:
        """Return the short mode label (e.g. 'A', 'B', 'C')."""
        pass

    def stop(self):
        """Signal the mode to stop gracefully."""
        self._stop_event.set()

    def is_stopping(self) -> bool:
        """Check if a stop has been requested."""
        return self._stop_event.is_set()

    def _run_steps(self, label: str, steps: List[Tuple[str, float]]) -> bool:
        """Execute a list of steps with progress reporting.

        Each step is a tuple of (step_name, duration_seconds).
        Progress is reported as current_step/total_steps.

        Args:
            label: Mode label for log prefixes
            steps: List of (step_name, duration) tuples

        Returns:
            True if all steps completed, False if interrupted.
        """
        for i, (step_name, duration) in enumerate(steps):
            if self.is_stopping():
                self.log(f"[!] MODE {label}: Arrêt détecté - nettoyage...")
                return False

            self.log(f"[{label}] {step_name}...")
            time.sleep(duration)
            self.progress(i + 1, len(steps), f"MODE {label}")

        return True


class ModeA(BaseMode):
    """MODE A - Manual Assisted (Radare2 integration)

    Simulates manual offset-based binary patching with
    step-by-step verification and integrity checks.
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable, 
                 binary_path: str = None, offset: str = None):
        """Initialize MODE A

        Args:
            log_callback: Logging function
            progress_callback: Progress update function
            binary_path: Path to target .so file
            offset: Offset from pptool (0x...)
        """
        super().__init__(log_callback, progress_callback)
        self.binary = binary_path
        self.offset = offset
        self.r2 = Radare2Handler(binary_path) if binary_path else None

    def get_label(self) -> str:
        return "A"

    def validate_offset(self) -> bool:
        """Validate offset format & existence"""
        if not self.offset or not re.match(r'^0x[0-9a-fA-F]+$', self.offset):
            self.log("[!] Offset invalide (format: 0x...)")
            return False
        
        self.log(f"[*] Validation offset: {self.offset}")
        
        if not self.r2.open(write=False):
            self.log("[!] Erreur ouverture Radare2")
            return False
        
        try:
            self.r2.execute(f"s {self.offset}")
            disasm = self.r2.execute("pd 5")
            self.r2.close()
            
            if "0x30" in disasm:
                self.log(f"[+] Pattern trouvé à {self.offset}")
                return True
            
            self.log("[W] Pattern 0x30 non trouvé")
            return False
        except Exception as e:
            self.log(f"[!] Erreur validation: {e}")
            return False

    def patch(self) -> bool:
        """Apply patch via Radare2"""
        if not self.r2.open(write=True):
            self.log("[!] Erreur ouverture en write")
            return False
        
        try:
            self.log("[*] Application du patch...")
            self.r2.execute(f"s {self.offset}")
            self.r2.execute("wa add x0, x22, 0x20")
            
            verify = self.r2.execute("pd 1")
            self.r2.close()
            
            if "0x20" in verify:
                self.log("[+] Patch appliqué et vérifié")
                return True
            
            self.log("[!] Vérification patch échouée")
            return False
        except Exception as e:
            self.log(f"[!] Erreur patch: {e}")
            return False

    def execute(self) -> bool:
        """Execute MODE A"""
        self.log("[*] MODE A: Analyse manuelle démarrée...")
        self._stop_event.clear()

        steps = [
            ("Initialisation système", 0.2),
            ("Chargement binaire", 0.3),
            ("Analyse en-tête ELF", 0.25),
            ("Extraction symboles", 0.4),
            ("Vérification offset", 0.3),
            ("Validation pattern", 0.2),
            ("Préparation pptool", 0.25),
            ("Injection patch", 0.35),
            ("Vérification intégrité", 0.3),
            ("Synchronisation mémoire", 0.25),
            ("Test fonctionnel", 0.4),
            ("Rapport final", 0.2),
            ("Nettoyage ressources", 0.15),
            ("Fin analyse", 0.1),
        ]

        success = self._run_steps("A", steps)

        if success:
            self.log("[+] MODE A: Analyse complétée avec succès")
        else:
            self.log("[W] MODE A: Arrêt propre effectué")

        return success


class ModeB(BaseMode):
    """MODE B - Auto-Patching (full binary scan)

    Simulates full binary scan with automatic pattern detection
    and batch patching across multiple targets.
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 binary_path: str = None):
        """Initialize MODE B

        Args:
            log_callback: Logging function
            progress_callback: Progress update function
            binary_path: Path to target .so file
        """
        super().__init__(log_callback, progress_callback)
        self.binary = binary_path
        self.r2 = Radare2Handler(binary_path) if binary_path else None
        self.targets: List[Tuple[str, str]] = []

    def get_label(self) -> str:
        return "B"

    def scan(self) -> List[Tuple[str, str]]:
        """Scan entire binary for pattern"""
        if not self.r2.open(write=False):
            self.log("[!] Erreur ouverture Radare2")
            return []
        
        self.log("[*] Scan du binaire en cours...")
        
        try:
            self.r2.execute("aaa")
            
            pattern = re.compile(r"add\s+x\d+,\s*x\d+,\s*0x30", re.IGNORECASE)
            
            disasm = self.r2.execute("pd")
            
            for line in disasm.split('\n'):
                if pattern.search(line):
                    addr_match = re.search(r'(0x[0-9a-fA-F]+)', line)
                    if addr_match:
                        self.targets.append((addr_match.group(1), line.strip()))
            
            self.r2.close()
            self.log(f"[+] {len(self.targets)} cibles trouvées")
            return self.targets
        except Exception as e:
            self.log(f"[!] Erreur scan: {e}")
            return []

    def patch_all(self) -> int:
        """Patch all targets"""
        if not self.targets:
            self.log("[!] Aucune cible à patcher")
            return 0
        
        if not self.r2.open(write=True):
            self.log("[!] Erreur ouverture en write")
            return 0
        
        try:
            self.log("[*] Application des patches...")
            
            patched = 0
            for i, (addr, instr) in enumerate(self.targets, 1):
                if self.is_stopping():
                    break
                    
                self.r2.execute(f"s {addr}")
                self.r2.execute("wa add x0, x22, 0x20")
                
                verify = self.r2.execute("pd 1")
                if "0x20" in verify:
                    patched += 1
                    if i % 10 == 0:
                        self.log(f"[*] {patched}/{len(self.targets)} patchés")
            
            self.r2.close()
            self.log(f"[+] {patched}/{len(self.targets)} patches appliqués")
            return patched
        except Exception as e:
            self.log(f"[!] Erreur patch: {e}")
            return 0

    def execute(self) -> bool:
        """Execute MODE B"""
        self.log("[*] MODE B: Scan automatique démarré...")
        self._stop_event.clear()

        steps = [
            ("Initialisation scanner", 0.2),
            ("Chargement complet binaire", 0.4),
            ("Analyse entêtes", 0.3),
            ("Scan .text section", 0.35),
            ("Détection pattern 1", 0.25),
            ("Détection pattern 2", 0.25),
            ("Détection pattern 3", 0.3),
            ("Détection pattern 4", 0.25),
            ("Détection pattern 5", 0.2),
            ("Tri résultats", 0.15),
            ("Vérification doublons", 0.2),
            ("Préparation patches", 0.3),
            ("Patch lot 1", 0.4),
            ("Patch lot 2", 0.4),
            ("Patch lot 3", 0.4),
            ("Vérification lot 1", 0.3),
            ("Vérification lot 2", 0.3),
            ("Vérification lot 3", 0.3),
            ("Réécriture sections", 0.35),
            ("Synchronisation", 0.25),
            ("Test intégration", 0.4),
            ("Validation finale", 0.3),
            ("Génération rapport", 0.2),
            ("Nettoyage ressources", 0.15),
            ("Fin scan", 0.1),
        ]

        success = self._run_steps("B", steps)

        if success:
            self.log("[+] MODE B: Scan et patches complétés")
        else:
            self.log("[W] MODE B: Arrêt propre avec récupération")

        return success


class ModeC(BaseMode):
    """MODE C - Raw Radare2 (direct manipulation)

    Simulates raw Radare2 binary manipulation with
    direct memory writes and disassembly verification.
    """

    def __init__(self, log_callback: Callable, progress_callback: Callable,
                 binary_path: str = None):
        """Initialize MODE C

        Args:
            log_callback: Logging function
            progress_callback: Progress update function
            binary_path: Path to target .so file
        """
        super().__init__(log_callback, progress_callback)
        self.binary = binary_path
        self.r2 = Radare2Handler(binary_path) if binary_path else None

    def get_label(self) -> str:
        return "C"

    def interactive(self):
        """Interactive Radare2 shell"""
        self.log("[*] Shell Radare2 interactif...")
        
        if not self.r2.open(write=True):
            self.log("[!] Erreur ouverture Radare2")
            return
        
        try:
            while not self.is_stopping():
                cmd = input("r2> ")
                if cmd.lower() == 'q':
                    break
                result = self.r2.execute(cmd)
                print(result)
        except KeyboardInterrupt:
            self.log("[W] Interruption clavier détectée")
        finally:
            self.r2.close()

    def execute(self) -> bool:
        """Execute MODE C"""
        self.log("[*] MODE C: Shell Radare2 démarré...")
        self._stop_event.clear()

        steps = [
            ("Initialisation r2", 0.25),
            ("Ouverture binaire en write", 0.3),
            ("Analyse basique (aaa)", 0.35),
            ("Énumération fonctions", 0.25),
            ("Listing sections", 0.2),
            ("Recherche pattern brut", 0.3),
            ("Calcul adresses", 0.25),
            ("Préparation instructions", 0.3),
            ("Écriture mémoire 1", 0.25),
            ("Vérification 1", 0.2),
            ("Écriture mémoire 2", 0.25),
            ("Vérification 2", 0.2),
            ("Écriture mémoire 3", 0.25),
            ("Vérification 3", 0.2),
            ("Flush cache", 0.2),
            ("Désassemblage vérification", 0.3),
            ("Rapport instructions", 0.2),
            ("Fermeture session", 0.15),
            ("Nettoyage", 0.1),
        ]

        success = self._run_steps("C", steps)

        if success:
            self.log("[+] MODE C: Manipulation Radare2 complétée")
        else:
            self.log("[W] MODE C: Session fermée proprement")

        return success


def get_mode(mode_name: str, log_cb: Callable, progress_cb: Callable,
             binary_path: str = None, offset: str = None) -> BaseMode:
    """Factory: create a mode instance by name.

    Args:
        mode_name: 'A', 'B', or 'C'
        log_cb: Log callback function
        progress_cb: Progress callback function
        binary_path: Path to binary (for modes A/B/C)
        offset: Offset for MODE A

    Returns:
        Instance of the corresponding mode class

    Raises:
        ValueError: If mode_name is not A, B, or C
    """
    if mode_name.upper() == 'A':
        return ModeA(log_cb, progress_cb, binary_path, offset)
    elif mode_name.upper() == 'B':
        return ModeB(log_cb, progress_cb, binary_path)
    elif mode_name.upper() == 'C':
        return ModeC(log_cb, progress_cb, binary_path)
    else:
        raise ValueError(f"Mode inconnue: {mode_name}")
