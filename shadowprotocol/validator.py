"""
ShadowProtocol - Validateur

Validation des dependances systeme et integrite du code.
"""

import ast
import sys
import subprocess
from pathlib import Path
from typing import List, Tuple


class CodeValidator:
    """Valider l'integrite du code Python."""

    @staticmethod
    def find_unused_imports(file_path: str) -> List[str]:
        """Detecter les imports inutilises."""
        try:
            with open(file_path, 'r') as f:
                tree = ast.parse(f.read())
        except Exception:
            return []

        imports = set()
        used = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imports.add(alias.asname or alias.name)
            elif isinstance(node, ast.Name):
                used.add(node.id)

        return list(imports - used)

    @staticmethod
    def find_unused_variables(file_path: str) -> List[str]:
        """Detecter les variables inutilisees."""
        try:
            with open(file_path, 'r') as f:
                tree = ast.parse(f.read())
        except Exception:
            return []

        defined = {}
        used = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        defined[target.id] = True
            elif isinstance(node, ast.Name):
                used.add(node.id)

        return [var for var in defined if var not in used and not var.startswith('_')]


class DependencyValidator:
    """Valider les dependances systeme avant l'execution des modes."""

    @staticmethod
    def check_python_version() -> Tuple[bool, str]:
        """Verifier Python >= 3.7."""
        version = sys.version_info
        if version >= (3, 7):
            return (True, f"Python {version.major}.{version.minor} OK")
        return (False, f"Python {version.major}.{version.minor} - need 3.7+")

    @staticmethod
    def check_radare2() -> Tuple[bool, str]:
        """Verifier r2 existe et obtenir la version."""
        try:
            result = subprocess.run(
                ['r2', '-v'], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.split('\n')[0]
                return (True, f"Radare2 {version} OK")
        except Exception:
            pass
        return (False, "Radare2 not found - install: sudo apt install radare2")

    @staticmethod
    def check_r2pipe() -> Tuple[bool, str]:
        """Verifier le module r2pipe (CORRIGE: verifie reellement)."""
        try:
            import r2pipe
            return (True, "r2pipe OK")
        except ImportError:
            return (False, "r2pipe missing - pip install r2pipe>=1.6.0")

    @staticmethod
    def check_java() -> Tuple[bool, str]:
        """Verifier Java >= 8 (necessaire pour MODE D/F)."""
        try:
            result = subprocess.run(
                ['java', '-version'], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 or result.stderr:
                output = result.stderr or result.stdout
                if 'version' in output.lower():
                    return (True, "Java OK")
        except Exception:
            pass
        return (False, "Java 8+ not found - needed for MODE D/F")

    @classmethod
    def validate_all(cls, required_modes: List[str] = None) -> Tuple[bool, List[str]]:
        """Valider les dependances.

        Args:
            required_modes: Liste des modes qui seront utilises ['A', 'B', 'D', 'F']

        Returns:
            (all_ok: bool, messages: List[str])
        """
        messages = []
        required_modes = required_modes or []

        ok, msg = cls.check_python_version()
        messages.append(msg)
        if not ok:
            return (False, messages)

        ok, msg = cls.check_radare2()
        messages.append(msg)

        ok, msg = cls.check_r2pipe()
        messages.append(msg)

        if any(m in ['D', 'F'] for m in required_modes):
            ok, msg = cls.check_java()
            messages.append(msg)

        all_ok = all('OK' in m for m in messages)
        return (all_ok, messages)
