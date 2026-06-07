"""
Validator - Cross-file validation & integrity checks
+ Dependency validation for system tools
"""

import os
import ast
import sys
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict, Tuple


class CodeValidator:
    """Validate Python code integrity"""

    @staticmethod
    def find_unused_imports(file_path: str) -> List[str]:
        """Detect unused imports"""
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
        """Detect unused variables"""
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


class ProjectValidator:
    """Validate entire project"""

    def __init__(self, project_path: str = "."):
        """Initialize project validator"""
        self.project_path = Path(project_path)
        self.code_validator = CodeValidator()
        self.issues = {
            'errors': [],
            'warnings': [],
            'info': []
        }

    def validate_all(self) -> bool:
        """Run all validations"""
        print("\n" + "="*80)
        print("PROJECT VALIDATION - ShadowProtocol v3.0")
        print("="*80 + "\n")

        py_files = list(self.project_path.rglob("*.py"))

        # Filter out __pycache__ and virtual environments
        py_files = [
            f for f in py_files
            if '__pycache__' not in str(f)
            and 'site-packages' not in str(f)
            and '.egg-info' not in str(f)
            and 'venv' not in str(f)
        ]

        if not py_files:
            print("[!] No Python files found")
            return False

        print(f"[*] Validating {len(py_files)} files...\n")

        for py_file in py_files:
            print(f"Checking: {py_file.name}")
            unused = self.code_validator.find_unused_imports(str(py_file))
            if unused:
                self.issues['warnings'].append(f"{py_file.name}: Unused imports: {', '.join(unused)}")

        for py_file in py_files:
            unused = self.code_validator.find_unused_variables(str(py_file))
            if unused:
                self.issues['warnings'].append(f"{py_file.name}: Unused variables: {', '.join(unused)}")

        self._print_report()

        return len(self.issues['errors']) == 0

    def _print_report(self):
        """Print validation report"""
        print("\n" + "="*80)
        print("VALIDATION REPORT")
        print("="*80 + "\n")

        if self.issues['errors']:
            print(f"ERRORS ({len(self.issues['errors'])}):")
            for error in self.issues['errors']:
                print(f"  [!] {error}")

        if self.issues['warnings']:
            print(f"\nWARNINGS ({len(self.issues['warnings'])}):")
            for warn in self.issues['warnings']:
                print(f"  [W] {warn}")

        if not self.issues['errors'] and not self.issues['warnings']:
            print("[+] All validations passed!")

        total = len(self.issues['errors']) + len(self.issues['warnings'])
        print(f"\n{'─'*80}")
        print(f"Total issues: {total}")
        print("="*80 + "\n")


class DependencyValidator:
    """Validate system dependencies before running modes."""

    @staticmethod
    def check_python_version() -> Tuple[bool, str]:
        """Check Python >= 3.7"""
        version = sys.version_info
        if version >= (3, 7):
            return (True, f"Python {version.major}.{version.minor} OK")
        return (False, f"Python {version.major}.{version.minor} - need 3.7+")

    @staticmethod
    def check_radare2() -> Tuple[bool, str]:
        """Check r2 binary exists and get version"""
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
        """Check r2pipe module"""
        try:
            import r2pipe
            return (True, "r2pipe OK")
        except ImportError:
            return (False, "r2pipe missing - pip install r2pipe>=1.6.0")

    @staticmethod
    def check_java() -> Tuple[bool, str]:
        """Check Java >= 8 (needed for MODE D/F)"""
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
        """Validate dependencies.

        Args:
            required_modes: List of modes that will be used ['A', 'B', 'D', 'F']

        Returns:
            (all_ok: bool, messages: List[str])
        """
        messages = []
        required_modes = required_modes or []

        # Always check
        ok, msg = cls.check_python_version()
        messages.append(msg)
        if not ok:
            return (False, messages)

        ok, msg = cls.check_radare2()
        messages.append(msg)

        ok, msg = cls.check_r2pipe()
        messages.append(msg)

        # Only if needed
        if any(m in ['D', 'F'] for m in required_modes):
            ok, msg = cls.check_java()
            messages.append(msg)

        all_ok = all('OK' in m for m in messages)
        return (all_ok, messages)


def validate_project(project_path: str = ".") -> bool:
    """Validate project integrity"""
    validator = ProjectValidator(project_path)
    return validator.validate_all()


def validate_dependencies(required_modes: List[str] = None) -> Tuple[bool, List[str]]:
    """Validate system dependencies."""
    return DependencyValidator.validate_all(required_modes)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--check-deps":
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
    else:
        success = validate_project(sys.argv[1] if len(sys.argv) > 1 else ".")
        sys.exit(0 if success else 1)
