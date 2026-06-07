"""
Validator - Cross-file validation & integrity checks

Key improvements (no business logic changes):
- Validates Python files in all subdirectories (not just top-level)
- Better error handling and reporting
"""

import os
import ast
import sys
from pathlib import Path
from typing import List, Dict


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

        # Search recursively for all .py files in the project
        py_files = list(self.project_path.rglob("*.py"))

        # Filter out __pycache__ and virtual environment directories
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
            print(f"Checking: {py_file.relative_to(self.project_path)}")
            unused = self.code_validator.find_unused_imports(str(py_file))
            if unused:
                rel_path = str(py_file.relative_to(self.project_path))
                self.issues['warnings'].append(f"{rel_path}: Unused imports: {', '.join(unused)}")

        for py_file in py_files:
            unused = self.code_validator.find_unused_variables(str(py_file))
            if unused:
                rel_path = str(py_file.relative_to(self.project_path))
                self.issues['warnings'].append(f"{rel_path}: Unused variables: {', '.join(unused)}")

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


def validate_project(project_path: str = ".") -> bool:
    """Validate project integrity"""
    validator = ProjectValidator(project_path)
    return validator.validate_all()


if __name__ == "__main__":
    success = validate_project(sys.argv[1] if len(sys.argv) > 1 else ".")
    sys.exit(0 if success else 1)
