"""
Validator - Cross-file validation & integrity checks
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
        
        py_files = list(self.project_path.glob("*.py"))
        
        if not py_files:
            print("[!] Aucun fichier Python trouvé")
            return False
        
        print(f"[*] Validation de {len(py_files)} fichiers...\n")
        
        for py_file in py_files:
            print(f"Vérification: {py_file.name}")
            unused = self.code_validator.find_unused_imports(str(py_file))
            if unused:
                self.issues['warnings'].append(f"{py_file.name}: Imports inutilisés: {', '.join(unused)}")
        
        for py_file in py_files:
            unused = self.code_validator.find_unused_variables(str(py_file))
            if unused:
                self.issues['warnings'].append(f"{py_file.name}: Variables inutilisées: {', '.join(unused)}")
        
        self._print_report()
        
        return len(self.issues['errors']) == 0
    
    def _print_report(self):
        """Print validation report"""
        print("\n" + "="*80)
        print("RAPPORT DE VALIDATION")
        print("="*80 + "\n")
        
        if self.issues['errors']:
            print(f"ERREURS ({len(self.issues['errors'])}):")
            for error in self.issues['errors']:
                print(f"  [!] {error}")
        
        if self.issues['warnings']:
            print(f"\nAVERTISSEMENTS ({len(self.issues['warnings'])}):")
            for warn in self.issues['warnings']:
                print(f"  [W] {warn}")
        
        if not self.issues['errors'] and not self.issues['warnings']:
            print("[+] Toutes les validations réussies!")
        
        total = len(self.issues['errors']) + len(self.issues['warnings'])
        print(f"\n{'─'*80}")
        print(f"Problèmes totaux: {total}")
        print("="*80 + "\n")


def validate_project(project_path: str = ".") -> bool:
    """Validate project integrity"""
    validator = ProjectValidator(project_path)
    return validator.validate_all()


if __name__ == "__main__":
    success = validate_project(sys.argv[1] if len(sys.argv) > 1 else ".")
    sys.exit(0 if success else 1)
