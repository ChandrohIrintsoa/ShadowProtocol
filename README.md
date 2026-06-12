# ShadowProtocol v4.0 - Le Grimoire de Transmutation Binaire

Binary Patcher with Radare2 Integration + Flutter Patcher + TUI

## Features

- **6 Rituels de Transmutation:**
  - **Rituel A** - L'Invocation Precise (patchage par offset pptool)
  - **Rituel B** - Le Balayage d'Ame (scan automatique et patch global)
  - **Rituel C** - La Connexion Directe (canal R2 brut avec 9 pouvoirs)
  - **Rituel D** - Le Patcheur Flutter (APK merge, blutter, PP/ASM patching)
  - **Rituel E** - La Quete des Fonctions (ARM64 pattern search v2/v3)
  - **Rituel F** - Le Patcheur de Manifeste (license check removal, extractNativeLibs)

- **Terminal UI (Le Grimoire):** 5 Chapitres avec curses, fallback ANSI
  - Chapitre I: Banniere ShadowProtocol
  - Chapitre II: Menu des 6 Rituels + sous-menu Rituel C
  - Chapitre III: Info de l'Esprit Cible (nom, arch, taille, canal r2)
  - Chapitre IV: Les Visions (log en temps reel, barre de progression)
  - Chapitre V: Les Transmutations (resultats de patch avec suivi)

- **Radare2 Integration:** Handler complet via r2pipe (seek, disasm, patch, scan, batch)
- **Auto-detection:** Detection automatique des fichiers .so au demarrage
- **Flutter Patcher:** APK merge, ARM64 extraction, blutter analysis, PP/ASM patching
- **Manifest Patcher:** License check removal, extractNativeLibs fix
- **Function Finder:** ARM64 pattern search v2 (x0 specific) et v3 (any register)
- **Resultats persistants:** Ecriture automatique dans le repertoire results/

## Installation

```bash
pip install .
# or
pip install -e .  # development mode
```

## Requirements

- Python 3.7+
- Radare2 (`r2`)
- r2pipe (`pip install r2pipe`)
- Java (for APK merge/manifest operations - Rituels D/F)

## Usage

```bash
# Interactive mode
shadowprotocol
python3 -m shadowprotocol

# Direct ritual execution
shadowprotocol A    # L'Invocation Precise
shadowprotocol B    # Le Balayage d'Ame
shadowprotocol C    # La Connexion Directe
shadowprotocol D    # Le Patcheur Flutter
shadowprotocol E    # La Quete des Fonctions
shadowprotocol F    # Le Patcheur de Manifeste

# Utilities
shadowprotocol --check       # Check dependencies
shadowprotocol --check-deps  # Check dependencies (alias)
shadowprotocol --dry-run A   # Dry-run Rituel A
```


## License

MIT License - see LICENSE file for details.
