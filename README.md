# 🔥 ShadowProtocol v3.0 Enhanced

**Status**: ✅ **PRODUCTION READY**  
**Version**: 3.0 - Fusion Edition (TUI + Radare2)  
**Architecture**: Curses + ANSI + Radare2 + 3 Modes (A/B/C)

---

## 📋 PROJECT OVERVIEW

ShadowProtocol v3.0 est une fusion complète de deux versions:

- **v2 TUI** → Interface terminal avancée (Curses + ANSI, logging temps réel, barre progression)
- **v1 Métier** → Logique Radare2 réelle (sélection cibles, patchage binaire)

**Résultat**: Une application de patchage binaire avec interface professionnelle et fonctionnalité réelle.

---

## ✨ KEY FEATURES

### 🎨 Advanced Terminal UI
- **Curses-based interface** avec fallback ANSI (compatibilité maximale)
- **Live logging** avec défilement temps réel (buffer 50 lignes)
- **Progress bar** avec étapes et pourcentage
- **Responsive layout** - s'adapte à la taille du terminal
- **Thread-safe logging** - sûr pour les opérations concurrentes

### 🛠️ Real Radare2 Integration
- **MODE A** - Patchage manuel assisté via offset PPTool
- **MODE B** - Scan automatique et patchage en masse
- **MODE C** - Shell Radare2 interactif direct
- Validation ELF binaires
- Détection architecture (ARM64, x86, i386)
- Vrai patchage via `r2pipe`

### 🎯 Target Selection
- Auto-détection fichiers `.so`
- Sélection interactive avec menu
- Validation intégrité binaire
- Affichage architecture et permissions

### 🔒 Safety & Reliability
- Gestion propre des signaux (SIGINT, SIGTERM)
- Nettoyage ressources avec timeout 5s
- Thread-safe operations
- Validation syntaxe Python complète
- Zéro code mort

---

## 🚀 INSTALLATION

### Prérequis Système

```bash
# Linux/Debian/Ubuntu
sudo apt update
sudo apt install radare2 python3 python3-pip

# macOS
brew install radare2 python3

# Termux (Android)
pkg install radare2 python3 python-pip
```

### Installation Python

**Option 1: pip (recommandé)**
```bash
pip install .
shadowprotocol  # Run
```

**Option 2: Development mode**
```bash
pip install -e .
shadowprotocol
```

**Option 3: Script direct**
```bash
chmod +x run.sh
./run.sh
```

**Option 4: Make**
```bash
make install
make run
```

---

## 📖 USAGE

### Interactive Mode
```bash
shadowprotocol
# Puis:
# [1] - Sélectionner cible .so
# [a] - MODE A (manuel)
# [b] - MODE B (auto)
# [c] - MODE C (raw r2)
# [q] - Quitter
```

### Direct Mode Execution
```bash
shadowprotocol A  # MODE A
shadowprotocol B  # MODE B
shadowprotocol C  # MODE C
```

### Using Make
```bash
make run        # Interactive
make mode-a     # MODE A
make mode-b     # MODE B
make mode-c     # MODE C
```

---

## 🎮 INTERFACE LAYOUT

```
╔ ShadowProtocol v3.0 | Mode: MODE A | Running... ══════════╗
───────────────────────────────────────────────────────────────
 ▶ LIVE OUTPUT
───────────────────────────────────────────────────────────────
 [10:25:32] [*] MODE A: Analyse manuelle démarrée...
 [10:25:33] [*] [A] Initialisation système...
 [10:25:33] [+] [A] Chargement binaire...
 [10:25:34] [*] [A] Analyse en-tête ELF...
 [10:25:35] [+] Cible sélectionnée: /path/to/lib.so (ARM64)
───────────────────────────────────────────────────────────────
 [████████████████████░░░░░░░░░░░░░░░░░░░░░] 65% MODE A 10/14
 [q] Quitter | Modes: [a] [b] [c]
```

---

## 🎯 THREE MODES

### MODE A - Manual Assisted
**Patchage manuel avec offset PPTool**
- Input: Chemin .so + offset (0x...)
- Validation pattern `0x30`
- Remplacement par `0x20`
- Vérification intégrité
- Durée: ~3s (+ validation)

### MODE B - Auto-Patching
**Scan automatique et patchage en masse**
- Scan binaire complet
- Détection automatique patterns
- Patchage tous les `add x0, x22, 0x30`
- Remplacement par `add x0, x22, 0x20`
- Statistiques finales
- Durée: ~5-10s (selon taille binaire)

### MODE C - Raw Radare2
**Shell interactif Radare2**
- Accès direct commandes r2
- Script execution
- Full binary manipulation
- Durée: ~4s ou plus (selon usage)

---

## 🔧 PROJECT STRUCTURE

```
shadowprotocol/
├── __init__.py              # Package init
├── __main__.py              # python3 -m support
├── main.py                  # Application orchestrator
├── ui.py                    # CursesUI + ANSIUI
├── logger.py                # Thread-safe logging
├── modes.py                 # ModeA/B/C + Radare2Handler
├── target_selector.py       # .so detection & validation
├── theme.py                 # ANSI colors & formatting
├── validator.py             # Project validation
├── setup.py                 # Package setup
├── requirements.txt         # Python dependencies
├── Makefile                 # Build commands
├── run.sh                   # Launch script
├── LICENSE                  # MIT License
└── README.md               # This file
```

---

## 📊 TECHNICAL SPECS

| Aspect | Details |
|--------|---------|
| **Language** | Python 3.7+ |
| **UI Framework** | curses (stdlib) |
| **Binary Handler** | Radare2 + r2pipe |
| **Threading** | Thread-safe logging + async modes |
| **Signal Handling** | SIGINT, SIGTERM |
| **Fallback UI** | ANSI escape sequences |
| **Terminal Resize** | Auto-detect & adapt |
| **Progress Tracking** | Real-time updates |

---

## 🔐 SECURITY FEATURES

✅ **Automatic validation** of ELF binaries  
✅ **Write permission checks** before patching  
✅ **Patch verification** after writing  
✅ **Graceful shutdown** with resource cleanup  
✅ **Signal handling** for clean interruption  
✅ **Input validation** for offsets  
✅ **Thread-safe operations** with locks  

---

## 🧪 VALIDATION

Valider le projet:
```bash
make validate
python3 -m shadowprotocol.validator
```

Vérifier syntaxe:
```bash
python3 -m py_compile shadowprotocol/*.py
```

---

## 📝 CHANGELOG

### v3.0.0 (2024)
- ✅ Fusion v2 TUI + v1 Métier
- ✅ Interface Curses avancée
- ✅ Vrai intégration Radare2
- ✅ Target selection automatique
- ✅ Thread-safe logging temps réel
- ✅ Barre progression
- ✅ Gestion signaux propre
- ✅ Fallback ANSI

### v2.0.0
- TUI avec curses + ANSI
- Modes simulés
- UI avancée

### v1.0.0
- Logique Radare2 réelle
- Target selection
- Modes A/B/C fonctionnels

---

## 🤝 REQUIREMENTS

- **Python 3.7+**
- **Radare2** (binary patcher)
- **r2pipe>=1.6.0** (Python Radare2 binding)
- **curses** (stdlib - inclus)
- **Linux/macOS/Termux** (POSIX)

---

## 📋 TROUBLESHOOTING

### "r2 not found"
```bash
sudo apt install radare2
```

### "r2pipe module not found"
```bash
pip install r2pipe
```

### Curses error on Windows
```bash
pip install windows-curses
```

### Terminal display issues
- Assurez-vous `TERM=xterm-256color`
- Utilisez un terminal avec support color 256
- Sinon, fallback ANSI est automatique

---

## 📄 LICENSE

MIT License - See LICENSE file

---

## ✅ STATUS

**Production Ready** ✅  
**Fully Tested** ✅  
**Zero Dead Code** ✅  
**Complete Documentation** ✅

---

**Version**: 3.0.0  
**Status**: Production Ready ✅  
**Author**: ShadowProtocol Enhanced Team
