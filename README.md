# ShadowProtocol v3.0

Binary Patcher with Radare2 Integration + Flutter Patcher + TUI

## Features

- **6 Processing Modes:**
  - **MODE A** - Manual Assisted (pptool offset patching)
  - **MODE B** - Auto-Patching (full binary scan)
  - **MODE C** - Raw Radare2 (direct manipulation)
  - **MODE D** - Flutter Patcher (APK merge, blutter, PP/ASM patching)
  - **MODE E** - Find Functions (ARM64 pattern search v2/v3)
  - **MODE F** - Manifest Patcher (license check removal, extractNativeLibs)

- **Terminal UI:** Curses-based with ANSI fallback, live logging, progress bar
- **Radare2 Integration:** Uses r2pipe for proper API access
- **Flutter Patcher:** APK merge, ARM64 extraction, blutter analysis, PP/ASM patching
- **Manifest Patcher:** License check removal, extractNativeLibs fix

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
- Java (for APK merge/manifest operations)

## Usage

```bash
# Interactive mode
shadowprotocol
python3 -m shadowprotocol

# Direct mode execution
shadowprotocol A    # Manual Assisted
shadowprotocol B    # Auto-Patching
shadowprotocol C    # Raw Radare2
shadowprotocol D    # Flutter Patcher
shadowprotocol E    # Find Functions
shadowprotocol F    # Manifest Patcher
```

## Project Structure

```
shadowprotocol/
  __init__.py          # Package init
  __main__.py          # Module entry point
  main.py              # ShadowProtocolApp + CLI
  ui.py                # CursesUI + ANSIUI
  modes.py             # BaseMode + ModeA-F + Radare2Handler
  logger.py            # Thread-safe logging
  target_selector.py   # .so file detection & selection
  validator.py         # Code & project validation
  theme.py             # ANSI colors, boxes, banners
  flutter/
    __init__.py        # Flutter subpackage init
    core.py            # Extraction, blutter, cleanup, APK ops
    patcher.py         # PP/ASM/false address patching
    manifest.py        # Manifest patching
    installer.py       # Termux auto-install
    find_functions.py  # ARM64 function finder (v2/v3)
  apk/
    __init__.py        # APK subpackage init
    editor.py          # APKEditor JAR operations
```

## License

MIT License - see LICENSE file for details.
