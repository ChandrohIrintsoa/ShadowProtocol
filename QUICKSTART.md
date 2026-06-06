# 🚀 QUICKSTART - ShadowProtocol v3.0

## 5 Minute Setup

### 1. Install System Dependencies
```bash
# Linux/Debian/Ubuntu
sudo apt update && sudo apt install radare2 python3 python3-pip

# macOS
brew install radare2 python3

# Termux
pkg install radare2 python3
```

### 2. Install Python Package
```bash
cd shadowprotocol
pip install .
```

### 3. Verify Installation
```bash
# Check everything is working
python3 -m py_compile shadowprotocol/*.py
echo "✅ All systems go!"
```

### 4. Start Application
```bash
shadowprotocol
```

### 5. First Run
1. Press `[1]` to select a target .so file
2. Press `[a]`, `[b]`, or `[c]` to start a mode
3. Press `[q]` to quit

---

## One-Liner Install (if you trust us)

```bash
pip install . && shadowprotocol
```

---

## Quick Commands

```bash
# Interactive mode
shadowprotocol

# Direct mode execution
shadowprotocol A  # MODE A
shadowprotocol B  # MODE B
shadowprotocol C  # MODE C

# Using Python module
python3 -m shadowprotocol

# Using script
./run.sh

# Using Make
make install && make run
```

---

## What You Need

- ✅ Python 3.7+
- ✅ Radare2 installed
- ✅ r2pipe Python package
- ✅ Linux/macOS/Termux
- ✅ Terminal (80x24 minimum)

---

## First Mode: Manual Patching (MODE A)

1. Start: `shadowprotocol`
2. Select: Press `[1]` → Choose .so file
3. Mode A: Press `[a]`
4. Follow: Prompts will guide you through
5. Success: Watch the progress bar fill

**Time**: ~5 seconds

---

## First Mode: Auto Patching (MODE B)

1. Start: `shadowprotocol`
2. Select: Press `[1]` → Choose .so file
3. Mode B: Press `[b]`
4. Auto: Scans binary automatically
5. Patches: All matches patched
6. Done: Results shown

**Time**: ~5-15 seconds (depends on binary)

---

## First Mode: Radare2 Shell (MODE C)

1. Start: `shadowprotocol`
2. Select: Press `[1]` → Choose .so file
3. Mode C: Press `[c]`
4. Shell: Type r2 commands
5. Exit: Type `q` to exit shell

**Example commands:**
```
r2> aaa           # Analyze
r2> pd @ 0x1000   # Disassemble
r2> wa "mov x0, 1"  # Write assembly
r2> q             # Quit
```

---

## Troubleshooting

### Error: "r2 command not found"
```bash
sudo apt install radare2
```

### Error: "No module named r2pipe"
```bash
pip install r2pipe
```

### Error: "curses" on Windows
```bash
pip install windows-curses
```

### UI looks weird
```bash
export TERM=xterm-256color
```

---

## Next Steps

1. Read **README.md** for full documentation
2. Read **INSTALL.md** for detailed setup
3. Read **USAGE.md** for detailed usage
4. Check **AUDIT_RAPPORT.md** for technical details

---

## Support

- All files have inline documentation
- Validation: `make validate`
- Syntax check: `python3 -m py_compile shadowprotocol/*.py`
- Logs: Watch the live output window

---

**That's it! You're ready to go! 🎉**

Press `shadowprotocol` and enjoy!
