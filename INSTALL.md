# 📦 Installation Guide - ShadowProtocol v3.0

## Quick Start (3 steps)

### 1. Install System Dependencies

**Linux/Debian/Ubuntu:**
```bash
sudo apt update
sudo apt install radare2 python3 python3-pip
```

**Fedora/RHEL:**
```bash
sudo dnf install radare2 python3 python3-pip
```

**macOS:**
```bash
brew install radare2 python3
```

**Termux (Android):**
```bash
pkg install radare2 python3
pip install --upgrade pip
```

### 2. Install Python Package

**From source:**
```bash
cd shadowprotocol-v3.0
pip install .
```

**Development mode:**
```bash
pip install -e .
```

**Using requirements.txt:**
```bash
pip install -r requirements.txt
```

### 3. Verify Installation

```bash
# Check Python version
python3 --version  # Should be 3.7+

# Check Radare2
r2 -v

# Check r2pipe
python3 -c "import r2pipe; print('r2pipe OK')"

# Run application
shadowprotocol
```

---

## Alternative Methods

### Using Make

```bash
# Install
make install

# Run
make run

# Validate
make validate
```

### Using run.sh

```bash
chmod +x run.sh
./run.sh          # Interactive
./run.sh A        # MODE A
./run.sh B        # MODE B
./run.sh C        # MODE C
```

### Python Module

```bash
python3 -m shadowprotocol           # Interactive
python3 -m shadowprotocol A         # MODE A
python3 -m shadowprotocol B         # MODE B
python3 -m shadowprotocol C         # MODE C
```

---

## System Requirements

| Component | Requirement | Version |
|-----------|------------|---------|
| Python | Required | 3.7+ |
| Radare2 | Required | Recent |
| r2pipe | Required | >=1.6.0 |
| curses | Stdlib | Built-in |
| OS | POSIX-based | Linux/macOS/Termux |
| RAM | Minimum | 256 MB |
| Disk | Minimum | 50 MB |

---

## Supported Platforms

| Platform | Status | Note |
|----------|--------|------|
| Ubuntu/Debian | ✅ | Full support |
| Fedora/RHEL | ✅ | Full support |
| macOS | ✅ | Full support |
| Termux | ✅ | Full support |
| Windows | ⚠️ | Use WSL2 or windows-curses |
| Alpine Linux | ⚠️ | May require musl libs |

---

## Troubleshooting

### Issue: "r2 command not found"

**Solution:**
```bash
# Verify installation
which r2

# If not found:
sudo apt install radare2

# Or build from source:
git clone https://github.com/radareorg/radare2.git
cd radare2
sys/install.sh
```

### Issue: "r2pipe module not found"

**Solution:**
```bash
pip install r2pipe

# Or upgrade if outdated:
pip install --upgrade r2pipe

# Verify:
python3 -c "import r2pipe; print(r2pipe.version)"
```

### Issue: "curses error" on macOS

**Solution:**
```bash
# Usually curses is pre-installed
# If issues, reinstall Python:
brew install python-tk@3.9

# Or use system Python:
/usr/bin/python3 -m shadowprotocol
```

### Issue: "Permission denied" on run.sh

**Solution:**
```bash
chmod +x run.sh
chmod +x shadowprotocol
```

### Issue: Terminal display issues

**Solutions:**
1. Set terminal mode:
   ```bash
   export TERM=xterm-256color
   ```

2. Use script directly:
   ```bash
   python3 -m shadowprotocol
   ```

3. Try ANSI fallback (automatic if curses fails)

### Issue: "No module named shadowprotocol"

**Solutions:**
```bash
# 1. Reinstall package
pip uninstall shadowprotocol
pip install .

# 2. Check PYTHONPATH
echo $PYTHONPATH

# 3. Use direct module
python3 -m shadowprotocol
```

---

## Development Installation

For developers who want to modify code:

```bash
# Clone repository (if Git)
git clone <repo-url>
cd shadowprotocol

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install in editable mode
pip install -e .

# Install dev dependencies (optional)
pip install pytest pylint

# Run tests
make validate

# Run application
shadowprotocol
```

---

## Docker Installation

For isolated environment:

```bash
docker run -it \
  --volume /path/to/binaries:/binaries \
  ubuntu:22.04 bash

apt update && apt install -y radare2 python3 python3-pip
pip install shadowprotocol
```

---

## Post-Installation

### Create Configuration (Optional)

```bash
mkdir -p ~/.config/shadowprotocol
cat > ~/.config/shadowprotocol/config.ini << EOF
[general]
default_target=/path/to/default.so
enable_logging=true
log_file=~/.config/shadowprotocol/shadowprotocol.log
EOF
```

### Add to PATH

```bash
# If installed with --user flag:
export PATH=$PATH:~/.local/bin

# Add to ~/.bashrc or ~/.zshrc:
echo 'export PATH=$PATH:~/.local/bin' >> ~/.bashrc
source ~/.bashrc
```

### Verify Installation

```bash
# All these should work:
shadowprotocol --help
shadowprotocol
python3 -m shadowprotocol
./run.sh
```

---

## Uninstallation

```bash
# Using pip
pip uninstall shadowprotocol

# Clean cache
rm -rf ~/.cache/pip/shadowprotocol*

# Remove config (optional)
rm -rf ~/.config/shadowprotocol
```

---

## Getting Help

1. **Check logs**: `shadowprotocol.log`
2. **Validate**: `make validate`
3. **Test imports**: `python3 -c "import shadowprotocol; print('OK')"`
4. **Run in debug**: Add logging statements to main.py

---

## Next Steps

After installation:

1. Run `shadowprotocol` to start interactive mode
2. Select a target .so file (option [1])
3. Choose a mode:
   - [a] MODE A - Manual offset patching
   - [b] MODE B - Automatic scan & patch
   - [c] MODE C - Raw Radare2 shell
4. Press [q] to quit at any time

---

**Installation Guide v3.0**  
Last Updated: 2024
