#!/bin/bash
# ShadowProtocol v3.0 - Launch Script
# Compatible with Linux, macOS, and Termux

# Set terminal mode for proper color support
export TERM=xterm-256color

# Check Python version (3.7+)
if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)" 2>/dev/null; then
    echo "[!] Python 3.7+ required"
    echo "    Found: $(python3 --version 2>&1)"
    exit 1
fi

# Check Radare2
if ! command -v r2 &> /dev/null; then
    echo "[!] Radare2 not found"
    echo "    Install: sudo apt install radare2"
    echo "    Termux:  pkg install radare2"
fi

echo "[+] Running ShadowProtocol v3.0..."
echo "[*] Python: $(python3 --version 2>&1)"
if command -v r2 &> /dev/null; then
    echo "[*] Radare2: $(r2 -v 2>&1 | head -1)"
fi
echo ""

# Run as Python module (supports both installed and local)
python3 -m shadowprotocol "$@"
