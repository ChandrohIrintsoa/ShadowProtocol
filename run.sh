#!/bin/bash
# ShadowProtocol v4.0
export TERM=xterm-256color

# Verification Python 3.7+
if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)" 2>/dev/null; then
    echo "[!] Python 3.7+ requis"
    echo "    Trouve: $(python3 --version 2>&1)"
    exit 1
fi

# Verification Radare2
if ! command -v r2 &> /dev/null; then
    echo "[!] Radare2 non trouve"
    echo "    Linux:  sudo apt install radare2"
    echo "    Termux: pkg install radare2"
    echo "    macOS:  brew install radare2"
fi

echo "[+] ShadowProtocol v4.0 - Le Grimoire de Transmutation Binaire"
echo "[*] Python: $(python3 --version 2>&1)"
if command -v r2 &> /dev/null; then
    echo "[*] Radare2: $(r2 -v 2>&1 | head -1)"
fi
echo ""

python3 -m shadowprotocol "$@"
