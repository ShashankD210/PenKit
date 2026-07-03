#!/usr/bin/env bash
# PenKit — optional tool installer (Debian/Ubuntu)
# Run with: bash install_tools.sh
set -e

echo "[*] Updating package list..."
sudo apt-get update -qq

echo "[*] Installing Python tools..."
pip install wfuzz rich --break-system-packages -q

echo "[*] Installing Debian packages (sqlmap, etc.)..."
sudo apt-get install -y -qq sqlmap

echo "[*] Installing Go tools (requires Go)..."
if command -v go &>/dev/null; then
    go install github.com/ffuf/ffuf/v2@latest
    go install github.com/hahwul/dalfox/v2@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    echo "[+] Go tools installed to ~/go/bin/ — add to PATH if needed."
else
    echo "[!] Go not found. Install from https://go.dev/dl/ then re-run."
fi

echo ""
echo "[+] Done. Run 'penkit --status' to verify."
