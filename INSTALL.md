# PenKit — Installation Guide

## Prerequisites

- Linux x86_64 (kernel 3.2+)
- Python 3.9+ (only needed if running from source)

---

## Option 1 — Standalone Binary (Recommended)

No Python or dependencies required.

```bash
# Make executable
chmod +x penkit_linux_x86_64

# Verify it works
./penkit_linux_x86_64 --version
./penkit_linux_x86_64 --status
```

> The binary bundles the CLI, recon module, key manager, and all runtime dependencies into a single 12MB ELF executable.

---

## Option 2 — From Source

### 2.1 Install dependencies

```bash
# Optional terminal UI library
pip install rich
```

### 2.2 Run

```bash
python3 penkit.py                    # Interactive mode
python3 penkit.py --tool ffuf        # Direct builder
python3 penkit.py --status           # Check tool availability
python3 penkit_recon.py              # Recon / OSINT menu
python3 penkit_keys.py               # API key management
```

---

## Required Pentest Tools

PenKit generates commands for these tools — install the ones you need:

| Tool    | Install |
|---------|---------|
| ffuf    | `go install github.com/ffuf/ffuf/v2@latest` |
| sqlmap  | `apt install sqlmap` or `git clone https://github.com/sqlmapproject/sqlmap` |
| dalfox  | `go install github.com/hahwul/dalfox/v2@latest` |
| httpx   | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| wfuzz   | `pip install wfuzz` |

Verify with:
```bash
penkit_linux_x86_64 --status
```

---

## Optional — Install All Tools

```bash
bash install_tools.sh
```

Requires `sudo`, `pip`, and Go.

---

## Building the Binary From Source

```bash
pip install pyinstaller
python3 -m pip install rich
pyinstaller penkit_bundle.spec
# Output: ./dist/penkit
```

---

## Config Files

| File | Purpose |
|------|---------|
| `~/.penkit_session.json` | Command history (auto-created, max 50 entries) |
| `~/.penkit_config.json` | API key storage (chmod 0600, owner-only) |

---

## Getting Started

```bash
# 1. Set API keys for recon features (optional)
python3 penkit_keys.py --setup

# 2. Or add env vars to ~/.bashrc
export SHODAN_API_KEY="your-key"
export VT_API_KEY="your-key"

# 3. Build commands
./penkit_linux_x86_64 --tool ffuf
```

---

## Uninstall

```bash
# Remove binary
rm penkit_linux_x86_64

# Remove config (optional)
rm ~/.penkit_session.json ~/.penkit_config.json
```
