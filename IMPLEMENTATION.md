# PenKit v1.0 — Implementation & Technical Documentation

> **Linux x86_64** | **Python 3.9+** | **Flask Web UI** | **Standalone Binaries**

---

## 1. Project Overview

PenKit is a unified penetration testing command builder that generates correct, ready-to-run commands for five security tools: **ffuf**, **sqlmap**, **dalfox**, **httpx**, and **wfuzz**. It eliminates manual flag memorization, reduces syntax errors, and adds anti-detection features like random User-Agent injection.

The project ships in two formats:

- **CLI Binary** (`penkit_linux_x86_64`) — Standalone 12MB Linux ELF executable. No Python required.
- **Web Application** (`penkit-web_linux_x86_64`) — Flask-based web UI on port 8080. Multi-user, browser-accessible command builder with live output, session history, and recon module.

Additionally, the source code can be run directly with `python3 penkit.py` or `python3 -m webapp`.

---

## 2. Directory Structure

```
penkit/
├── penkit.py                    # CLI entry — interactive mode, --tool, --history, --status
├── penkit_recon.py              # Recon API module — 14 OSINT endpoint wrappers
├── penkit_keys.py               # API key manager — env → config → prompt
├── penkit_bundle.spec           # PyInstaller spec for CLI binary
├── webapp_linux_x86_64.spec     # PyInstaller spec for web app binary
├── install_tools.sh             # Linux pentest tool installer (apt + go)
├── INSTALL.md                   # Installation guide
├── report.html                  # Standalone HTML audit report
│
├── penkit_linux_x86_64          # ⚡ Standalone CLI binary (12MB, no deps)
├── penkit-web_linux_x86_64      # 🌐 Standalone web app binary (12MB, no deps)
│
├── webapp/                      # Flask web application source
│   ├── __init__.py              # create_app(), Flask factory
│   ├── routes.py                # All HTTP routes (22 endpoints)
│   ├── utils.py                 # Shared helpers: tool status, history, random agents
│   ├── templates/
│   │   ├── base.html            # Layout shell — header, nav, footer, toast/modal JS
│   │   ├── index.html           # Dashboard — tool grid, history table, quick launch
│   │   ├── builder.html         # Per-tool command builder with anti-detection panel
│   │   ├── recon.html           # 14-module OSINT launch pad
│   │   └── keys.html            # API key CRUD + bulk upload + env export
│   └── static/                  # (reserved for custom CSS/JS)
│
├── __pycache__/                 # Compiled bytecode (auto-generated)
│
├── .git/                        # Git repository
└── IMPLEMENTATION.md            # This file
```

---

## 3. Architecture

### 3.1 Components

```
┌─────────────────────────────────────────────────────────────┐
│                     PenKit System                            │
├─────────────────────┬───────────────────────────────────────┤
│   penkit.py         │  CLI binary / direct Python          │
│   (penkit_linux_x86_64) │  Interactive REPL + non-interactive│
│                      │  flags: --tool, --history, --status  │
├─────────────────────┼───────────────────────────────────────┤
│   penkit_recon.py   │  Recon module (imported by CLI & web) │
│                      │  14 OSINT wrappers (urllib-based)     │
├─────────────────────┼───────────────────────────────────────┤
│   penkit_keys.py    │  Key resolution: env → ~/.penkit_config│
│                      │  → interactive prompt                  │
├─────────────────────┼───────────────────────────────────────┤
│   webapp/            │  Flask web UI (port 8080)             │
│                      │  Dashboard + 5 Builders + Recon + Keys│
│   (penkit-web_linux_x86_64) │                              │
└─────────────────────┴───────────────────────────────────────┘
```

### 3.2 Data Flow

```
User Input
    │
    ├── CLI mode ──→ penkit.py builders ──→ Command String ──→ Run / Dry-run / Copy
    │                                               │
    │                                          ~/.penkit_session.json (history)
    │
    └── Web mode ──→ Flask routes ──→ build_cmd() ──→ /generate API ──→ JSON response
                                      │
                                      └── apply_random_agent() ──→ UA injection
                                      │
                                      └── /run API ──→ subprocess ──→ live output
                                      │
                                      └── save_to_history() ──→ shared session file
```

### 3.3 Execution Model

- **CLI Binary**: Single-threaded REPL loop. One command at a time. Direct terminal I/O via Rich library.
- **Web App**: Multi-session Flask server. Each HTTP request is independent. Commands run in subprocess with 120s timeout. Output streamed back as JSON.

---

## 4. Module Details

### 4.1 penkit.py — CLI Command Builder

**Path:** `penkit.py`  
**Executable:** `penkit_linux_x86_64`  
**Entry point:** `cli_mode()` → `interactive_mode()` or `--tool` direct launch  
**Version:** 1.0.0

#### Core Functions

| Function | Description |
|----------|-------------|
| `cli_mode()` | argparse entry: `--tool`, `--history`, `--status`, `--version` |
| `interactive_mode()` | Rich REPL loop — tool grid, generate, run, dry-run, copy |
| `build_ffuf()` | ffuf command builder — URL, wordlist, method, threads, mc/fs/ext, headers, data, recursion, proxy, output |
| `build_sqlmap()` | sqlmap builder — URL, data, cookie, level/risk, dbms, threads, headers, proxy, dbs/tables/dump/os-shell, tor, batch, random-agent, tamper |
| `build_dalfox()` | dalfox builder — mode (url/pipe/file/sxss), target, cookie, header, data, worker, timeout, payload, blind XSS, proxy, waf-evasion, mining, output |
| `build_httpx()` | httpx builder — target/live URL, ports, threads, rate-limit, mc, proxy, sc/title/tech/ip/cl/cname/tls/follow/probe/silent/json, output |
| `build_wfuzz()` | wfuzz builder — dual wordlists, method, threads, hc/sc/hw/hl/hh filters, data, header, cookie, proxy, verbose, tor, output |
| `run_cmd()` | Executes command via `subprocess.run(shell=True)`, checks tool availability, handles KeyboardInterrupt |
| `save_session()` / `show_history()` | JSON session file (`~/.penkit_session.json`), max 50 entries |
| `check_tool()` | Checks if binary exists in PATH via `shutil.which()` |

#### Rich UI Features

- Banner with tool status table (found/missing indicators)
- Syntax-highlighted command panels with tool-specific colors
- Interactive prompts (`Prompt.ask`, `Confirm.ask`)
- Fallback console when `rich` is not installed
- Cross-platform clipboard copy (xclip / pbcopy / clip)

#### CLI Flags

```
--tool {ffuf,sqlmap,dalfox,httpx,wfuzz}   Launch specific builder
--history                                  Show session history (last 10)
--status                                   Check tool availability
--version                                  Show version info
-h, --help                                 Show help message
```

---

### 4.2 penkit_recon.py — OSINT Reconnaissance Module

**Path:** `penkit_recon.py`  
**Dependencies:** stdlib only (`urllib`, `json`, `base64`) + `penkit_keys`  
**HTTP Timeout:** 15 seconds per request

#### 14 Recon Modules

| # | Service | Function | Input | Output |
|---|---------|----------|-------|--------|
| 1 | Shodan | `shodan_host(ip)` | IP address | Open ports, CVE list, org, country, OS, last update |
| 2 | Shodan | `shodan_search(query, limit)` | Search query | IP, port, org, product, country per match |
| 3 | VirusTotal | `vt_url(url)` | URL | Malicious/suspicious/clean stats |
| 4 | VirusTotal | `vt_ip(ip)` | IP address | Reputation across engines |
| 5 | VirusTotal | `vt_hash(file_hash)` | MD5/SHA1/SHA256 | Detection ratio, first seen |
| 6 | SecurityTrails | `securitytrails_subdomains(domain)` | Domain | Subdomain list + FQDN |
| 7 | SecurityTrails | `securitytrails_dns(domain)` | Domain | Current DNS records (A, AAAA, MX, NS, TXT) |
| 8 | Censys | `censys_ip(ip)` | IP address | Services, ports, TLS certs |
| 9 | Hunter.io | `hunter_domain(domain)` | Domain | Email, type, confidence, name |
| 10 | Hunter.io | `hunter_verify(email)` | Email address | Valid/risky/invalid + score |
| 11 | HaveIBeenPwned | `hibp_account(email)` | Email address | Breach name, date, data classes |
| 12 | WhoisXML | `whoisxml_lookup(domain)` | Domain | Registrar, created/expires/updated dates, nameservers |
| 13 | BinaryEdge | `binaryedge_ip(ip)` | IP address | Ports, CVEs, exposed services |
| 14 | FullHunt | `fullhunt_domain(domain)` | Domain | Hosts, IPs, CDN, tags, attack surface |

#### HTTP Layer

- Uses `urllib.request` + `urllib.parse` (no external HTTP library)
- Error handling: `urllib.error.HTTPError` parsed for status code + body snippet
- All API keys resolved via `penkit_keys.get_key()`
- Stdlib-only — no extra dependencies

---

### 4.3 penkit_keys.py — API Key Manager

**Path:** `penkit_keys.py`  
**Config file:** `~/.penkit_config.json` (chmod 0600, owner-only)

#### Supported Services (10)

| Service | Env Variable | Env Name | Free Tier |
|---------|-------------|----------|-----------|
| Shodan | `SHODAN_API_KEY` | shodan | ✅ |
| VirusTotal | `VT_API_KEY` | virustotal | ✅ |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | securitytrails | ✅ |
| Censys | `CENSYS_API_ID` | censys | ✅ |
| Censys Secret | `CENSYS_API_SECRET` | censys_secret | ✅ |
| Hunter.io | `HUNTER_API_KEY` | hunter | ✅ |
| HaveIBeenPwned | `HIBP_API_KEY` | haveibeenpwned | ❌ Paid |
| WhoisXML | `WHOISXML_API_KEY` | whoisxml | ✅ |
| BinaryEdge | `BINARYEDGE_API_KEY` | binaryedge | ❌ Paid |
| FullHunt | `FULLHUNT_API_KEY` | fullhunt | ✅ |

#### Key Resolution Priority

1. **Environment variable** (highest)
2. **Config file** (`~/.penkit_config.json`)
3. **Interactive prompt** with password masking (fallback)

#### Public API

| Function | Description |
|----------|-------------|
| `get_key(service)` | Resolve key for a service. Returns `str` or `None`. |
| `show_key_status()` | Table view of all services and their key source. |
| `interactive_key_setup()` | Bulk walkthrough — set/update keys for all 10 services. |
| `delete_key(service)` | Remove a key from config file. |
| `export_env_snippet()` | Generate shell `export` block for `.bashrc`/`.zshrc`. |
| `generate_env_file()` | Write `.env.penkit` template to cwd. |
| `_load_config()` | Internal — read config file, return `api_keys` dict. |
| `_save_config(keys)` | Internal — atomic write + chmod 600. |

---

### 4.4 webapp/ — Flask Web Application

**Path:** `webapp/`  
**Executable:** `penkit-web_linux_x86_64`  
**Port:** 8080  
**Framework:** Flask 3.1.1  
**Templates:** Jinja2 (dark theme, responsive)

#### 4.4.1 Backend (routes.py — 22 endpoints)

| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| GET | `/` | `index()` | Dashboard — tool grid, history, quick launch |
| GET | `/status` | `status()` | JSON: tool availability (found/missing/path) |
| GET | `/history` | `history()` | JSON: session command history |
| POST | `/clear-history` | `clear_history()` | Clear all session history |
| GET | `/builder/<tool>` | `builder()` | Command builder page (ffuf/sqlmap/dalfox/httpx/wfuzz) |
| POST | `/generate` | `generate()` | Build command from form params + inject random UA |
| POST | `/run` | `run_command()` | Execute command (120s timeout) or dry-run |
| POST | `/copy` | `copy_cmd()` | Clipboard copy endpoint |
| GET | `/api/random-agent` | `random_agent()` | Return random User-Agent string |
| GET | `/recon` | `recon()` | Recon module landing page (14 module grid) |
| POST | `/api/recon/<service>` | `api_recon()` | Execute recon query against OSINT API |
| GET | `/keys` | `keys_page()` | API key management page |
| GET | `/api/keys/status` | `keys_status()` | JSON: key status for all 10 services |
| POST | `/api/keys/save` | `keys_save()` | Bulk save keys to config |
| POST | `/api/keys/delete` | `keys_delete()` | Delete keys from config |
| GET | `/api/keys/export` | `keys_export()` | Generate env export snippet |

#### 4.4.2 Anti-Detection (utils.py)

```python
apply_random_agent(cmd, tool)   # Injects random UA into any generated command
get_random_agent()              # Picks random UA from pool of 15 real browsers
get_random_ip()                 # Generates random IPv4 address
```

**UA Injection by Tool:**

| Tool | Method | Example Injected Flag |
|------|--------|----------------------|
| ffuf | `-H 'User-Agent: ...'` | Appends `-H` flag |
| wfuzz | `-H 'User-Agent: ...'` | Appends `-H` flag |
| httpx | `-H 'User-Agent: ...'` | Appends `-H` flag |
| sqlmap | `--headers='User-Agent: ...'` | Replaces or appends `--headers` |
| dalfox | `--header 'User-Agent: ...'` | Replaces or appends `--header` |

**User-Agent Pool (15 entries):**

- Chrome 124 on Windows, Mac, Linux
- Firefox 125 on Windows, Linux
- Safari 17.4 on MacOS, iOS
- Edge 124 on Windows, Mac
- Brave 1.64 on Windows
- Opera 110 on Linux
- Android Chrome 124

#### 4.4.3 Frontend (templates/)

**base.html** — Master layout
- Sticky header with logo + navigation (Dashboard, Builders, Recon, Keys, Live status)
- Dark theme with CSS variables: `#0d1117` primary bg, `#58a6ff` accent, `#3fb950` success, `#f85149` error
- Modal overlay, toast notifications, copy-to-clipboard
- Responsive grid/flex layouts

**index.html** — Dashboard
- 5 tool cards in responsive grid (click → builder)
- Session history table (auto-refresh, copy button, clear button)
- Quick launch sidebar with per-tool buttons
- 8 feature cards explaining capabilities
- Live status updates via AJAX

**builder.html** — Command Builder
- Dynamic form fields rendered per tool (16–18 fields each)
- Anti-detection panel (top-right): random UA toggle (default on), random IP toggle, live agent preview
- Generated command preview with syntax coloring
- Action buttons: Generate, Dry Run, Run, Copy
- Live output terminal (captures stdout + stderr, 120s timeout)
- Tool-specific field definitions in JS `toolFields` dict

**recon.html** — Recon Module
- 14 clickable module cards in grid
- Dynamic input form (IP / domain / URL / email / hash)
- Limit parameter for search queries
- Execute button → `/api/recon/<service>` → output display

**keys.html** — API Key Manager
- 10-service key status table (source: env/config/missing)
- Bulk key upload form (10 input fields)
- Individual delete buttons
- Export `.env` snippet button
- Masked key display (first 4 + last 4 characters)

---

## 5. Data Formats

### 5.1 Session File

**Path:** `~/.penkit_session.json`  
**Format:**
```json
[
  {
    "tool": "ffuf",
    "cmd": "ffuf -u 'https://target.com/FUZZ' -w 'wl.txt' -t 40 -mc 200,301,302,403 -H 'User-Agent: Mozilla/5.0...'",
    "timestamp": "2026-06-07T21:15:00"
  }
]
```
- Max entries: 50 (FIFO eviction)
- Shared between CLI and web app
- Auto-created on first command generation

### 5.2 Config File

**Path:** `~/.penkit_config.json`  
**Permissions:** `chmod 0600` (owner read/write only)  
**Format:**
```json
{
  "api_keys": {
    "shodan": "abcd1234...",
    "virustotal": "efgh5678..."
  }
}
```

### 5.3 HTTP API Responses

**Tool Status:**
```json
{
  "tools": [
    {"tool": "ffuf", "found": true, "path": "/usr/local/bin/ffuf", "color": "#00bcd4", "description": "..."}
  ]
}
```

**Generate Command:**
```json
{ "cmd": "ffuf -u 'https://target.com/FUZZ' -w 'wl.txt' ..." }
```

**Run Command (success):**
```json
{ "output": "...stdout + stderr...", "dry_run": false }
```

**Run Command (dry run):**
```json
{ "output": "[DRY RUN] Would execute:\nffuf ...", "dry_run": true }
```

**Random Agent:**
```json
{ "agent": "Mozilla/5.0 (Windows NT 10.0; ...)" }
```

---

## 6. Build Instructions

### 6.1 Prerequisites

```bash
# Virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Dependencies
pip install flask pyinstaller rich
```

### 6.2 Build CLI Binary

```bash
# Using spec file
pyinstaller penkit_bundle.spec

# Output: dist/penkit (12MB standalone Linux binary)
```

**Spec highlights:**
- Entry point: `penkit.py`
- Hidden imports: `penkit_keys`, `penkit_recon`, `rich.*`
- Data: none (rich handles its own data)
- Excludes: `tkinter`, `unittest`, `email`, `pdb`, `doctest`, `xml.etree`, `http`, `html`, `ossaudiodev`
- Console mode (terminal UI)

### 6.3 Build Web App Binary

```bash
pyinstaller webapp_linux_x86_64.spec

# Output: dist/penkit-web (12MB standalone Flask server)
```

**Spec highlights:**
- Entry point: `webapp/__init__.py`
- Hidden imports: `flask.*`, `penkit_keys`, `penkit_recon`, `rich.*`
- Bundled data: `webapp/templates/` (HTML), `webapp/static/` (CSS/JS)
- Embedded templates inside the binary

### 6.4 Run the Web App

**Option A — Binary:**
```bash
chmod +x penkit-web_linux_x86_64
./penkit-web_linux_x86_64
# Visit http://localhost:8080
```

**Option B — Source (from project root):**
```bash
python3 -m webapp
# or
flask --app webapp run --host 0.0.0.0 --port 8080
```

---

## 7. API Endpoints Reference

### 7.1 Page Routes

| Path | Method | Auth | Description |
|------|--------|------|-------------|
| `/` | GET | None | Dashboard |
| `/builder/ffuf` | GET | None | FFUF command builder |
| `/builder/sqlmap` | GET | None | SQLMap command builder |
| `/builder/dalfox` | GET | None | DALFOX command builder |
| `/builder/httpx` | GET | None | HTTPX command builder |
| `/builder/wfuzz` | GET | None | WFUZZ command builder |
| `/recon` | GET | None | Recon module selector |
| `/keys` | GET | None | API key management |

### 7.2 JSON API

| Path | Method | Auth | Description |
|------|--------|------|-------------|
| `/status` | GET | None | Tool availability |
| `/history` | GET | None | Session history |
| `/clear-history` | POST | None | Clear history |
| `/generate` | POST | None | Build command from params |
| `/run` | POST | None | Execute command (with UA injection) |
| `/copy` | POST | None | Copy to clipboard |
| `/api/random-agent` | GET | None | Random UA string |
| `/api/recon/<service>` | POST | None | Run OSINT query |
| `/api/keys/status` | GET | None | Key status (10 services) |
| `/api/keys/save` | POST | None | Bulk save keys |
| `/api/keys/delete` | POST | None | Delete keys |
| `/api/keys/export` | GET | None | Env export snippet |

---

## 8. Dependencies

### 8.1 CLI Binary

- **None** — Fully self-contained (Python 3.13 + stdlib + rich bundled via PyInstaller)

### 8.2 Web App Binary

- **None** — Flask + Jinja2 + rich + penkit modules bundled via PyInstaller

### 8.3 Source Mode

| Package | Purpose | Required |
|---------|---------|----------|
| `flask` | Web framework | Yes (web app) |
| `rich` | Terminal UI (tables, syntax, panels) | No (fallback console provided) |
| `pyinstaller` | Binary packaging | No (dev only) |

### 8.4 Security Tools (user-installed)

| Tool | Install Command | Purpose |
|------|----------------|---------|
| ffuf | `go install github.com/ffuf/ffuf/v2@latest` | Web path fuzzing |
| sqlmap | `apt install sqlmap` | SQL injection testing |
| dalfox | `go install github.com/hahwul/dalfox/v2@latest` | XSS scanning |
| httpx | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | HTTP probing |
| wfuzz | `pip install wfuzz` | Web fuzzing with filters |

---

## 9. Error Handling

- **Tool-not-found**: `shutil.which()` check before execution. Returns error JSON in web mode, console message in CLI.
- **Command timeout**: 120-second `subprocess.TimeoutExpired` catch → returns timeout message.
- **HTTP errors (recon)**: `urllib.error.HTTPError` caught — extracts status code + first 200 chars of error body.
- **Config file**: Parse failures silently return empty dict — app continues with missing keys.
- **KeyboardInterrupt**: Caught in all interactive loops (CLI REPL, web builder, key setup).
- **Clipboard**: Platform errors suppressed with user-friendly fallback message.
- **Generic exceptions**: All route handlers wrapped in try/except → return 500 with error message.
- **Rich import**: Graceful fallback to plain text console when `rich` is unavailable.

---

## 10. Security Considerations

- **API keys**: Never hardcoded. Resolved via env vars → encrypted config (`chmod 0600`) → masked interactive prompt.
- **Config file**: Owner-only permissions enforced on write (`os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)`).
- **No secrets in logs**: Keys never printed to console. Masked display shows first 4 + last 4 chars only.
- **Random User-Agent**: 15 real browser UA strings injected per command to reduce fingerprinting.
- **Command execution**: Tools run via `subprocess.run(shell=True)` with 120s timeout. Input validated (tool name in PATH check).
- **Binary packaging**: PyInstaller bundles all dependencies — no external network calls at runtime (except recon APIs and tool execution).
- **Session file**: Stored in `~` (user home) with default permissions. Contains commands only — no keys or credentials.

---

## 11. Build Artifacts

| File | Type | Size | Description |
|------|------|------|-------------|
| `penkit_linux_x86_64` | ELF binary | ~12MB | Standalone CLI — run `./penkit_linux_x86_64 --help` |
| `penkit-web_linux_x86_64` | ELF binary | ~12MB | Standalone web server — run `./penkit-web_linux_x86_64` |
| `penkit_bundle.spec` | PyInstaller spec | 1.3KB | Build spec for CLI binary |
| `webapp_linux_x86_64.spec` | PyInstaller spec | 1.6KB | Build spec for web app binary |

---

## 12. Testing Checklist

- [x] All `.py` files compile without syntax errors
- [x] `/` — Dashboard loads with tool status and history
- [x] `/status` — Returns JSON with all 5 tools
- [x] `/history` — Returns session history array
- [x] `/builder/{tool}` — All 5 builder pages render (200 OK)
- [x] `/generate` — Command generation with random UA injection
- [x] `/run` — Command execution with output capture
- [x] `/recon` — Recon landing page (14 modules)
- [x] `/keys` — Key management page with 10 services
- [x] `/api/keys/status` — Returns key status for all services
- [x] `/api/random-agent` — Returns random UA string
- [x] `penkit_linux_x86_64 --version` — Shows version
- [x] `penkit_linux_x86_64 --status` — All 5 tools FOUND
- [x] `penkit_keys.py` — Key manager compiles and imports

---

## 13. Version

**PenKit v1.0.0**  
**Date:** 2026-06-07  
**Python:** 3.13  
**Flask:** 3.1.1  
**Platform:** Linux x86_64  
