#!/usr/bin/env python3
"""
PenKit - Unified Penetration Testing Command Builder
Supports: ffuf, sqlmap, dalfox, httpx, wfuzz
"""

import os
import sys
import subprocess
import shutil
import argparse
import json
import platform
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich.syntax import Syntax
    from rich import box
    
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# ──────────────────────────────────────────────
# Console setup
# ──────────────────────────────────────────────
if HAS_RICH:
    console = Console()
else:
    class FallbackConsole:
        def print(self, *a, **kw): print(*[str(x) for x in a])
        def rule(self, *a, **kw): print("─" * 60)
    console = FallbackConsole()

BANNER = """
[bold cyan]  ____            _  ___ _[/bold cyan]
[bold cyan] |  _ \\ ___ _ __ | |/ (_) |_[/bold cyan]
[bold cyan] | |_) / _ \\ '_ \\| ' /| | __|[/bold cyan]
[bold cyan] |  __/  __/ | | | . \\| | |_[/bold cyan]
[bold cyan] |_|   \\___|_| |_|\\_\\_|\\__|[/bold cyan]

[bold white]  Unified Pentest Command Builder[/bold white]
[dim]  ffuf · sqlmap · dalfox · httpx · wfuzz[/dim]
"""

SHORT_BANNER = """
[bold cyan]╔╦╗┌─┐┌┐┌┌─┐┌─┐[/bold cyan]
[bold cyan] ║ │ │││││ │├┤ [/bold cyan]
[bold cyan] ╩ └─┘┘└┘└─┘└─┘[/bold cyan]

[bold white] PenKit [/bold white][dim]v1.0.0[/dim]
"""

TOOLS = ["ffuf", "sqlmap", "dalfox", "httpx", "wfuzz"]

TOOL_DESCRIPTIONS = {
    "ffuf":    "Web fuzzer — directory, file, parameter, vhost brute-forcing",
    "sqlmap":  "SQL injection scanner & exploitation framework",
    "dalfox":  "XSS scanner with parameter mining & blind XSS support",
    "httpx":   "Fast HTTP toolkit — probing, tech detection, recon",
    "wfuzz":   "Web application fuzzer with advanced filtering",
}

TOOL_COLORS = {
    "ffuf":   "cyan",
    "sqlmap": "red",
    "dalfox": "yellow",
    "httpx":  "green",
    "wfuzz":  "magenta",
}

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def check_tool(name):
    return shutil.which(name) is not None

def run_cmd(cmd, dry_run=False):
    if HAS_RICH:
        console.print(Panel(SHORT_BANNER, border_style="cyan", padding=(0, 1), expand=False))
    else:
        console.print("\n=== PenKit v1.0.0 ===")
    console.print()
    if HAS_RICH:
        console.print(Panel(Syntax(cmd, "bash", theme="monokai"), title="[bold]Command[/bold]", border_style="dim"))
    else:
        console.print(f"[CMD] {cmd}")
    if dry_run:
        console.print("[yellow]Dry-run mode — command not executed.[/yellow]" if HAS_RICH else "DRY RUN — not executed.")
        return
    if not check_tool(cmd.split()[0]):
        console.print(f"[red]Tool '{cmd.split()[0]}' not found in PATH. Install it first.[/red]" if HAS_RICH else f"ERROR: {cmd.split()[0]} not found.")
        return
    try:
        subprocess.run(cmd, shell=True)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]" if HAS_RICH else "Interrupted.")

def ask(prompt, default="", password=False):
    if HAS_RICH:
        return Prompt.ask(f"  [cyan]{prompt}[/cyan]", default=default, password=password) or default
    val = input(f"  {prompt} [{default}]: ").strip()
    return val if val else default

def ask_bool(prompt, default=False):
    if HAS_RICH:
        return Confirm.ask(f"  [cyan]{prompt}[/cyan]", default=default)
    val = input(f"  {prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    if val == "": return default
    return val in ("y", "yes")

def section(title, color="bold white"):
    if HAS_RICH:
        console.rule(f"[{color}]{title}[/{color}]")
    else:
        console.print(f"\n{'─'*20} {title} {'─'*20}")

def show_tool_status():
    if HAS_RICH:
        table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold dim")
        table.add_column("Tool", style="bold", width=10)
        table.add_column("Description", width=50)
        table.add_column("Installed", width=12)
        for t in TOOLS:
            found = check_tool(t)
            status = "[green]✓  found[/green]" if found else "[red]✗  missing[/red]"
            table.add_row(f"[{TOOL_COLORS[t]}]{t}[/{TOOL_COLORS[t]}]", TOOL_DESCRIPTIONS[t], status)
        console.print(table)
    else:
        for t in TOOLS:
            status = "FOUND" if check_tool(t) else "MISSING"
            console.print(f"  {t:<10} {status}")

# ──────────────────────────────────────────────
# FFUF
# ──────────────────────────────────────────────

def build_ffuf(args=None):
    section("ffuf — Web Fuzzer", TOOL_COLORS["ffuf"])
    url      = ask("Target URL (use FUZZ keyword)", "https://target.com/FUZZ")
    wordlist = ask("Wordlist path", "/usr/share/wordlists/dirb/common.txt")
    method   = ask("HTTP method", "GET")
    threads  = ask("Threads", "40")
    mc       = ask("Match HTTP codes (comma-sep, blank=default)", "200,301,302,403")
    fs       = ask("Filter by response size (blank=none)", "")
    ext      = ask("File extensions to append (e.g. php,html)", "")
    headers  = ask("Extra headers (format: Name: Value; separate multiple with |)", "")
    data     = ask("POST data body (with FUZZ if needed, blank=none)", "")
    rec      = ask_bool("Enable recursion?", False)
    follow   = ask_bool("Follow redirects?", False)
    silent   = ask_bool("Silent mode?", False)
    output   = ask("Output file (blank=none)", "")
    proxy    = ask("Proxy (e.g. http://127.0.0.1:8080, blank=none)", "")

    parts = [f"ffuf -u '{url}' -w '{wordlist}'"]
    if method.upper() != "GET":
        parts.append(f"-X {method.upper()}")
    parts.append(f"-t {threads}")
    if mc:
        parts.append(f"-mc {mc}")
    if fs:
        parts.append(f"-fs {fs}")
    if ext:
        parts.append(f"-e {','.join(e.strip().lstrip('.') for e in ext.split(','))}")
    if headers:
        for h in headers.split("|"):
            h = h.strip()
            if h:
                parts.append(f"-H '{h}'")
    if data:
        parts.append(f"-d '{data}'")
    if rec:
        parts.append("-recursion")
    if follow:
        parts.append("-r")
    if silent:
        parts.append("-s")
    if proxy:
        parts.append(f"-x '{proxy}'")
    if output:
        parts.append(f"-o '{output}' -of json")

    return " \\\n  ".join(parts)

# ──────────────────────────────────────────────
# SQLMAP
# ──────────────────────────────────────────────

def build_sqlmap(args=None):
    section("sqlmap — SQL Injection", TOOL_COLORS["sqlmap"])
    url     = ask("Target URL (with param, e.g. ?id=1)", "https://target.com/page?id=1")
    data    = ask("POST data (blank=GET)", "")
    cookie  = ask("Cookie header value", "")
    level   = ask("Level (1-5)", "1")
    risk    = ask("Risk (1-3)", "1")
    dbms    = ask("Force DBMS (MySQL/PostgreSQL/Oracle/SQLite/MSSQL, blank=auto)", "")
    threads = ask("Threads (1-10)", "1")
    headers = ask("Extra headers (Name: Value, separate multiple with |)", "")
    proxy   = ask("Proxy (blank=none)", "")
    dbs     = ask_bool("Enumerate databases (--dbs)?", False)
    tables  = ask_bool("Enumerate tables (--tables)?", False)
    dump    = ask_bool("Dump database (--dump)?", False)
    os_sh   = ask_bool("Attempt OS shell (--os-shell)?", False)
    tor     = ask_bool("Use Tor (--tor)?", False)
    batch   = ask_bool("Batch mode — no user prompts (--batch)?", True)
    rand_ua = ask_bool("Random user-agent (--random-agent)?", True)
    tamper  = ask("Tamper scripts (comma-sep, blank=none, e.g. space2comment)", "")

    parts = [f"sqlmap -u '{url}'"]
    if data:
        parts.append(f"--data='{data}'")
    if cookie:
        parts.append(f"--cookie='{cookie}'")
    parts.append(f"--level={level}")
    parts.append(f"--risk={risk}")
    if dbms:
        parts.append(f"--dbms={dbms}")
    if int(threads) > 1:
        parts.append(f"--threads={threads}")
    if headers:
        for h in headers.split("|"):
            h = h.strip()
            if h:
                parts.append(f"-H '{h}'")
    if proxy:
        parts.append(f"--proxy='{proxy}'")
    if rand_ua:
        parts.append("--random-agent")
    if batch:
        parts.append("--batch")
    if tamper:
        parts.append(f"--tamper='{tamper}'")
    if dbs:
        parts.append("--dbs")
    if tables:
        parts.append("--tables")
    if dump:
        parts.append("--dump")
    if os_sh:
        parts.append("--os-shell")
    if tor:
        parts.append("--tor --tor-type=SOCKS5")

    return " \\\n  ".join(parts)

# ──────────────────────────────────────────────
# DALFOX
# ──────────────────────────────────────────────

def build_dalfox(args=None):
    section("dalfox — XSS Scanner", TOOL_COLORS["dalfox"])
    mode    = ask("Mode (url/pipe/file/sxss)", "url")
    target  = ask("Target URL", "https://target.com/search?q=test")
    cookie  = ask("Cookie", "")
    header  = ask("Custom header (Name: Value, blank=none)", "")
    data    = ask("POST data (blank=GET)", "")
    worker  = ask("Worker threads", "100")
    timeout = ask("Timeout (seconds)", "10")
    payload = ask("Custom payload file path (blank=none)", "")
    blind   = ask("Blind XSS callback URL (blank=disable)", "")
    proxy   = ask("Proxy (blank=none)", "")
    waf     = ask_bool("Enable WAF evasion?", False)
    mining  = ask_bool("Mine parameters from URL?", False)
    follow  = ask_bool("Follow redirects?", False)
    skip    = ask_bool("Skip BAV (basic auth verification)?", False)
    json_out= ask_bool("JSON output?", False)
    output  = ask("Output file (blank=none)", "")

    parts = [f"dalfox {mode} '{target}'"]
    if cookie:
        parts.append(f"--cookie '{cookie}'")
    if header:
        parts.append(f"--header '{header}'")
    if data:
        parts.append(f"--data '{data}'")
    parts.append(f"--worker {worker}")
    parts.append(f"--timeout {timeout}")
    if payload:
        parts.append(f"--custom-payload '{payload}'")
    if blind:
        parts.append(f"--blind '{blind}'")
    if proxy:
        parts.append(f"--proxy '{proxy}'")
    if waf:
        parts.append("--waf-evasion")
    if mining:
        parts.append("--mining-parameters")
    if follow:
        parts.append("--follow-redirects")
    if skip:
        parts.append("--skip-bav")
    if json_out:
        parts.append("--format json")
    if output:
        parts.append(f"--output '{output}'")

    return " \\\n  ".join(parts)

# ──────────────────────────────────────────────
# HTTPX
# ──────────────────────────────────────────────

def build_httpx(args=None):
    section("httpx — HTTP Toolkit / IP Scanner", TOOL_COLORS["httpx"])
    target  = ask("Target file, single URL, or IP (e.g. 192.168.1.1)", "targets.txt")
    ports   = ask("Ports to probe (comma-sep, blank=default)", "80,443")
    threads = ask("Threads", "50")
    rate    = ask("Rate limit req/s (0=unlimited)", "0")
    mc      = ask("Match status codes (blank=all)", "")
    output  = ask("Output file (blank=none)", "")
    proxy   = ask("Proxy (blank=none)", "")
    sc      = ask_bool("Show status code?", True)
    title   = ask_bool("Show page title?", True)
    tech    = ask_bool("Technology detection? (recommended for CVE lookup)", True)
    ip      = ask_bool("Show IP address?", True)
    cl      = ask_bool("Show content length?", False)
    cname   = ask_bool("Show CNAME?", False)
    tls     = ask_bool("TLS info?", False)
    follow  = ask_bool("Follow redirects?", False)
    probe   = ask_bool("Show probe status?", False)
    silent  = ask_bool("Silent mode?", False)
    json_out= ask_bool("JSON output lines?", False)
    cve_lookup = ask_bool("Lookup CVEs for detected technologies? (requires NVD API key)", False)

    is_file = not target.startswith("http") and "." not in target.split("/")[0] if "/" in target else not target.startswith("http")
    is_ip = all(part.isdigit() for part in target.split(".")) if "." in target else False
    if is_ip:
        is_file = False
    parts = [f"httpx {'-l' if is_file else '-u'} '{target}'"]
    if ports:
        parts.append(f"-p {ports}")
    parts.append(f"-t {threads}")
    if int(rate) > 0:
        parts.append(f"-rl {rate}")
    if mc: parts.append(f"-mc {mc}")
    if proxy: parts.append(f"-http-proxy '{proxy}'")
    if sc:   parts.append("-sc")
    if title: parts.append("-title")
    if tech:  parts.append("-tech-detect")
    if ip:    parts.append("-ip")
    if cl:    parts.append("-cl")
    if cname: parts.append("-cname")
    if tls:   parts.append("-tls-probe")
    if follow: parts.append("-follow-redirects")
    if probe: parts.append("-probe")
    if silent: parts.append("-silent")
    if json_out: parts.append("-json")
    if output:
        parts.append(f"-o '{output}'")

    cmd = " \\\n  ".join(parts)
    
    if cve_lookup:
        cmd += f" \\\n  # Post-scan: python3 penkit_vuln.py --url '{target}'"
    
    return cmd

# ──────────────────────────────────────────────
# WFUZZ
# ──────────────────────────────────────────────

def build_wfuzz(args=None):
    section("wfuzz — Web Fuzzer", TOOL_COLORS["wfuzz"])
    url     = ask("Target URL (use FUZZ / FUZ2Z etc.)", "https://target.com/FUZZ")
    wl      = ask("Wordlist path (-w)", "/usr/share/wordlists/dirb/common.txt")
    wl2     = ask("Second wordlist for FUZ2Z (blank=none)", "")
    method  = ask("HTTP method", "GET")
    threads = ask("Threads", "10")
    hc      = ask("Hide HTTP codes (comma-sep, e.g. 404,400)", "404")
    sc      = ask("Show only these codes (blank=all)", "")
    hw      = ask("Hide by word count (blank=none)", "")
    hl      = ask("Hide by line count (blank=none)", "")
    hh      = ask("Hide by char count (blank=none)", "")
    data    = ask("POST data (blank=GET)", "")
    header  = ask("Custom header (Name: Value, blank=none)", "")
    cookie  = ask("Cookie (blank=none)", "")
    proxy   = ask("Proxy (blank=none)", "")
    verbose = ask_bool("Verbose output?", False)
    color   = ask_bool("Colorized output?", True)
    tor     = ask_bool("Route through Tor?", False)
    output  = ask("Output file (blank=none)", "")

    parts = [f"wfuzz -w '{wl}'"]
    if wl2:
        parts.append(f"-w '{wl2}'")
    parts.append(f"-t {threads}")
    if hc:  parts.append(f"--hc {hc}")
    if sc:  parts.append(f"--sc {sc}")
    if hw:  parts.append(f"--hw {hw}")
    if hl:  parts.append(f"--hl {hl}")
    if hh:  parts.append(f"--hh {hh}")
    if method.upper() != "GET":
        parts.append(f"-X {method.upper()}")
    if data:
        parts.append(f"-d '{data}'")
    if header:
        parts.append(f"-H '{header}'")
    if cookie:
        parts.append(f"-b '{cookie}'")
    if tor:
        parts.append("-p socks5://127.0.0.1:9050")
    elif proxy:
        parts.append(f"-p '{proxy}'")
    if verbose:
        parts.append("-v")
    if color:
        parts.append("--color")
    if output:
        parts.append(f"-f '{output},html'")

    parts.append(f"'{url}'")
    return " \\\n  ".join(parts)

# ──────────────────────────────────────────────
# Command-line non-interactive mode
# ──────────────────────────────────────────────

QUICK_BUILDERS = {
    "ffuf":   build_ffuf,
    "sqlmap": build_sqlmap,
    "dalfox": build_dalfox,
    "httpx":  build_httpx,
    "wfuzz":  build_wfuzz,
}

# ──────────────────────────────────────────────
# Save / Load session
# ──────────────────────────────────────────────

SESSION_FILE = os.path.join(os.path.expanduser("~"), ".penkit_session.json")

def save_session(tool, cmd):
    sessions = []
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE) as f:
                sessions = json.load(f)
        except Exception:
            sessions = []
    sessions.append({
        "tool": tool,
        "cmd": cmd,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    })
    sessions = sessions[-50:]  # keep last 50
    with open(SESSION_FILE, "w") as f:
        json.dump(sessions, f, indent=2)

def show_history():
    if not os.path.exists(SESSION_FILE):
        console.print("No session history found.")
        return
    with open(SESSION_FILE) as f:
        sessions = json.load(f)
    if not sessions:
        console.print("History is empty.")
        return
    if HAS_RICH:
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
        table.add_column("#", width=4)
        table.add_column("Tool", width=10)
        table.add_column("Time", width=22)
        table.add_column("Command preview", width=60)
        for i, s in enumerate(reversed(sessions[-15:]), 1):
            preview = s["cmd"].replace("\n", " ").replace("  ", " ")[:80]
            table.add_row(str(i), f"[{TOOL_COLORS.get(s['tool'],'white')}]{s['tool']}[/{TOOL_COLORS.get(s['tool'],'white')}]", s["timestamp"], preview)
        console.print(table)
    else:
        for s in reversed(sessions[-10:]):
            console.print(f"[{s['timestamp']}] {s['tool']}: {s['cmd'][:80]}")

# ──────────────────────────────────────────────
# Main interactive loop
# ──────────────────────────────────────────────

def interactive_mode():
    if HAS_RICH:
        console.print(Panel(BANNER, border_style="dim", padding=(0, 2)))
    else:
        console.print(BANNER)

    console.print()
    show_tool_status()
    console.print()
    console.print("[dim]Type a tool number or name. Commands: vuln | history | status | quit[/dim]\n" if HAS_RICH else "Type tool name or number. Commands: vuln | history | status | quit")

    menu_items = {str(i+1): t for i, t in enumerate(TOOLS)}

    while True:
        console.print()
        if HAS_RICH:
            choices_str = "  ".join(
                f"[{TOOL_COLORS[t]}][bold]{i}[/bold] {t}[/{TOOL_COLORS[t]}]"
                for i, t in menu_items.items()
            )
            console.print(choices_str)
            choice = Prompt.ask("\n  [bold]Select tool[/bold]  [dim](or 'vuln' for CVE scan)[/dim]").strip().lower()
        else:
            for i, t in menu_items.items():
                console.print(f"  {i}) {t}")
            choice = input("\n  Select tool (or 'vuln' for CVE scan): ").strip().lower()

        if choice in ("q", "quit", "exit"):
            console.print("Bye!\n")
            break
        elif choice in ("vuln", "cve", "v"):
            try:
                from penkit_vuln import vuln_mode
                vuln_mode()
            except ImportError:
                console.print("[red]penkit_vuln module not found.[/red]" if HAS_RICH else "penkit_vuln module not found.")
            except KeyboardInterrupt:
                pass
            continue
        elif choice in ("history", "h"):
            show_history()
            continue
        elif choice in ("status", "s"):
            show_tool_status()
            continue
        elif choice in ("help", "?"):
            console.print("  Enter a tool name or number 1-5. Type 'vuln' for URL/IP CVE scanning, 'history' to see past commands, 'status' to recheck installed tools.")
            continue

        tool = None
        if choice in menu_items:
            tool = menu_items[choice]
        elif choice in TOOLS:
            tool = choice

        if not tool:
            console.print("[red]Unknown option. Try a tool name, number 1-5, 'vuln', or 'help'.[/red]" if HAS_RICH else "Unknown option.")
            continue

        try:
            cmd = QUICK_BUILDERS[tool]()
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled.[/yellow]" if HAS_RICH else "Cancelled.")
            continue

        console.print()
        if HAS_RICH:
            console.print(Panel(Syntax(cmd, "bash", theme="monokai", word_wrap=True), title=f"[bold {TOOL_COLORS[tool]}]Generated {tool} command[/bold {TOOL_COLORS[tool]}]", border_style=TOOL_COLORS[tool]))
        else:
            console.print(f"\n--- Command ---\n{cmd}\n")

        save_session(tool, cmd)

        if HAS_RICH:
            action = Prompt.ask("  Action", choices=["run", "dryrun", "copy", "vuln", "skip"], default="skip")
        else:
            action = input("  Action [run/dryrun/copy/vuln/skip]: ").strip().lower() or "skip"

        if action == "run":
            run_cmd(cmd)
        elif action == "dryrun":
            run_cmd(cmd, dry_run=True)
        elif action == "copy":
            try:
                import subprocess as sp
                plat = platform.system()
                if plat == "Linux":
                    sp.run(["xclip", "-selection", "clipboard"], input=cmd.encode(), check=False)
                elif plat == "Darwin":
                    sp.run(["pbcopy"], input=cmd.encode(), check=False)
                elif plat == "Windows":
                    sp.run(["clip"], input=cmd.encode(), check=False)
                console.print("[green]Copied to clipboard.[/green]" if HAS_RICH else "Copied.")
            except Exception:
                console.print("[yellow]Clipboard unavailable. Copy manually from above.[/yellow]" if HAS_RICH else "Clipboard unavailable.")
        elif action == "vuln":
            try:
                from penkit_vuln import vuln_mode
                vuln_mode()
            except ImportError:
                console.print("[red]penkit_vuln module not found.[/red]" if HAS_RICH else "penkit_vuln module not found.")

# ──────────────────────────────────────────────
# CLI argument mode
# ──────────────────────────────────────────────

def cli_mode():
    parser = argparse.ArgumentParser(
        prog="penkit",
        description="PenKit — Unified Pentest Command Builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  penkit                    Launch interactive mode
  penkit --tool ffuf        Build an ffuf command interactively
  penkit --history          Show command history
  penkit --status           Check tool availability
  penkit --version          Show version info
        """
    )
    parser.add_argument("--tool", choices=TOOLS, help="Launch directly into a specific tool builder")
    parser.add_argument("--history", action="store_true", help="Show command history")
    parser.add_argument("--status", action="store_true", help="Check tool availability")
    parser.add_argument("--version", action="store_true", help="Show version")
    args = parser.parse_args()

    if args.version:
        if HAS_RICH:
            console.print(Panel(SHORT_BANNER, border_style="cyan", padding=(0, 1), expand=False))
        else:
            console.print("\n=== PenKit v1.0.0 ===\n")
        console.print("PenKit v1.0.0  |  Python " + sys.version.split()[0])
        return
    if args.status:
        if HAS_RICH:
            console.print(Panel(SHORT_BANNER, border_style="cyan", padding=(0, 1), expand=False))
        else:
            console.print("\n=== PenKit v1.0.0 ===\n")
        show_tool_status()
        return
    if args.history:
        if HAS_RICH:
            console.print(Panel(SHORT_BANNER, border_style="cyan", padding=(0, 1), expand=False))
        else:
            console.print("\n=== PenKit v1.0.0 ===\n")
        show_history()
        return
    if args.tool:
        if HAS_RICH:
            console.print(Panel(SHORT_BANNER, border_style="cyan", padding=(0, 1), expand=False))
        else:
            console.print("\n=== PenKit v1.0.0 ===\n")
        try:
            cmd = QUICK_BUILDERS[args.tool]()
            if HAS_RICH:
                console.print(Panel(Syntax(cmd, "bash", theme="monokai", word_wrap=True), title=f"[bold]Generated command — {args.tool}[/bold]"))
            else:
                console.print(cmd)
            save_session(args.tool, cmd)
        except KeyboardInterrupt:
            console.print("\nCancelled.")
        return

    interactive_mode()

# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    cli_mode()
