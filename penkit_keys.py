"""
PenKit — API Key Manager
Loads keys from three sources in priority order:
  1. Environment variables  (highest priority)
  2. Config file (~/.penkit_config.json)
  3. Interactive prompt      (fallback)
"""

import os
import json
import stat
import getpass
from pathlib import Path

try:
    from rich.console import Console
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    class _C:
        def print(self, *a, **kw): print(*[str(x) for x in a])
    console = _C()

BANNER = """
[bold cyan]  ____            _  ___ _[/bold cyan]
[bold cyan] |  _ \\ ___ _ __ | |/ (_) |_[/bold cyan]
[bold cyan] | |_) / _ \\ '_ \\| ' /| | __|[/bold cyan]
[bold cyan] |  __/  __/ | | | . \\| | |_[/bold cyan]
[bold cyan] |_|   \\___|_| |_|\\_\\_|\\__|[/bold cyan]

[bold white]  API Key Manager[/bold white]
[dim]  Store keys securely, use them everywhere[/dim]
"""

CONFIG_PATH = Path.home() / ".penkit_config.json"

# ── Supported services ────────────────────────────────────────────────────────

SERVICES = {
    "shodan": {
        "label":   "Shodan",
        "env":     "SHODAN_API_KEY",
        "url":     "https://account.shodan.io",
        "use":     "Internet-wide host/port/banner scanning",
        "free":    True,
    },
    "virustotal": {
        "label":   "VirusTotal",
        "env":     "VT_API_KEY",
        "url":     "https://www.virustotal.com/gui/join-us",
        "use":     "URL, IP, hash, and file reputation",
        "free":    True,
    },
    "securitytrails": {
        "label":   "SecurityTrails",
        "env":     "SECURITYTRAILS_API_KEY",
        "url":     "https://securitytrails.com/app/signup",
        "use":     "DNS history, subdomains, WHOIS",
        "free":    True,
    },
    "censys": {
        "label":   "Censys",
        "env":     "CENSYS_API_ID",
        "url":     "https://app.censys.io/register",
        "use":     "Internet scan data — hosts, certs, services",
        "free":    True,
    },
    "censys_secret": {
        "label":   "Censys API Secret",
        "env":     "CENSYS_API_SECRET",
        "url":     "https://app.censys.io/account/api",
        "use":     "Required alongside Censys API ID",
        "free":    True,
    },
    "hunter": {
        "label":   "Hunter.io",
        "env":     "HUNTER_API_KEY",
        "url":     "https://hunter.io/users/sign_up",
        "use":     "Email discovery and verification",
        "free":    True,
    },
    "haveibeenpwned": {
        "label":   "HaveIBeenPwned",
        "env":     "HIBP_API_KEY",
        "url":     "https://haveibeenpwned.com/API/Key",
        "use":     "Breach and paste lookup for email addresses",
        "free":    False,
    },
    "whoisxml": {
        "label":   "WhoisXML API",
        "env":     "WHOISXML_API_KEY",
        "url":     "https://www.whoisxmlapi.com/signup.php",
        "use":     "Domain WHOIS, DNS, IP geolocation",
        "free":    True,
    },
    "binaryedge": {
        "label":   "BinaryEdge",
        "env":     "BINARYEDGE_API_KEY",
        "url":     "https://www.binaryedge.io/pricing.html",
        "use":     "Internet scan — ports, vulns, exposed services",
        "free":    False,
    },
    "fullhunt": {
        "label":   "FullHunt",
        "env":     "FULLHUNT_API_KEY",
        "url":     "https://fullhunt.io/register",
        "use":     "Attack surface and subdomain enumeration",
        "free":    True,
    },
    "nvd": {
        "label":   "NVD (National Vulnerability Database)",
        "env":     "NVD_API_KEY",
        "url":     "https://nvd.nist.gov/developers/request-an-api-key",
        "use":     "CVE lookup by keyword, CPE, or product",
        "free":    True,
    },
}

# ── Config file I/O ───────────────────────────────────────────────────────────

def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f).get("api_keys", {})
    except Exception:
        return {}

def _save_config(keys: dict):
    existing = {}
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                existing = json.load(f)
        except Exception:
            pass
    existing["api_keys"] = keys
    with open(CONFIG_PATH, "w") as f:
        json.dump(existing, f, indent=2)
    # Restrict file permissions to owner-only on Unix
    try:
        os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass

# ── Key resolution (env → config → prompt) ───────────────────────────────────

def get_key(service: str, prompt_if_missing: bool = True, save_if_prompted: bool = True) -> str | None:
    """
    Return the API key for a service.
    Priority: env var → config file → interactive prompt.
    Returns None if not found and prompting is disabled.
    """
    meta = SERVICES.get(service)
    if not meta:
        return None

    # 1. Environment variable
    env_val = os.environ.get(meta["env"], "").strip()
    if env_val:
        return env_val

    # 2. Config file
    cfg = _load_config()
    cfg_val = cfg.get(service, "").strip()
    if cfg_val:
        return cfg_val

    # 3. Interactive prompt
    if not prompt_if_missing:
        return None

    if HAS_RICH:
        console.print(f"\n  [yellow]No key found for [bold]{meta['label']}[/bold].[/yellow]")
        console.print(f"  [dim]Get one free at: {meta['url']}[/dim]")
        val = Prompt.ask(f"  Enter your {meta['label']} API key (blank to skip)", default="", password=True)
    else:
        print(f"\n  No key for {meta['label']}. Get one at: {meta['url']}")
        val = getpass.getpass(f"  {meta['label']} API key (blank to skip): ").strip()

    if not val:
        return None

    if save_if_prompted:
        cfg[service] = val
        _save_config(cfg)
        console.print(f"  [green]Key saved to {CONFIG_PATH}[/green]" if HAS_RICH else f"  Saved to {CONFIG_PATH}")

    return val

# ── Bulk key management ───────────────────────────────────────────────────────

def show_key_status():
    cfg = _load_config()
    if HAS_RICH:
        table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold dim")
        table.add_column("Service",     style="bold", width=18)
        table.add_column("Use case",    width=38)
        table.add_column("Env var",     width=22, style="dim")
        table.add_column("Status",      width=16)
        table.add_column("Free tier",   width=10)
        for svc, meta in SERVICES.items():
            env_val = os.environ.get(meta["env"], "")
            cfg_val = cfg.get(svc, "")
            if env_val:
                status = "[cyan]● env var[/cyan]"
            elif cfg_val:
                status = "[green]● config[/green]"
            else:
                status = "[red]✗  missing[/red]"
            free = "[green]Yes[/green]" if meta["free"] else "[yellow]Paid[/yellow]"
            table.add_row(meta["label"], meta["use"], meta["env"], status, free)
        console.print(table)
    else:
        for svc, meta in SERVICES.items():
            env_val = os.environ.get(meta["env"], "")
            cfg_val = cfg.get(svc, "")
            status = "env" if env_val else ("config" if cfg_val else "missing")
            print(f"  {meta['label']:<20} {status}")

def interactive_key_setup():
    """Walk through all services and let the user set/update keys."""
    cfg = _load_config()
    if HAS_RICH:
        console.print(Panel(BANNER, border_style="cyan", padding=(0, 2)))
        console.print(Panel(
            "[dim]Keys are stored in [bold]~/.penkit_config.json[/bold] (owner-read-only, chmod 600).\n"
            "You can also set them as environment variables — env vars take priority over the config file.[/dim]",
            title="[bold]API Key Setup[/bold]", border_style="dim"
        ))
    else:
        console.print(BANNER)
        console.print("\n  Keys stored in ~/.penkit_config.json (chmod 600). Env vars take priority.\n")

    for svc, meta in SERVICES.items():
        env_val = os.environ.get(meta["env"], "")
        cfg_val = cfg.get(svc, "")
        current = env_val or cfg_val

        if HAS_RICH:
            if current:
                masked = current[:4] + "…" + current[-4:] if len(current) > 10 else "****"
                console.print(f"\n  [bold]{meta['label']}[/bold]  [dim](current: {masked})[/dim]")
            else:
                console.print(f"\n  [bold]{meta['label']}[/bold]  [dim]— {meta['use']}[/dim]")
                console.print(f"  [dim]Sign up: {meta['url']}[/dim]")
            update = Confirm.ask(f"  {'Update' if current else 'Set'} this key?", default=not bool(current))
        else:
            masked = (current[:4] + "…" if current else "not set")
            update_str = input(f"  {meta['label']} [{masked}] — set/update? [y/N]: ").strip().lower()
            update = update_str in ("y", "yes")

        if update:
            if HAS_RICH:
                val = Prompt.ask(f"  {meta['label']} API key", password=True, default="")
            else:
                val = getpass.getpass(f"  {meta['label']} API key: ").strip()
            if val:
                cfg[svc] = val
                console.print("  [green]Saved.[/green]" if HAS_RICH else "  Saved.")

    _save_config(cfg)
    console.print(f"\n[green]Config written to {CONFIG_PATH}[/green]" if HAS_RICH else f"\nSaved: {CONFIG_PATH}")

def delete_key(service: str):
    cfg = _load_config()
    if service in cfg:
        del cfg[service]
        _save_config(cfg)
        console.print(f"[green]Removed key for {SERVICES.get(service, {}).get('label', service)}.[/green]" if HAS_RICH else "Removed.")
    else:
        console.print("Key not found in config." if HAS_RICH else "Key not found.")

def export_env_snippet() -> str:
    """Return a shell export block the user can add to their .bashrc/.zshrc."""
    cfg = _load_config()
    lines = ["# PenKit API keys — add to ~/.bashrc or ~/.zshrc", "# Generated by penkit --keys export", ""]
    for svc, meta in SERVICES.items():
        val = cfg.get(svc, "")
        placeholder = f'"{val}"' if val else f'"YOUR_{meta["env"]}_HERE"'
        lines.append(f'export {meta["env"]}={placeholder}')
    return "\n".join(lines)

def generate_env_file():
    """Write a .env template the user can fill in."""
    out = Path.cwd() / ".env.penkit"
    lines = [
        "# PenKit .env template",
        "# Fill in your keys and source this file: source .env.penkit",
        "# WARNING: never commit this file to version control",
        "",
    ]
    cfg = _load_config()
    for svc, meta in SERVICES.items():
        val = cfg.get(svc, "")
        lines.append(f"# {meta['label']} — {meta['url']}")
        lines.append(f'{meta["env"]}="{val or ""}"')
        lines.append("")
    out.write_text("\n".join(lines))
    # chmod 600
    try:
        os.chmod(out, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass
    return out
