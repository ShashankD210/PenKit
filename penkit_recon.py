"""
PenKit — Recon API Module
Wraps Shodan, VirusTotal, SecurityTrails, Censys, Hunter, HIBP, WhoisXML, BinaryEdge, FullHunt.
All keys are user-supplied via env vars or ~/.penkit_config.json — never hardcoded.
"""

import json
import os
import sys
import urllib.request
import urllib.parse
import urllib.error
import base64

# Allow running as a standalone script from the repo root or as an installed package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from penkit_keys import get_key

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich import box
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    class _C:
        def print(self, *a, **kw): print(*[str(x) for x in a])
    console = _C()

# ── HTTP helper ───────────────────────────────────────────────────────────────

def _get(url: str, headers: dict = None, label: str = "") -> dict | None:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        _err(f"{label} HTTP {e.code}: {body[:200]}")
        return None
    except Exception as ex:
        _err(f"{label} error: {ex}")
        return None

def _err(msg):
    console.print(f"  [red]{msg}[/red]" if HAS_RICH else f"  ERROR: {msg}")

def _pretty(data: dict, title: str = ""):
    raw = json.dumps(data, indent=2)
    if HAS_RICH:
        console.print(Panel(Syntax(raw, "json", theme="monokai", word_wrap=True), title=f"[bold]{title}[/bold]", border_style="dim"))
    else:
        print(f"\n--- {title} ---")
        print(raw)

# ── Shodan ────────────────────────────────────────────────────────────────────

def shodan_host(ip: str):
    """Look up a host on Shodan."""
    key = get_key("shodan")
    if not key:
        return
    url = f"https://api.shodan.io/shodan/host/{urllib.parse.quote(ip)}?key={key}"
    data = _get(url, label="Shodan")
    if not data:
        return
    if HAS_RICH:
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("Field", style="dim", width=18)
        t.add_column("Value")
        t.add_row("IP",         data.get("ip_str", ip))
        t.add_row("Org",        data.get("org", "—"))
        t.add_row("Country",    data.get("country_name", "—"))
        t.add_row("OS",         str(data.get("os") or "—"))
        t.add_row("Last update",data.get("last_update", "—"))
        ports = ", ".join(str(p) for p in data.get("ports", []))
        t.add_row("Open ports", ports or "—")
        vulns = ", ".join(data.get("vulns", {}).keys())
        t.add_row("CVEs",       vulns or "none")
        console.print(t)
    else:
        _pretty(data, f"Shodan — {ip}")

def shodan_search(query: str, limit: int = 10):
    """Run a Shodan search query."""
    key = get_key("shodan")
    if not key:
        return
    params = urllib.parse.urlencode({"key": key, "query": query, "minify": "true"})
    url = f"https://api.shodan.io/shodan/host/search?{params}"
    data = _get(url, label="Shodan search")
    if not data:
        return
    matches = data.get("matches", [])[:limit]
    if HAS_RICH:
        t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold dim")
        t.add_column("IP",       width=16)
        t.add_column("Port",     width=6)
        t.add_column("Org",      width=28)
        t.add_column("Product",  width=20)
        t.add_column("Country",  width=14)
        for m in matches:
            t.add_row(
                m.get("ip_str", ""),
                str(m.get("port", "")),
                m.get("org", "—"),
                m.get("product", "—"),
                m.get("location", {}).get("country_name", "—"),
            )
        console.print(t)
        console.print(f"  [dim]Total results: {data.get('total', '?')}[/dim]")
    else:
        _pretty(data, "Shodan search")

# ── VirusTotal ────────────────────────────────────────────────────────────────

def _vt_headers() -> dict | None:
    key = get_key("virustotal")
    return {"x-apikey": key} if key else None

def vt_url(target_url: str):
    """Check a URL with VirusTotal."""
    h = _vt_headers()
    if not h:
        return
    encoded = base64.urlsafe_b64encode(target_url.encode()).rstrip(b"=").decode()
    data = _get(f"https://www.virustotal.com/api/v3/urls/{encoded}", headers=h, label="VT URL")
    if not data:
        return
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    _vt_stats(stats, f"VirusTotal — {target_url}")

def vt_ip(ip: str):
    """Check an IP with VirusTotal."""
    h = _vt_headers()
    if not h:
        return
    data = _get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=h, label="VT IP")
    if not data:
        return
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    _vt_stats(stats, f"VirusTotal — {ip}")

def vt_hash(file_hash: str):
    """Check a file hash with VirusTotal."""
    h = _vt_headers()
    if not h:
        return
    data = _get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=h, label="VT hash")
    if not data:
        return
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    _vt_stats(stats, f"VirusTotal — {file_hash[:16]}…")

def _vt_stats(stats: dict, title: str):
    mal   = stats.get("malicious", 0)
    susp  = stats.get("suspicious", 0)
    clean = stats.get("undetected", 0)
    total = sum(stats.values())
    if HAS_RICH:
        color = "red" if mal > 0 else ("yellow" if susp > 0 else "green")
        console.print(Panel(
            f"[{color}]Malicious: {mal}[/{color}]  "
            f"[yellow]Suspicious: {susp}[/yellow]  "
            f"[green]Clean: {clean}[/green]  "
            f"[dim]Total engines: {total}[/dim]",
            title=f"[bold]{title}[/bold]", border_style=color
        ))
    else:
        print(f"\n{title}\n  Malicious: {mal}  Suspicious: {susp}  Clean: {clean}  Total: {total}")

# ── SecurityTrails ────────────────────────────────────────────────────────────

def securitytrails_subdomains(domain: str):
    """List subdomains for a domain."""
    key = get_key("securitytrails")
    if not key:
        return
    h = {"apikey": key, "Accept": "application/json"}
    data = _get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains", headers=h, label="SecurityTrails")
    if not data:
        return
    subs = data.get("subdomains", [])
    if HAS_RICH:
        t = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
        t.add_column("Subdomain", width=40)
        t.add_column("FQDN",      width=50)
        for s in subs[:30]:
            t.add_row(s, f"{s}.{domain}")
        console.print(t)
        console.print(f"  [dim]Total: {data.get('subdomain_count', len(subs))}[/dim]")
    else:
        for s in subs:
            print(f"  {s}.{domain}")

def securitytrails_dns(domain: str):
    """Get current DNS records for a domain."""
    key = get_key("securitytrails")
    if not key:
        return
    h = {"apikey": key, "Accept": "application/json"}
    data = _get(f"https://api.securitytrails.com/v1/domain/{domain}", headers=h, label="SecurityTrails DNS")
    if data:
        _pretty(data.get("current_dns", data), f"SecurityTrails DNS — {domain}")

# ── Censys ────────────────────────────────────────────────────────────────────

def censys_ip(ip: str):
    """Look up an IP on Censys."""
    api_id     = get_key("censys")
    api_secret = get_key("censys_secret")
    if not api_id or not api_secret:
        return
    token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    h = {"Authorization": f"Basic {token}", "Accept": "application/json"}
    data = _get(f"https://search.censys.io/api/v2/hosts/{ip}", headers=h, label="Censys")
    if data:
        _pretty(data.get("result", data), f"Censys — {ip}")

# ── Hunter.io ─────────────────────────────────────────────────────────────────

def hunter_domain(domain: str):
    """Find email addresses associated with a domain."""
    key = get_key("hunter")
    if not key:
        return
    params = urllib.parse.urlencode({"domain": domain, "api_key": key})
    data = _get(f"https://api.hunter.io/v2/domain-search?{params}", label="Hunter.io")
    if not data:
        return
    emails = data.get("data", {}).get("emails", [])
    if HAS_RICH:
        t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold dim")
        t.add_column("Email",      width=36)
        t.add_column("Type",       width=12)
        t.add_column("Confidence", width=12)
        t.add_column("Name",       width=28)
        for e in emails:
            t.add_row(
                e.get("value", ""),
                e.get("type", "—"),
                str(e.get("confidence", "—")) + "%",
                f"{e.get('first_name','')} {e.get('last_name','')}".strip() or "—",
            )
        console.print(t)
        console.print(f"  [dim]Total emails: {len(emails)}[/dim]")
    else:
        for e in emails:
            print(f"  {e.get('value','')}  ({e.get('confidence','?')}%)")

def hunter_verify(email: str):
    """Verify a single email address."""
    key = get_key("hunter")
    if not key:
        return
    params = urllib.parse.urlencode({"email": email, "api_key": key})
    data = _get(f"https://api.hunter.io/v2/email-verifier?{params}", label="Hunter verify")
    if data:
        result = data.get("data", {})
        status = result.get("status", "unknown")
        score  = result.get("score", "?")
        color  = "green" if status == "valid" else ("yellow" if status == "risky" else "red")
        console.print(f"  [{color}]{email} → {status} (score: {score})[/{color}]" if HAS_RICH else f"  {email} — {status} ({score})")

# ── HaveIBeenPwned ────────────────────────────────────────────────────────────

def hibp_account(email: str):
    """Check if an email has appeared in known data breaches."""
    key = get_key("haveibeenpwned")
    if not key:
        return
    h = {"hibp-api-key": key, "user-agent": "penkit"}
    encoded = urllib.parse.quote(email)
    data = _get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}?truncateResponse=false", headers=h, label="HIBP")
    if data is None:
        console.print("  [green]No breaches found.[/green]" if HAS_RICH else "  No breaches found.")
        return
    if HAS_RICH:
        t = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
        t.add_column("Breach",     width=28)
        t.add_column("Date",       width=14)
        t.add_column("Data types", width=50)
        for b in data:
            types = ", ".join(b.get("DataClasses", [])[:5])
            t.add_row(b.get("Name",""), b.get("BreachDate",""), types)
        console.print(t)
        console.print(f"  [red]Found in {len(data)} breach(es)[/red]")
    else:
        for b in data:
            print(f"  {b.get('Name','')} ({b.get('BreachDate','')})")

# ── WhoisXML ──────────────────────────────────────────────────────────────────

def whoisxml_lookup(domain: str):
    """WHOIS lookup via WhoisXML API."""
    key = get_key("whoisxml")
    if not key:
        return
    params = urllib.parse.urlencode({"apiKey": key, "domainName": domain, "outputFormat": "JSON"})
    data = _get(f"https://www.whoisxmlapi.com/whoisserver/WhoisService?{params}", label="WhoisXML")
    if not data:
        return
    wr = data.get("WhoisRecord", data)
    if HAS_RICH:
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("Field", style="dim", width=22)
        t.add_column("Value")
        t.add_row("Domain",      wr.get("domainName", domain))
        t.add_row("Registrar",   wr.get("registrarName", "—"))
        t.add_row("Created",     wr.get("createdDate", "—"))
        t.add_row("Expires",     wr.get("expiresDate", "—"))
        t.add_row("Updated",     wr.get("updatedDate", "—"))
        ns = ", ".join(wr.get("nameServers", {}).get("hostNames", []))
        t.add_row("Nameservers", ns or "—")
        console.print(t)
    else:
        _pretty(wr, f"WHOIS — {domain}")

# ── BinaryEdge ────────────────────────────────────────────────────────────────

def binaryedge_ip(ip: str):
    """Query BinaryEdge for host data."""
    key = get_key("binaryedge")
    if not key:
        return
    h = {"X-Key": key}
    data = _get(f"https://api.binaryedge.io/v2/query/ip/{ip}", headers=h, label="BinaryEdge")
    if data:
        _pretty(data, f"BinaryEdge — {ip}")

# ── FullHunt ──────────────────────────────────────────────────────────────────

def fullhunt_domain(domain: str):
    """Enumerate attack surface for a domain via FullHunt."""
    key = get_key("fullhunt")
    if not key:
        return
    h = {"X-API-KEY": key}
    data = _get(f"https://fullhunt.io/api/v1/domain/{domain}/subdomains", headers=h, label="FullHunt")
    if not data:
        return
    hosts = data.get("hosts", [])
    if HAS_RICH:
        t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold dim")
        t.add_column("Host",        width=42)
        t.add_column("IPs",         width=20)
        t.add_column("CDN",         width=8)
        t.add_column("Tags",        width=30)
        for h_entry in hosts[:30]:
            t.add_row(
                h_entry.get("host", ""),
                ", ".join(h_entry.get("ip_addresses", [])),
                "✓" if h_entry.get("cdn") else "—",
                ", ".join(h_entry.get("tags", [])) or "—",
            )
        console.print(t)
        console.print(f"  [dim]Total hosts: {len(hosts)}[/dim]")
    else:
        for h_entry in hosts:
            print(f"  {h_entry.get('host','')}  {h_entry.get('ip_addresses','')}")

# ── Interactive recon menu ────────────────────────────────────────────────────

RECON_MENU = {
    "1":  ("Shodan — host lookup",        lambda: shodan_host(ask("IP address"))),
    "2":  ("Shodan — search query",       lambda: shodan_search(ask("Query (e.g. apache port:8080 country:US)"), int(ask("Max results", "10")))),
    "3":  ("VirusTotal — URL scan",       lambda: vt_url(ask("URL to check"))),
    "4":  ("VirusTotal — IP reputation",  lambda: vt_ip(ask("IP address"))),
    "5":  ("VirusTotal — file hash",      lambda: vt_hash(ask("MD5 / SHA1 / SHA256"))),
    "6":  ("SecurityTrails — subdomains", lambda: securitytrails_subdomains(ask("Domain"))),
    "7":  ("SecurityTrails — DNS",        lambda: securitytrails_dns(ask("Domain"))),
    "8":  ("Censys — host lookup",        lambda: censys_ip(ask("IP address"))),
    "9":  ("Hunter.io — domain emails",   lambda: hunter_domain(ask("Domain"))),
    "10": ("Hunter.io — verify email",    lambda: hunter_verify(ask("Email address"))),
    "11": ("HaveIBeenPwned — breach check",lambda: hibp_account(ask("Email address"))),
    "12": ("WhoisXML — WHOIS lookup",     lambda: whoisxml_lookup(ask("Domain"))),
    "13": ("BinaryEdge — host lookup",    lambda: binaryedge_ip(ask("IP address"))),
    "14": ("FullHunt — subdomain enum",   lambda: fullhunt_domain(ask("Domain"))),
}

def ask(prompt, default=""):
    if HAS_RICH:
        from rich.prompt import Prompt
        return Prompt.ask(f"  [cyan]{prompt}[/cyan]", default=default) or default
    val = input(f"  {prompt} [{default}]: ").strip()
    return val if val else default

def recon_menu():
    if HAS_RICH:
        t = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
        t.add_column("#",  width=4)
        t.add_column("Module", width=42)
        for k, (label, _) in RECON_MENU.items():
            t.add_row(k, label)
        console.print(t)
        from rich.prompt import Prompt
        choice = Prompt.ask("  [bold]Select module[/bold]", default="1")
    else:
        for k, (label, _) in RECON_MENU.items():
            print(f"  {k:>2}) {label}")
        choice = input("  Select: ").strip()

    entry = RECON_MENU.get(choice)
    if entry:
        try:
            entry[1]()
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled.[/yellow]" if HAS_RICH else "Cancelled.")
    else:
        console.print("Invalid choice." if HAS_RICH else "Invalid choice.")
