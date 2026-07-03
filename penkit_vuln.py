#!/usr/bin/env python3
"""
PenKit — Vulnerability & CVE Scanning Module
Uses NVD API 2.0 + httpx tech detection to identify CVEs for URLs, IPs, and technologies.
"""

import json
import os
import sys
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from penkit_keys import get_key

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.prompt import Prompt, Confirm
    from rich import box
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    class _C:
        def print(self, *a, **kw): print(*[str(x) for x in a])
    console = _C()

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _get(url, headers=None, label=""):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
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

def _pretty(data, title=""):
    raw = json.dumps(data, indent=2)
    if HAS_RICH:
        console.print(Panel(Syntax(raw, "json", theme="monokai", word_wrap=True), title=f"[bold]{title}[/bold]", border_style="dim"))
    else:
        print(f"\n--- {title} ---")
        print(raw)

# ── NVD CVE Lookup ────────────────────────────────────────────────────────────

def lookup_cve_by_keyword(keyword, limit=20):
    """Search CVEs by keyword (product, vendor, technology)."""
    api_key = get_key("nvd", prompt_if_missing=False)
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": limit,
    })
    url = f"{NVD_BASE}?{params}"
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    data = _get(url, headers=headers, label="NVD")
    if not data:
        return []
    vulns = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        metrics = cve.get("metrics", {})
        score = None
        severity = "UNKNOWN"
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics:
                m = metrics[key][0]
                score = m.get("cvssData", {}).get("baseScore")
                severity = m.get("cvssData", {}).get("baseSeverity", severity)
                break
        vulns.append({
            "id": cve_id,
            "description": desc[:200] + "..." if len(desc) > 200 else desc,
            "score": score,
            "severity": severity,
            "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })
    return vulns

def lookup_cve_by_cpe(cpe, limit=20):
    """Search CVEs by CPE string."""
    api_key = get_key("nvd", prompt_if_missing=False)
    params = urllib.parse.urlencode({
        "cpeName": cpe,
        "resultsPerPage": limit,
    })
    url = f"{NVD_BASE}?{params}"
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    data = _get(url, headers=headers, label="NVD CPE")
    if not data:
        return []
    vulns = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        metrics = cve.get("metrics", {})
        score = None
        severity = "UNKNOWN"
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics:
                m = metrics[key][0]
                score = m.get("cvssData", {}).get("baseScore")
                severity = m.get("cvssData", {}).get("baseSeverity", severity)
                break
        vulns.append({
            "id": cve_id,
            "description": desc[:200] + "..." if len(desc) > 200 else desc,
            "score": score,
            "severity": severity,
            "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })
    return vulns

# ── Technology Detection + CVE Mapping ────────────────────────────────────────

def detect_tech_from_headers(headers: dict) -> list:
    """Detect technologies from HTTP headers."""
    techs = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    if "server" in headers_lower:
        techs.append(headers_lower["server"])
    if "x-powered-by" in headers_lower:
        techs.append(headers_lower["x-powered-by"])
    if "x-aspnet-version" in headers_lower:
        techs.append(f"ASP.NET {headers_lower['x-aspnet-version']}")
    if "x-generator" in headers_lower:
        techs.append(headers_lower["x-generator"])
    return techs

def scan_url_for_cves(url: str, limit: int = 20):
    """Scan a URL for technologies and look up CVEs."""
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (PenKit)"})
        with urllib.request.urlopen(req, timeout=15) as r:
            headers = dict(r.headers)
            body = r.read().decode(errors="replace")[:5000]
    except Exception as e:
        _err(f"Cannot fetch {url}: {e}")
        return []

    techs = detect_tech_from_headers(headers)
    
    # Try to detect from body
    body_lower = body.lower()
    tech_checks = [
        ("wordpress", "WordPress"),
        ("drupal", "Drupal"),
        ("joomla", "Joomla"),
        ("django", "Django"),
        ("flask", "Flask"),
        ("laravel", "Laravel"),
        ("react", "React"),
        ("angular", "Angular"),
        ("vue.js", "Vue.js"),
        ("express", "Express.js"),
        ("spring", "Spring"),
        ("tomcat", "Apache Tomcat"),
        ("nginx", "Nginx"),
        ("apache", "Apache"),
        ("iis", "Microsoft IIS"),
        ("php", "PHP"),
        ("node.js", "Node.js"),
        ("rails", "Ruby on Rails"),
    ]
    for keyword, name in tech_checks:
        if keyword in body_lower and name not in techs:
            techs.append(name)

    results = []
    seen = set()
    for tech in techs[:5]:
        cves = lookup_cve_by_keyword(tech, limit=limit)
        for cve in cves:
            if cve["id"] not in seen:
                seen.add(cve["id"])
                cve["tech"] = tech
                results.append(cve)
        if not cves:
            results.append({
                "id": "N/A",
                "description": f"No CVEs found for {tech}",
                "score": None,
                "severity": "INFO",
                "link": "",
                "tech": tech,
            })
    return results

def scan_ip_for_cves(ip: str, limit: int = 20):
    """Scan an IP for open ports/services and look up CVEs."""
    import urllib.request
    import socket
    
    # For IP scanning, we need to detect services running on the IP
    # We'll use common ports to detect services
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 6379, 27017, 8080, 8443]
    detected_services = []
    
    for port in common_ports[:10]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = _guess_service(port)
                detected_services.append(service)
            sock.close()
        except Exception:
            pass
    
    results = []
    seen = set()
    for svc in detected_services[:5]:
        cves = lookup_cve_by_keyword(svc, limit=limit)
        for cve in cves:
            if cve["id"] not in seen:
                seen.add(cve["id"])
                cve["tech"] = svc
                results.append(cve)
        if not cves:
            results.append({
                "id": "N/A",
                "description": f"No CVEs found for {svc}",
                "score": None,
                "severity": "INFO",
                "link": "",
                "tech": svc,
            })
    return results

def _guess_service(port):
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 27017: "MongoDB",
        8080: "HTTP Proxy", 8443: "HTTPS Alt"
    }
    return services.get(port, f"Port {port}")

def print_cve_table(vulns, title="CVE Results"):
    if not vulns:
        console.print("  [green]No CVEs found.[/green]" if HAS_RICH else "  No CVEs found.")
        return
    if HAS_RICH:
        table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold dim")
        table.add_column("CVE ID", width=16)
        table.add_column("Severity", width=12)
        table.add_column("Score", width=8)
        table.add_column("Technology", width=20)
        table.add_column("Description", width=50)
        for v in vulns:
            sev = v.get("severity", "UNKNOWN")
            sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}.get(sev, "white")
            table.add_row(
                f"[link={v.get('link','')}]{v['id']}[/link]" if v.get("link") else v["id"],
                f"[{sev_color}]{sev}[/{sev_color}]",
                str(v.get("score") or "—"),
                v.get("tech", ""),
                v.get("description", "")[:60],
            )
        console.print(table)
    else:
        for v in vulns:
            print(f"  {v['id']} [{v.get('severity','?')}] score={v.get('score','?')} tech={v.get('tech','')} {v.get('description','')[:80]}")

# ── Unified Scan ──────────────────────────────────────────────────────────────

def _ask(prompt, default=""):
    if HAS_RICH:
        return Prompt.ask(f"  [cyan]{prompt}[/cyan]", default=default) or default
    val = input(f"  {prompt} [{default}]: ").strip()
    return val if val else default

def _ask_bool(prompt, default=False):
    if HAS_RICH:
        return Confirm.ask(f"  [cyan]{prompt}[/cyan]", default=default)
    val = input(f"  {prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return val in ("y", "yes") if val else default

VULN_MENU = {
    "1": ("URL — tech detect + CVE lookup",     lambda: scan_url_for_cves(_ask("Target URL (e.g. https://target.com)", "https://target.com")), None),
    "2": ("IP — port scan + CVE lookup",         lambda: scan_ip_for_cves(_ask("Target IP (e.g. 192.168.1.1)", "192.168.1.1")), None),
    "3": ("Keyword — CVE search (product)",      lambda: lookup_cve_by_keyword(_ask("Keyword (e.g. Apache, Nginx, WordPress)", "Apache"), int(_ask("Max results", "20"))), None),
    "4": ("CPE — CVE lookup by CPE string",      lambda: lookup_cve_by_cpe(_ask("CPE string (e.g. cpe:2.3:a:apache:http_server:2.4.49)", ""), int(_ask("Max results", "20"))), None),
}

def vuln_mode():
    """Interactive vulnerability scanning mode."""
    if HAS_RICH:
        console.print(Panel("[bold red]Vulnerability & CVE Scanner[/bold red]\n[dim]Scan URLs, IPs, and technologies for known CVEs[/dim]", border_style="red", padding=(0, 2)))
    else:
        console.print("\n=== Vulnerability & CVE Scanner ===")
    console.print()
    while True:
        if HAS_RICH:
            choices_str = "  ".join(
                f"[bold]{k}[/bold] {v[0]}" for k, v in VULN_MENU.items()
            )
            console.print(choices_str)
            console.print("  [bold]b[/bold] Back")
            choice = Prompt.ask("\n  [bold red]Select scan type[/bold red]").strip().lower()
        else:
            for k, v in VULN_MENU.items():
                console.print(f"  {k}) {v[0]}")
            console.print("  b) Back")
            choice = input("\n  Select scan type: ").strip().lower()

        if choice in ("b", "back", "q", "quit"):
            break
        if choice in VULN_MENU:
            try:
                vulns = VULN_MENU[choice][1]()
                print_cve_table(vulns, title=VULN_MENU[choice][0])
            except KeyboardInterrupt:
                console.print("\n[yellow]Cancelled.[/yellow]" if HAS_RICH else "Cancelled.")
                continue
        else:
            console.print("[red]Unknown option.[/red]" if HAS_RICH else "Unknown option.")
