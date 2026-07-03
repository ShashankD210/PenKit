import subprocess
import shutil
import json
import os
import sys
import random
import string
import hashlib
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TOOLS = ["ffuf", "sqlmap", "dalfox", "httpx", "wfuzz"]
TOOL_COLORS = {"ffuf": "#00bcd4", "sqlmap": "#f85149", "dalfox": "#d2991d", "httpx": "#3fb950", "wfuzz": "#bc4cff"}
TOOL_DESCRIPTIONS = {
    "ffuf": "Web fuzzer — directory, file, parameter, vhost brute-forcing",
    "sqlmap": "SQL injection scanner & exploitation framework",
    "dalfox": "XSS scanner with parameter mining & blind XSS support",
    "httpx": "Fast HTTP toolkit — probing, tech detection, recon",
    "wfuzz": "Web application fuzzer with advanced filtering",
}

SESSION_FILE = os.path.join(os.path.expanduser("~"), ".penkit_session.json")
REPORTS_DIR = os.path.join(os.path.expanduser("~"), ".penkit_reports")
MAX_REPORTS = 200

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Brave/1.64.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/17.4.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

def _ensure_reports_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    try:
        os.chmod(REPORTS_DIR, 0o700)
    except Exception:
        pass

def _generate_report_id(tool: str, timestamp: str) -> str:
    raw = f"{tool}_{timestamp}_{random.randint(1000, 9999)}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]

def save_report(tool: str, cmd: str, output: str, status: str = "success", extra: dict = None) -> dict:
    _ensure_reports_dir()
    timestamp = datetime.now().isoformat(timespec="seconds")
    report_id = _generate_report_id(tool, timestamp)
    
    report = {
        "id": report_id,
        "tool": tool,
        "cmd": cmd,
        "output": output,
        "status": status,
        "timestamp": timestamp,
        "extra": extra or {},
    }
    
    json_path = os.path.join(REPORTS_DIR, f"report_{report_id}.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    try:
        os.chmod(json_path, 0o600)
    except Exception:
        pass
    
    html_path = os.path.join(REPORTS_DIR, f"report_{report_id}.html")
    html = _render_html_report(report)
    with open(html_path, "w") as f:
        f.write(html)
    try:
        os.chmod(html_path, 0o600)
    except Exception:
        pass
    
    _rotate_reports()
    return report

def _rotate_reports():
    try:
        reports = sorted([f for f in os.listdir(REPORTS_DIR) if f.startswith("report_") and f.endswith(".json")])
        if len(reports) > MAX_REPORTS:
            for old in reports[:len(reports) - MAX_REPORTS]:
                base = old.replace(".json", "")
                for ext in [".json", ".html"]:
                    p = os.path.join(REPORTS_DIR, base + ext)
                    if os.path.exists(p):
                        os.remove(p)
    except Exception:
        pass

def _render_html_report(report: str) -> str:
    status_color = {"success": "#3fb950", "error": "#f85149", "timeout": "#d2991d"}.get(report.get("status", "success"), "#8b949e")
    output_escaped = report.get("output", "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    cmd_escaped = report.get("cmd", "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PenKit Report — {report.get('tool', 'unknown')}</title>
<style>
  :root {{ --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --dim: #8b949e; --accent: #58a6ff; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 24px; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
  h1 {{ margin: 0 0 16px; font-size: 1.3em; }}
  .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; }}
  .meta-item {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px; }}
  .meta-item label {{ display: block; font-size: 0.75em; color: var(--dim); text-transform: uppercase; letter-spacing: 0.5px; }}
  .meta-item value {{ font-size: 0.95em; color: var(--text); word-break: break-all; }}
  .status {{ display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 0.85em; font-weight: 600; background: {status_color}22; color: {status_color}; }}
  pre {{ background: #000; border: 1px solid var(--border); border-radius: 6px; padding: 14px; overflow-x: auto; font-size: 0.85em; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }}
  .cmd {{ color: var(--accent); }}
</style>
</head>
<body>
  <div class="card">
    <h1>PenKit Scan Report</h1>
    <div class="meta">
      <div class="meta-item"><label>Tool</label><value>{report.get('tool', '')}</value></div>
      <div class="meta-item"><label>Status</label><value><span class="status">{report.get('status', '')}</span></value></div>
      <div class="meta-item"><label>Timestamp</label><value>{report.get('timestamp', '')}</value></div>
      <div class="meta-item"><label>Report ID</label><value>{report.get('id', '')}</value></div>
    </div>
  </div>
  <div class="card">
    <h1>Command</h1>
    <pre class="cmd">{cmd_escaped}</pre>
  </div>
  <div class="card">
    <h1>Output</h1>
    <pre>{output_escaped}</pre>
  </div>
</body>
</html>"""

def load_report(report_id: str) -> dict | None:
    path = os.path.join(REPORTS_DIR, f"report_{report_id}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

def list_reports(limit: int = 50) -> list:
    _ensure_reports_dir()
    reports = []
    try:
        for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
            if f.startswith("report_") and f.endswith(".json"):
                path = os.path.join(REPORTS_DIR, f)
                try:
                    with open(path) as fh:
                        data = json.load(fh)
                        reports.append({
                            "id": data.get("id", f.replace("report_", "").replace(".json", "")),
                            "tool": data.get("tool", ""),
                            "status": data.get("status", ""),
                            "timestamp": data.get("timestamp", ""),
                            "cmd_preview": data.get("cmd", "")[:120],
                        })
                except Exception:
                    continue
                if len(reports) >= limit:
                    break
    except Exception:
        pass
    return reports

def get_random_agent():
    return random.choice(USER_AGENTS)

def get_random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def apply_random_agent(cmd, tool):
    ua = get_random_agent()
    header_str = f"User-Agent: {ua}"
    if tool in ("ffuf", "wfuzz", "httpx"):
        parts = cmd.split("'")
        for i, p in enumerate(parts):
            if i % 2 == 0 and p.strip().startswith("-H"):
                parts[i] = parts[i] + f" -H '{header_str}'"
                return "'".join(parts)
        return cmd + f" -H '{header_str}'"
    if tool == "sqlmap":
        parts = cmd.split("'")
        for i, p in enumerate(parts):
            if i % 2 == 0 and p.strip().startswith("-H"):
                parts[i] = parts[i] + f" -H '{header_str}'"
                return "'".join(parts)
        return cmd + f" -H '{header_str}'"
    if tool == "dalfox":
        if "--header" in cmd:
            import re
            cmd = re.sub(r"--header\s+'[^']*'", f"--header '{header_str}'", cmd)
            return cmd
        return cmd + f" --header '{header_str}'"
    return cmd + f" -H '{header_str}'"

def check_tool(name):
    return shutil.which(name) is not None

def get_tool_status():
    result = []
    for t in TOOLS:
        found = check_tool(t)
        path = shutil.which(t) or "Not found"
        result.append({
            "tool": t,
            "found": found,
            "path": path,
            "color": TOOL_COLORS[t],
            "description": TOOL_DESCRIPTIONS[t]
        })
    return result

def load_history():
    if not os.path.exists(SESSION_FILE):
        return []
    try:
        with open(SESSION_FILE) as f:
            return json.load(f)
    except Exception:
        return []

def save_to_history(tool, cmd):
    sessions = load_history()
    sessions.append({
        "tool": tool,
        "cmd": cmd,
        "timestamp": datetime.now().isoformat(timespec="seconds")
    })
    sessions = sessions[-50:]
    with open(SESSION_FILE, "w") as f:
        json.dump(sessions, f, indent=2)
