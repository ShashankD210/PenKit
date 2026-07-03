from flask import render_template, request, jsonify, session, Response
import subprocess
import shutil
import json
import os
import sys
from datetime import datetime
from webapp import utils

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def register_routes(app):

    @app.route('/')
    def index():
        tools = utils.get_tool_status()
        history = utils.load_history()
        return render_template('index.html', tools=tools, history=history)

    @app.route('/status')
    def status():
        return jsonify({"tools": utils.get_tool_status()})

    @app.route('/history')
    def history():
        data = utils.load_history()
        return jsonify({"history": data})

    @app.route('/clear-history', methods=['POST'])
    def clear_history():
        session_file = os.path.join(os.path.expanduser("~"), ".penkit_session.json")
        if os.path.exists(session_file):
            with open(session_file, "w") as f:
                json.dump([], f)
        return jsonify({"ok": True})

    @app.route('/builder/<tool_name>')
    def builder(tool_name):
        if tool_name not in utils.TOOLS:
            return jsonify({"error": "Unknown tool"}), 404
        return render_template('builder.html', tool=tool_name)

    @app.route('/reports')
    def reports_page():
        reports = utils.list_reports()
        return render_template('reports.html', reports=reports)

    @app.route('/report/<report_id>')
    def report_view(report_id):
        report = utils.load_report(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404
        return render_template('report.html', report=report)

    @app.route('/report/<report_id>/json')
    def report_json(report_id):
        report = utils.load_report(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404
        return jsonify(report)

    @app.route('/report/<report_id>/html')
    def report_html_download(report_id):
        report = utils.load_report(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404
        html = utils._render_html_report(report)
        from flask import Response
        return Response(html, mimetype="text/html")

    @app.route('/api/reports')
    def api_reports():
        reports = utils.list_reports()
        return jsonify({"reports": reports})

    @app.route('/api/report/<report_id>')
    def api_report(report_id):
        report = utils.load_report(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404
        return jsonify(report)

    @app.route('/api/reports', methods=['DELETE'])
    def api_reports_delete():
        try:
            import glob
            for f in glob.glob(os.path.join(utils.REPORTS_DIR, "report_*")):
                os.remove(f)
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/run', methods=['POST'])
    def run_command():
        data = request.get_json()
        cmd = data.get('cmd', '')
        tool = data.get('tool', '')
        dry_run = data.get('dry_run', False)

        if not cmd:
            return jsonify({"error": "No command provided"}), 400

        utils.save_to_history(tool, cmd)
        cmd = utils.apply_random_agent(cmd, tool)

        if dry_run:
            return jsonify({"output": f"[DRY RUN] Would execute:\n{cmd}", "dry_run": True})

        parts = cmd.split()
        runner = parts[0]
        if not shutil.which(runner):
            return jsonify({"error": f"Tool '{runner}' not found in PATH. Install it first."}), 400

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            output = result.stdout
            if result.stderr:
                output += "\n" + result.stderr
            status = "success" if result.returncode == 0 else "error"
            
            if not dry_run:
                report = utils.save_report(tool, cmd, output, status=status)
                return jsonify({"output": output, "dry_run": False, "report_id": report.get("id")})
            
            return jsonify({"output": output, "dry_run": False})
        except subprocess.TimeoutExpired:
            if not dry_run:
                utils.save_report(tool, cmd, "Command timed out (120s limit).", status="timeout")
            return jsonify({"output": "Command timed out (120s limit)."})
        except Exception as e:
            if not dry_run:
                utils.save_report(tool, cmd, f"Error: {str(e)}", status="error")
            return jsonify({"output": f"Error: {str(e)}"}) 

    @app.route('/copy', methods=['POST'])
    def copy_cmd():
        data = request.get_json()
        return jsonify({"ok": True})

    @app.route('/api/random-agent', methods=['GET'])
    def random_agent():
        return jsonify({"agent": utils.get_random_agent()})

    @app.route('/generate', methods=['POST'])
    def generate():
        data = request.get_json()
        tool = data.get('tool', '')
        if tool not in utils.TOOLS:
            return jsonify({"error": "Unknown tool"}), 404
        cmd = build_cmd(tool, data.get('params', {}))
        cmd = utils.apply_random_agent(cmd, tool)
        if cmd:
            utils.save_to_history(tool, cmd)
        return jsonify({"cmd": cmd})

    @app.route('/vuln')
    def vuln_page():
        return render_template('vuln.html')

    @app.route('/api/vuln/scan_url', methods=['POST'])
    def api_vuln_scan_url():
        data = request.get_json()
        url = data.get('url', '')
        limit = int(data.get('limit', 20))
        if not url:
            return jsonify({"error": "URL required"}), 400
        try:
            from penkit_vuln import scan_url_for_cves
            vulns = scan_url_for_cves(url, limit=limit)
            return jsonify({"vulns": vulns, "target": url, "type": "url"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/api/vuln/scan_ip', methods=['POST'])
    def api_vuln_scan_ip():
        data = request.get_json()
        ip = data.get('ip', '')
        limit = int(data.get('limit', 20))
        if not ip:
            return jsonify({"error": "IP required"}), 400
        try:
            from penkit_vuln import scan_ip_for_cves
            vulns = scan_ip_for_cves(ip, limit=limit)
            return jsonify({"vulns": vulns, "target": ip, "type": "ip"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/api/vuln/search_cve', methods=['POST'])
    def api_vuln_search_cve():
        data = request.get_json()
        keyword = data.get('keyword', '')
        limit = int(data.get('limit', 20))
        if not keyword:
            return jsonify({"error": "Keyword required"}), 400
        try:
            from penkit_vuln import lookup_cve_by_keyword
            vulns = lookup_cve_by_keyword(keyword, limit=limit)
            return jsonify({"vulns": vulns, "target": keyword, "type": "keyword"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/api/vuln/lookup_cpe', methods=['POST'])
    def api_vuln_lookup_cpe():
        data = request.get_json()
        cpe = data.get('cpe', '')
        limit = int(data.get('limit', 20))
        if not cpe:
            return jsonify({"error": "CPE string required"}), 400
        try:
            from penkit_vuln import lookup_cve_by_cpe
            vulns = lookup_cve_by_cpe(cpe, limit=limit)
            return jsonify({"vulns": vulns, "target": cpe, "type": "cpe"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/recon')
    def recon():
        return render_template('recon.html')

    @app.route('/api/recon/<service>', methods=['POST'])
    def api_recon(service):
        data = request.get_json()
        recon_map = {
            "shodan_host": lambda: __import__('penkit_recon', fromlist=['shodan_host']).shodan_host(data.get('ip', '')),
            "shodan_search": lambda: __import__('penkit_recon', fromlist=['shodan_search']).shodan_search(data.get('query', ''), int(data.get('limit', 10))),
            "vt_url": lambda: __import__('penkit_recon', fromlist=['vt_url']).vt_url(data.get('url', '')),
            "vt_ip": lambda: __import__('penkit_recon', fromlist=['vt_ip']).vt_ip(data.get('ip', '')),
            "vt_hash": lambda: __import__('penkit_recon', fromlist=['vt_hash']).vt_hash(data.get('hash', '')),
            "securitytrails_subdomains": lambda: __import__('penkit_recon', fromlist=['securitytrails_subdomains']).securitytrails_subdomains(data.get('domain', '')),
            "securitytrails_dns": lambda: __import__('penkit_recon', fromlist=['securitytrails_dns']).securitytrails_dns(data.get('domain', '')),
            "censys_ip": lambda: __import__('penkit_recon', fromlist=['censys_ip']).censys_ip(data.get('ip', '')),
            "hunter_domain": lambda: __import__('penkit_recon', fromlist=['hunter_domain']).hunter_domain(data.get('domain', '')),
            "hunter_verify": lambda: __import__('penkit_recon', fromlist=['hunter_verify']).hunter_verify(data.get('email', '')),
            "hibp_account": lambda: __import__('penkit_recon', fromlist=['hibp_account']).hibp_account(data.get('email', '')),
            "whoisxml_lookup": lambda: __import__('penkit_recon', fromlist=['whoisxml_lookup']).whoisxml_lookup(data.get('domain', '')),
            "binaryedge_ip": lambda: __import__('penkit_recon', fromlist=['binaryedge_ip']).binaryedge_ip(data.get('ip', '')),
            "fullhunt_domain": lambda: __import__('penkit_recon', fromlist=['fullhunt_domain']).fullhunt_domain(data.get('domain', '')),
        }
        if service not in recon_map:
            return jsonify({"error": "Unknown recon service"}), 404
        result = recon_map[service]()
        return jsonify({"ok": True})

    @app.route('/keys')
    def keys_page():
        return render_template('keys.html')

    @app.route('/api/keys/status')
    def keys_status():
        try:
            from penkit_keys import SERVICES, _load_config
            cfg = _load_config()
            result = []
            env = dict(os.environ)
            for svc, meta in SERVICES.items():
                env_val = env.get(meta["env"], "")
                cfg_val = cfg.get(svc, "")
                source = "env" if env_val else ("config" if cfg_val else "missing")
                val = env_val or cfg_val
                masked = (val[:4] + "…" + val[-4:]) if val and len(val) > 10 else ("****" if val else "")
                result.append({
                    "service": svc,
                    "label": meta["label"],
                    "env": meta["env"],
                    "source": source,
                    "masked": masked,
                    "url": meta["url"]
                })
            return jsonify({"keys": result})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/api/keys/save', methods=['POST'])
    def keys_save():
        try:
            from penkit_keys import _load_config, _save_config
            data = request.get_json()
            cfg = _load_config()
            for svc, val in data.get('keys', {}).items():
                if val:
                    cfg[svc] = val
            _save_config(cfg)
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/api/keys/delete', methods=['POST'])
    def keys_delete():
        try:
            from penkit_keys import _load_config, _save_config
            data = request.get_json()
            cfg = _load_config()
            for svc in data.get('services', []):
                if svc in cfg:
                    del cfg[svc]
            _save_config(cfg)
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/api/keys/export')
    def keys_export():
        try:
            from penkit_keys import export_env_snippet
            return jsonify({"export": export_env_snippet()})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

def build_cmd(tool, params):
    if tool == "ffuf":
        url      = params.get('url', params.get('target', 'https://target.com/FUZZ'))
        wordlist = params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
        method   = params.get('method', 'GET')
        threads  = params.get('threads', '40')
        mc       = params.get('mc', '200,301,302,403')
        fs       = params.get('fs', '')
        ext      = params.get('ext', '')
        headers  = params.get('headers', '')
        data     = params.get('data', '')
        rec      = params.get('recursion', False)
        follow   = params.get('follow', False)
        silent   = params.get('silent', False)
        output   = params.get('output', '')
        proxy    = params.get('proxy', '')

        parts = [f"ffuf -u '{url}' -w '{wordlist}'"]
        if method.upper() != "GET":
            parts.append(f"-X {method.upper()}")
        parts.append(f"-t {threads}")
        if mc: parts.append(f"-mc {mc}")
        if fs: parts.append(f"-fs {fs}")
        if ext:
            parts.append(f"-e {','.join(e.strip().lstrip('.') for e in ext.split(','))}")
        if headers:
            for h in headers.split("|"):
                h = h.strip()
                if h:
                    parts.append(f"-H '{h}'")
        if data: parts.append(f"-d '{data}'")
        if rec: parts.append("-recursion")
        if follow: parts.append("-r")
        if silent: parts.append("-s")
        if proxy: parts.append(f"-x '{proxy}'")
        if output: parts.append(f"-o '{output}' -of json")
        return " \\\n  ".join(parts)

    elif tool == "sqlmap":
        url     = params.get('url', 'https://target.com/page?id=1')
        data    = params.get('data', '')
        cookie  = params.get('cookie', '')
        level   = params.get('level', '1')
        risk    = params.get('risk', '1')
        dbms    = params.get('dbms', '')
        threads = params.get('threads', '1')
        headers = params.get('headers', '')
        proxy   = params.get('proxy', '')
        dbs     = params.get('dbs', False)
        tables  = params.get('tables', False)
        dump    = params.get('dump', False)
        os_sh   = params.get('os_sh', False)
        tor     = params.get('tor', False)
        batch   = params.get('batch', True)
        rand_ua = params.get('rand_ua', True)
        tamper  = params.get('tamper', '')

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
        if dbs: parts.append("--dbs")
        if tables: parts.append("--tables")
        if dump: parts.append("--dump")
        if os_sh: parts.append("--os-shell")
        if tor: parts.append("--tor --tor-type=SOCKS5")
        return " \\\n  ".join(parts)

    elif tool == "dalfox":
        mode    = params.get('mode', 'url')
        target  = params.get('url', 'https://target.com/search?q=test')
        cookie  = params.get('cookie', '')
        header  = params.get('header', '')
        data    = params.get('data', '')
        worker  = params.get('worker', '100')
        timeout = params.get('timeout', '10')
        payload = params.get('payload', '')
        blind   = params.get('blind', '')
        proxy   = params.get('proxy', '')
        waf     = params.get('waf', False)
        mining  = params.get('mining', False)
        follow  = params.get('follow', False)
        skip    = params.get('skip', False)
        json_out= params.get('json_out', False)
        output  = params.get('output', '')

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
        if waf: parts.append("--waf-evasion")
        if mining: parts.append("--mining-parameters")
        if follow: parts.append("--follow-redirects")
        if skip: parts.append("--skip-bav")
        if json_out: parts.append("--format json")
        if output: parts.append(f"--output '{output}'")
        return " \\\n  ".join(parts)

    elif tool == "httpx":
        target  = params.get('target', 'targets.txt')
        ports   = params.get('ports', '80,443')
        threads = params.get('threads', '50')
        rate    = params.get('rate', '0')
        mc      = params.get('mc', '')
        proxy   = params.get('proxy', '')
        sc      = params.get('sc', True)
        title   = params.get('title', True)
        tech    = params.get('tech', True)
        ip      = params.get('ip', True)
        cl      = params.get('cl', False)
        cname   = params.get('cname', False)
        tls     = params.get('tls', False)
        follow  = params.get('follow', False)
        probe   = params.get('probe', False)
        silent  = params.get('silent', False)
        json_out= params.get('json_out', False)
        output  = params.get('output', '')

        is_file = not target.startswith("http")
        parts = [f"httpx {'-l' if is_file else '-u'} '{target}'"]
        if ports:
            parts.append(f"-p {ports}")
        parts.append(f"-t {threads}")
        if int(rate) > 0:
            parts.append(f"-rl {rate}")
        if mc: parts.append(f"-mc {mc}")
        if proxy: parts.append(f"-http-proxy '{proxy}'")
        if sc: parts.append("-sc")
        if title: parts.append("-title")
        if tech: parts.append("-tech-detect")
        if ip: parts.append("-ip")
        if cl: parts.append("-cl")
        if cname: parts.append("-cname")
        if tls: parts.append("-tls-probe")
        if follow: parts.append("-follow-redirects")
        if probe: parts.append("-probe")
        if silent: parts.append("-silent")
        if json_out: parts.append("-json")
        if output: parts.append(f"-o '{output}'")

        cmd = " \\\n  ".join(parts)
        cve = params.get('cve_lookup', False)
        if cve:
            cmd += f" \\\n  # Post-scan: python3 penkit_vuln.py --url '{target}'"
        return cmd

    elif tool == "wfuzz":
        wl      = params.get('wl', '/usr/share/wordlists/dirb/common.txt')
        wl2     = params.get('wl2', '')
        url     = params.get('url', 'https://target.com/FUZZ')
        method  = params.get('method', 'GET')
        threads = params.get('threads', '10')
        hc      = params.get('hc', '404')
        sc      = params.get('sc', '')
        hw      = params.get('hw', '')
        hl      = params.get('hl', '')
        hh      = params.get('hh', '')
        data    = params.get('data', '')
        header  = params.get('header', '')
        cookie  = params.get('cookie', '')
        proxy   = params.get('proxy', '')
        verbose = params.get('verbose', False)
        color   = params.get('color', True)
        tor     = params.get('tor', False)
        output  = params.get('output', '')

        parts = [f"wfuzz -w '{wl}'"]
        if wl2:
            parts.append(f"-w '{wl2}'")
        parts.append(f"-t {threads}")
        if hc: parts.append(f"--hc {hc}")
        if sc: parts.append(f"--sc {sc}")
        if hw: parts.append(f"--hw {hw}")
        if hl: parts.append(f"--hl {hl}")
        if hh: parts.append(f"--hh {hh}")
        if method.upper() != "GET":
            parts.append(f"-X {method.upper()}")
        if data: parts.append(f"-d '{data}'")
        if header:
            parts.append(f"-H '{header}'")
        if cookie:
            parts.append(f"-b '{cookie}'")
        if tor:
            parts.append("-p socks5://127.0.0.1:9050")
        elif proxy:
            parts.append(f"-p '{proxy}'")
        if verbose: parts.append("-v")
        if color: parts.append("--color")
        if output: parts.append(f"-f '{output},html'")
        parts.append(f"'{url}'")
        return " \\\n  ".join(parts)

    return None
