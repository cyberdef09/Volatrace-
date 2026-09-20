import subprocess
import os
import sys
import html
from datetime import datetime

def banner():
    print("=" * 65)
    print("      MemHawk - SOC Tier-2 Memory Forensics Dashboard       ")
    print("=" * 65)

def get_volatility_cmd():
    scripts_dir = os.path.join(sys.prefix, "Scripts")
    vol_candidates = [
        os.path.join(scripts_dir, "vol.exe"),
        os.path.join(scripts_dir, "vol.py"),
        "vol.py",
        "vol"
    ]
    for candidate in vol_candidates:
        if os.path.exists(candidate):
            return [sys.executable, candidate] if candidate.endswith(".py") else [candidate]
    return ["vol.py"]

def run_command(base_cmd, dump_path, plugin):
    cmd = base_cmd + ["-f", dump_path, plugin]
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return process.stdout
    except Exception as e:
        return f"[-] Error running {plugin}: {str(e)}"

def parse_table(raw_text):
    """Volatility ke raw output ko structured rows aur columns me convert karta hai."""
    lines = raw_text.strip().split("\n")
    data_lines = [l for l in lines if l and not l.startswith("Volatility 3") and not l.startswith("***")]
    
    if not data_lines:
        return [], []

    headers = [h.strip() for h in data_lines[0].split("\t") if h.strip()]
    rows = []
    for line in data_lines[1:]:
        parts = [p.strip() for p in line.split("\t")]
        if len(parts) >= len(headers):
            rows.append(parts[:len(headers)])
        elif len(parts) > 1:
            rows.append(parts)
    return headers, rows

def generate_responsive_dashboard(dump_path, pstree_raw, malfind_raw, netscan_raw):
    os.makedirs("output", exist_ok=True)
    report_file = f"output/Forensic_Dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    # Metric counts
    rwx_count = malfind_raw.count("PAGE_EXECUTE_READWRITE")
    rar_found = "Important.rar" in pstree_raw
    cmd_found = "cmd.exe" in pstree_raw

    # Parsing to structures
    pstree_h, pstree_r = parse_table(pstree_raw)
    malfind_h, malfind_r = parse_table(malfind_raw)
    netscan_h, netscan_r = parse_table(netscan_raw)

    def render_rows(rows, alert_col=None, alert_val=None):
        out = ""
        for r in rows:
            is_suspicious = False
            row_str = " ".join(r)
            if "PAGE_EXECUTE_READWRITE" in row_str or "Important.rar" in row_str or "cmd.exe" in row_str:
                is_suspicious = True

            tr_class = "danger-row" if is_suspicious else ""
            out += f"<tr class='{tr_class}'>"
            for idx, c in enumerate(r):
                val = html.escape(c)
                if "PAGE_EXECUTE_READWRITE" in val:
                    val = f"<span class='badge badge-red'>{val}</span>"
                elif "Important.rar" in val:
                    val = f"<span class='badge badge-red'>🚨 {val}</span>"
                elif "LISTENING" in val:
                    val = f"<span class='badge badge-blue'>{val}</span>"
                elif "CLOSED" in val:
                    val = f"<span class='badge badge-gray'>{val}</span>"
                out += f"<td>{val}</td>"
            out += "</tr>\n"
        return out

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MemHawk Triage Incident Report</title>
    <style>
        :root {{
            --bg: #090d16;
            --card-bg: #131b2e;
            --border: #232f48;
            --accent: #38bdf8;
            --danger: #ef4444;
            --success: #10b981;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
        }}
        * {{ box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ margin: 0; background: var(--bg); color: var(--text-main); padding: 24px; }}
        
        /* Top Hero Header */
        .top-nav {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 24px; }}
        .brand {{ display: flex; align-items: center; gap: 12px; }}
        .brand h1 {{ margin: 0; font-size: 24px; letter-spacing: -0.5px; color: #fff; }}
        .brand .tag {{ background: rgba(56, 189, 248, 0.1); color: var(--accent); padding: 4px 10px; border-radius: 20px; font-size: 12px; border: 1px solid var(--accent); }}

        /* Stat Metrics Cards */
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .stat-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 18px; }}
        .stat-card .label {{ font-size: 13px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-bottom: 6px; }}
        .stat-card .value {{ font-size: 28px; font-weight: 800; }}
        .stat-card.alert {{ border-left: 4px solid var(--danger); }}
        .stat-card.alert .value {{ color: var(--danger); }}

        /* Tabs Navigation */
        .tabs-header {{ display: flex; gap: 8px; border-bottom: 1px solid var(--border); margin-bottom: 16px; }}
        .tab-btn {{ background: transparent; border: none; color: var(--text-muted); padding: 10px 18px; font-size: 14px; font-weight: 600; cursor: pointer; border-bottom: 2px solid transparent; }}
        .tab-btn.active {{ color: var(--accent); border-bottom: 2px solid var(--accent); }}
        
        /* Search Bar */
        .search-container {{ margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }}
        .search-input {{ width: 100%; max-width: 400px; background: var(--card-bg); border: 1px solid var(--border); padding: 10px 14px; border-radius: 6px; color: #fff; outline: none; }}
        .search-input:focus {{ border-color: var(--accent); }}

        /* Data Tables */
        .table-wrap {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; overflow-x: auto; box-shadow: 0 4px 16px rgba(0,0,0,0.3); }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }}
        th {{ background: #17223b; padding: 14px 16px; color: #cbd5e1; font-weight: 600; border-bottom: 1px solid var(--border); position: sticky; top: 0; }}
        td {{ padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.04); color: #e2e8f0; }}
        tr:hover td {{ background: rgba(255,255,255,0.02); }}
        tr.danger-row td {{ background: rgba(239, 68, 68, 0.08); border-left: 2px solid var(--danger); }}

        /* Badges */
        .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
        .badge-red {{ background: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; }}
        .badge-blue {{ background: #0c4a6e; color: #7dd3fc; border: 1px solid #0284c7; }}
        .badge-gray {{ background: #334155; color: #94a3b8; }}

        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}
    </style>
</head>
<body>

    <div class="top-nav">
        <div class="brand">
            <h1>🦅 MemHawk Triage Analyzer</h1>
            <span class="tag">Incident: Evidence #01</span>
        </div>
        <div style="font-size: 13px; color: var(--text-muted);">
            Image: <strong>{html.escape(dump_path)}</strong> | UTC: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>

    <!-- Overview Stat Cards -->
    <div class="stats-grid">
        <div class="stat-card alert">
            <div class="label">Code Injection Hits</div>
            <div class="value">{rwx_count}</div>
        </div>
        <div class="stat-card alert">
            <div class="label">Phishing Artifacts</div>
            <div class="value">{'CRITICAL' if rar_found else 'CLEAN'}</div>
        </div>
        <div class="stat-card">
            <div class="label">Unauthorized Terminals</div>
            <div class="value">{'DETECTED' if cmd_found else 'NONE'}</div>
        </div>
        <div class="stat-card">
            <div class="label">Overall Triage Verdict</div>
            <div class="value" style="color: var(--danger);">COMPROMISED</div>
        </div>
    </div>

    <!-- Global Instant Search -->
    <div class="search-container">
        <input type="text" id="filterInput" class="search-input" placeholder="🔍 Instant search process, PID, IP, or path...">
    </div>

    <!-- Interactive Tabs -->
    <div class="tabs-header">
        <button class="tab-btn active" onclick="switchTab('tab-injection', this)">🚨 Injected Code ({len(malfind_r)})</button>
        <button class="tab-btn" onclick="switchTab('tab-process', this)">🌳 Process Hierarchy ({len(pstree_r)})</button>
        <button class="tab-btn" onclick="switchTab('tab-network', this)">🌐 Network Sockets ({len(netscan_r)})</button>
    </div>

    <!-- Tab 1: Code Injection -->
    <div id="tab-injection" class="tab-content active">
        <div class="table-wrap">
            <table id="table-injection">
                <thead>
                    <tr>{''.join([f'<th>{html.escape(h)}</th>' for h in malfind_h])}</tr>
                </thead>
                <tbody>
                    {render_rows(malfind_r)}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Tab 2: Process Tree -->
    <div id="tab-process" class="tab-content">
        <div class="table-wrap">
            <table id="table-process">
                <thead>
                    <tr>{''.join([f'<th>{html.escape(h)}</th>' for h in pstree_h])}</tr>
                </thead>
                <tbody>
                    {render_rows(pstree_r)}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Tab 3: Network -->
    <div id="tab-network" class="tab-content">
        <div class="table-wrap">
            <table id="table-network">
                <thead>
                    <tr>{''.join([f'<th>{html.escape(h)}</th>' for h in netscan_h])}</tr>
                </thead>
                <tbody>
                    {render_rows(netscan_r)}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function switchTab(tabId, el) {{
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            el.classList.add('active');
        }}

        // Real-time table filter logic
        document.getElementById('filterInput').addEventListener('keyup', function() {{
            const query = this.value.toLowerCase();
            const activeTable = document.querySelector('.tab-content.active table tbody');
            const rows = activeTable.querySelectorAll('tr');
            
            rows.forEach(row => {{
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(query) ? '' : 'none';
            }});
        }});
    </script>
</body>
</html>
"""
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    return report_file

def main():
    banner()
    if len(sys.argv) < 2:
        print("Usage: python memhawk.py <dump_path>")
        sys.exit(1)

    dump_path = sys.argv[1]
    if not os.path.exists(dump_path):
        print(f"[-] File '{dump_path}' nahi mili!")
        sys.exit(1)

    base_cmd = get_volatility_cmd()
    print(f"[*] Analyzing Memory Image: {dump_path}")
    
    print("[+] Extracting Process Execution Tree...")
    pstree_raw = run_command(base_cmd, dump_path, "windows.pstree")

    print("[+] Scanning Injected Shellcode (malfind)...")
    malfind_raw = run_command(base_cmd, dump_path, "windows.malfind")

    print("[+] Recovering Active Network Sockets (netscan)...")
    netscan_raw = run_command(base_cmd, dump_path, "windows.netscan")

    print("[*] Generating Modern Forensic Dashboard...")
    report_path = generate_responsive_dashboard(dump_path, pstree_raw, malfind_raw, netscan_raw)

    print(f"\n[✓] Investigation Complete!")
    print(f"[✓] Dashboard Ready: {os.path.abspath(report_path)}")

if __name__ == "__main__":
    main()