import json
import os
from datetime import datetime
from dataclasses import asdict
from rich.console import Console
from rich.panel import Panel

console = Console()

class Reporter:
    """
    Generates structured reports from fuzzing, rate limit,
    and error disclosure findings. Outputs JSON + HTML.
    """

    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs("results/fuzzing", exist_ok=True)
        os.makedirs("results/rate_limit", exist_ok=True)
        os.makedirs("results/errors", exist_ok=True)

    def save_json(self, data: list, category: str, filename: str = None) -> str:
        fname = filename or f"{category}_{self.timestamp}.json"
        path = f"results/{category}/{fname}"

        serializable = []
        for item in data:
            try:
                serializable.append(asdict(item))
            except Exception:
                serializable.append(str(item))

        with open(path, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2, default=str)

        console.print(f"  [green]✅ JSON saved:[/green] {path}")
        return path

    def generate_html_report(
        self,
        fuzz_results: list,
        rate_results: list,
        error_findings: list,
    ) -> str:

        critical = [f for f in error_findings if f.severity == "CRITICAL"]
        high     = [f for f in error_findings if f.severity == "HIGH"]
        medium   = [f for f in error_findings if f.severity == "MEDIUM"]
        low      = [f for f in error_findings if f.severity == "LOW"]

        interesting_fuzz = [r for r in fuzz_results if r.interesting]
        leaked_fuzz      = [r for r in fuzz_results if r.error_leaked]

        def findings_rows(findings):
            rows = ""
            for f in findings:
                color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#4488ff"}.get(f.severity, "#fff")
                rows += f"""
                <tr>
                    <td><span class="badge" style="background:{color}">{f.severity}</span></td>
                    <td>{f.category}</td>
                    <td><code>{f.trigger_payload[:50]}</code></td>
                    <td><code>{f.evidence[:80]}</code></td>
                    <td>{f.recommendation[:80]}</td>
                </tr>"""
            return rows

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>API Security Report — {self.timestamp}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; padding: 2rem; }}
        h1 {{ color: #58a6ff; margin-bottom: 0.3rem; }}
        h2 {{ color: #79c0ff; margin: 2rem 0 1rem; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }}
        .meta {{ color: #8b949e; margin-bottom: 2rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.2rem; text-align: center; }}
        .card .number {{ font-size: 2.5rem; font-weight: bold; }}
        .card .label {{ color: #8b949e; font-size: 0.85rem; margin-top: 0.3rem; }}
        .critical {{ color: #ff4444; }}
        .high {{ color: #ff8800; }}
        .medium {{ color: #ffcc00; }}
        .low {{ color: #4488ff; }}
        .ok {{ color: #3fb950; }}
        table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
        th {{ background: #21262d; padding: 0.75rem 1rem; text-align: left; color: #8b949e; font-size: 0.85rem; }}
        td {{ padding: 0.75rem 1rem; border-top: 1px solid #30363d; font-size: 0.9rem; vertical-align: top; }}
        tr:hover td {{ background: #1c2128; }}
        .badge {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; color: #000; }}
        code {{ background: #21262d; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.82rem; color: #79c0ff; word-break: break-all; }}
        .no-findings {{ color: #3fb950; padding: 1rem; background: #161b22; border-radius: 8px; text-align: center; }}
    </style>
</head>
<body>
    <h1>🔐 API Security Fuzzing Report</h1>
    <p class="meta">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &nbsp;|&nbsp; Target: GitHub REST API v3</p>

    <h2>📊 Executive Summary</h2>
    <div class="grid">
        <div class="card"><div class="number critical">{len(critical)}</div><div class="label">Critical Findings</div></div>
        <div class="card"><div class="number high">{len(high)}</div><div class="label">High Findings</div></div>
        <div class="card"><div class="number medium">{len(medium)}</div><div class="label">Medium Findings</div></div>
        <div class="card"><div class="number low">{len(low)}</div><div class="label">Low Findings</div></div>
        <div class="card"><div class="number" style="color:#58a6ff">{len(fuzz_results)}</div><div class="label">Total Fuzz Requests</div></div>
        <div class="card"><div class="number" style="color:#ff8800">{len(interesting_fuzz)}</div><div class="label">Interesting Responses</div></div>
        <div class="card"><div class="number" style="color:#ff4444">{len(leaked_fuzz)}</div><div class="label">Potential Leaks</div></div>
    </div>

    <h2>🔎 Error Disclosure Findings</h2>
    {"<table><thead><tr><th>Severity</th><th>Category</th><th>Payload</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>" + findings_rows(error_findings) + "</tbody></table>" if error_findings else '<div class="no-findings">✅ No information disclosure detected</div>'}

    <h2>⚡ Rate Limit Analysis</h2>
    {"".join([f'''<div class="card" style="text-align:left;margin-bottom:1rem"><b>Requests sent:</b> {r.total_requests} &nbsp;|&nbsp; <b>Blocked:</b> {r.blocked_requests} &nbsp;|&nbsp; <b>First block at:</b> #{r.first_block_at or "Never"} &nbsp;|&nbsp; <b>Retry-After:</b> {f"{r.retry_after}s" if r.retry_after else "Not present"}<br><br><small style="color:#8b949e">{r.notes}</small></div>''' for r in rate_results]) if rate_results else '<div class="no-findings">No rate limit tests run</div>'}

    <h2>🧪 Interesting Fuzz Results</h2>
    {"<table><thead><tr><th>Endpoint</th><th>Payload</th><th>Status</th><th>Response Time</th><th>Notes</th></tr></thead><tbody>" + "".join([f"<tr><td><code>{r.endpoint}</code></td><td><code>{str(r.payload)[:50]}</code></td><td>{r.status_code}</td><td>{r.response_time}s</td><td>{r.notes}</td></tr>" for r in interesting_fuzz]) + "</tbody></table>" if interesting_fuzz else '<div class="no-findings">✅ No anomalous responses detected</div>'}

</body>
</html>"""

        path = f"results/security_report_{self.timestamp}.html"
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

        console.print(Panel(
            f"[bold green]✅ HTML Report generated:[/bold green] {path}",
            style="green"
        ))
        return path

    def print_final_summary(self, error_findings: list):
        critical = len([f for f in error_findings if f.severity == "CRITICAL"])
        high     = len([f for f in error_findings if f.severity == "HIGH"])
        medium   = len([f for f in error_findings if f.severity == "MEDIUM"])

        console.print(Panel(
            f"""[bold]Security Assessment Complete[/bold]

[red]Critical:[/red] {critical}
[orange3]High:[/orange3]     {high}
[yellow]Medium:[/yellow]   {medium}

{'[bold red]⚠  ACTION REQUIRED — Critical findings detected[/bold red]' if critical else '[bold green]✅ No critical findings[/bold green]'}""",
            title="🔐 Final Report",
            style="cyan",
        ))