import sys
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

from src.auth import SpotifyAuth
from src.fuzzer import FuzzingEngine
from src.rate_limiter import RateLimitTester
from src.error_detector import ErrorDetector
from src.reporter import Reporter

console = Console()

TARGETS = [
    {"endpoint": "/search",       "param": "q",    "rate_params": {"q": "test", "type": "track"}},
    {"endpoint": "/tracks/bad_id", "param": "id",  "rate_params": {}},
    {"endpoint": "/artists/bad_id","param": "id",  "rate_params": {}},
]

def print_banner():
    console.print(Panel("""
[bold cyan]   ___   ____  ____   ____                      _ __       
  / _ | / __ \\/ _  | / __/__ ______ ______(_) /___ __
 / __ |/ /_/ / // / _\\ \\/ -_) __/ // / __/ / __/ // /
/_/ |_/ .___/____/ /___/\\__/\\__/\\_,_/_/ /_/\\__/\\_, / 
      /_/    [/bold cyan][yellow]Fuzzing Suite v1.0[/yellow][bold cyan]              /___/[/bold cyan]

[white]Target:[/white]      [green]Spotify Web API[/green]
[white]Modules:[/white]     [yellow]Fuzzer · Rate Limiter · Error Detector · Reporter[/yellow]
[white]Author:[/white]      [cyan]VladimirRamirez07[/cyan]
""", style="cyan"))

def run_fuzzing(auth_headers: dict, reporter: Reporter):
    console.print(Panel("[bold]MODULE 1 — Fuzzing Engine[/bold]", style="cyan"))
    engine = FuzzingEngine(auth_headers)

    for target in TARGETS[:2]:  # Solo los primeros 2 para no spammear
        engine.fuzz_endpoint(target["endpoint"], target["param"])

    reporter.save_json(engine.results, "fuzzing")
    return engine.results

def run_rate_limit(auth_headers: dict, reporter: Reporter):
    console.print(Panel("[bold]MODULE 2 — Rate Limit Tester[/bold]", style="cyan"))
    tester = RateLimitTester(auth_headers)

    result = tester.run_burst_test(
        endpoint="/search",
        params={"q": "test", "type": "track"},
        total_requests=60,
        delay=0.05,
    )

    reporter.save_json([result], "rate_limit")
    return [result]

def run_error_detection(auth_headers: dict, reporter: Reporter):
    console.print(Panel("[bold]MODULE 3 — Error Disclosure Detector[/bold]", style="cyan"))
    detector = ErrorDetector(auth_headers)

    all_findings = []
    for target in TARGETS[:2]:
        findings = detector.scan_endpoint(target["endpoint"], target["param"])
        all_findings.extend(findings)

    reporter.save_json(all_findings, "errors")
    return all_findings

def main():
    print_banner()

    # Autenticación
    console.print("\n[bold white]🔑 Authenticating with Spotify...[/bold white]")
    try:
        auth = SpotifyAuth()
        token = auth.get_token()
        console.print(f"[green]✅ Token obtained:[/green] {token[:25]}...")
    except Exception as e:
        console.print(f"[bold red]❌ Auth failed:[/bold red] {e}")
        sys.exit(1)

    reporter = Reporter()

    # Módulo 1 — Fuzzing
    if Confirm.ask("\n▶ Run [cyan]Fuzzing Engine[/cyan]?", default=True):
        fuzz_results = run_fuzzing(auth.auth_headers, reporter)
    else:
        fuzz_results = []

    # Módulo 2 — Rate Limit
    if Confirm.ask("\n▶ Run [cyan]Rate Limit Tester[/cyan]?", default=True):
        rate_results = run_rate_limit(auth.auth_headers, reporter)
    else:
        rate_results = []

    # Módulo 3 — Error Detection
    if Confirm.ask("\n▶ Run [cyan]Error Disclosure Detector[/cyan]?", default=True):
        error_findings = run_error_detection(auth.auth_headers, reporter)
    else:
        error_findings = []

    # Reporte final
    console.print("\n[bold white]📄 Generating final report...[/bold white]")
    reporter.generate_html_report(fuzz_results, rate_results, error_findings)
    reporter.print_final_summary(error_findings)

if __name__ == "__main__":
    main()