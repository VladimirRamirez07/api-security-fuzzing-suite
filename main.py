import sys
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

from src.auth import GitHubAuth
from src.fuzzer import FuzzingEngine
from src.rate_limiter import RateLimitTester
from src.error_detector import ErrorDetector
from src.reporter import Reporter

console = Console()

TARGETS = [
    {"endpoint": "/search/repositories", "param": "q",        "rate_params": {"q": "python", "per_page": "1"}},
    {"endpoint": "/users/torvalds",       "param": "username", "rate_params": {}},
    {"endpoint": "/search/users",         "param": "q",        "rate_params": {"q": "test"}},
]

def print_banner():
    console.print(Panel("""
[bold cyan]   ___   ____  ____   ____                      _ __       
  / _ | / __ \\/ _  | / __/__ ______ ______(_) /___ __
 / __ |/ /_/ / // | _\\ \\/ -_) __/ // / __/ / __/ // /
/_/ |_/ .___/____/ /___/\\__/\\__/\\_,_/_/ /_/\\__/\\_, / 
      /_/    [/bold cyan][yellow]Fuzzing Suite v1.0[/yellow][bold cyan]              /___/[/bold cyan]

[white]Target:[/white]      [green]GitHub REST API v3[/green]
[white]Modules:[/white]     [yellow]Fuzzer · Rate Limiter · Error Detector · Reporter[/yellow]
[white]Author:[/white]      [cyan]VladimirRamirez07[/cyan]
""", style="cyan"))

def run_fuzzing(auth_headers: dict, reporter: Reporter):
    console.print(Panel("[bold]MODULE 1 — Fuzzing Engine[/bold]", style="cyan"))
    engine = FuzzingEngine(auth_headers)

    for target in TARGETS[:2]:
        engine.fuzz_endpoint(target["endpoint"], target["param"])

    reporter.save_json(engine.results, "fuzzing")
    return engine.results

def run_rate_limit(auth_headers: dict, reporter: Reporter):
    console.print(Panel("[bold]MODULE 2 — Rate Limit Tester[/bold]", style="cyan"))
    tester = RateLimitTester(auth_headers)

    result = tester.run_burst_test(
        endpoint="/search/repositories",
        params={"q": "python", "per_page": "1"},
        total_requests=40,
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

    console.print("\n[bold white]🔑 Authenticating with GitHub...[/bold white]")
    try:
        auth = GitHubAuth()
        user = auth.verify()
        console.print(f"[green]✅ Authenticated as:[/green] {user['login']} ({user.get('name', 'N/A')})")
    except Exception as e:
        console.print(f"[bold red]❌ Auth failed:[/bold red] {e}")
        sys.exit(1)

    reporter = Reporter()

    if Confirm.ask("\n▶ Run [cyan]Fuzzing Engine[/cyan]?", default=True):
        fuzz_results = run_fuzzing(auth.auth_headers, reporter)
    else:
        fuzz_results = []

    if Confirm.ask("\n▶ Run [cyan]Rate Limit Tester[/cyan]?", default=True):
        rate_results = run_rate_limit(auth.auth_headers, reporter)
    else:
        rate_results = []

    if Confirm.ask("\n▶ Run [cyan]Error Disclosure Detector[/cyan]?", default=True):
        error_findings = run_error_detection(auth.auth_headers, reporter)
    else:
        error_findings = []

    console.print("\n[bold white]📄 Generating final report...[/bold white]")
    reporter.generate_html_report(fuzz_results, rate_results, error_findings)
    reporter.print_final_summary(error_findings)

if __name__ == "__main__":
    main()