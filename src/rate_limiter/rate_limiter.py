import requests
import time
import threading
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table
from src.config import Config

console = Console()

@dataclass
class RateLimitResult:
    total_requests: int
    blocked_requests: int
    successful_requests: int
    first_block_at: int | None       # En qué request número bloqueó
    retry_after: int | None          # Segundos que pide esperar
    rate_limit_headers: dict         # Headers relevantes encontrados
    window_seconds: float
    notes: str = ""

class RateLimitTester:
    """
    Tests how well an API enforces rate limiting.
    Sends bursts of requests and analyzes when/how the API blocks them.
    Checks for proper Retry-After headers and rate limit disclosure.
    """

    RATE_LIMIT_HEADERS = [
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "retry-after",
        "x-rate-limit-limit",
        "x-rate-limit-remaining",
        "ratelimit-limit",
        "ratelimit-remaining",
    ]

    def __init__(self, auth_headers: dict):
        self.headers = auth_headers
        self.base_url = Config.SPOTIFY_BASE_URL
        self.results: list[RateLimitResult] = []

    def _extract_rate_headers(self, response: requests.Response) -> dict:
        """Extrae headers relacionados a rate limiting de la respuesta."""
        found = {}
        for header in self.RATE_LIMIT_HEADERS:
            value = response.headers.get(header)
            if value:
                found[header] = value
        return found

    def run_burst_test(
        self,
        endpoint: str,
        params: dict,
        total_requests: int = 60,
        delay: float = 0.05,
    ) -> RateLimitResult:
        """
        Envía una ráfaga de requests y mide cuándo la API empieza a bloquear.
        """
        console.print(f"\n[bold cyan]⚡ Rate Limit Burst Test:[/bold cyan] {endpoint}")
        console.print(f"   Sending [yellow]{total_requests}[/yellow] requests with {delay}s delay\n")

        blocked = 0
        successful = 0
        first_block_at = None
        retry_after = None
        rate_limit_headers = {}
        start_time = time.time()

        for i in range(1, total_requests + 1):
            try:
                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=self.headers,
                    params=params,
                    timeout=Config.REQUEST_TIMEOUT,
                )

                # Capturar headers de rate limit
                found_headers = self._extract_rate_headers(response)
                if found_headers:
                    rate_limit_headers.update(found_headers)

                if response.status_code == 429:
                    blocked += 1
                    if first_block_at is None:
                        first_block_at = i
                        ra = response.headers.get("retry-after")
                        retry_after = int(ra) if ra else None
                        console.print(f"  [bold red]🚫 BLOCKED[/bold red] at request #{i} — status 429")

                elif response.status_code == 200:
                    successful += 1
                    if i % 10 == 0:
                        console.print(f"  [green]✓[/green] {i}/{total_requests} requests OK")
                else:
                    console.print(f"  [yellow]⚠[/yellow]  Request #{i} → status {response.status_code}")

            except requests.exceptions.RequestException as e:
                console.print(f"  [red]Error on request #{i}:[/red] {e}")
                blocked += 1

            time.sleep(delay)

        elapsed = round(time.time() - start_time, 2)

        # Análisis de resultado
        notes = []
        if first_block_at is None:
            notes.append("⚠️  No rate limiting detected after {total_requests} requests — possible misconfiguration")
        if not rate_limit_headers:
            notes.append("⚠️  No rate limit headers found — poor API transparency")
        if retry_after is None and blocked > 0:
            notes.append("⚠️  Blocked but no Retry-After header — client can't know when to retry")

        result = RateLimitResult(
            total_requests=total_requests,
            blocked_requests=blocked,
            successful_requests=successful,
            first_block_at=first_block_at,
            retry_after=retry_after,
            rate_limit_headers=rate_limit_headers,
            window_seconds=elapsed,
            notes=" | ".join(notes) if notes else "✅ Rate limiting appears properly configured",
        )

        self._print_summary(result)
        self.results.append(result)
        return result

    def _print_summary(self, result: RateLimitResult):
        """Imprime un resumen visual del test."""
        table = Table(title="Rate Limit Test Summary", style="cyan")
        table.add_column("Metric", style="bold white")
        table.add_column("Value", style="yellow")

        table.add_row("Total Requests", str(result.total_requests))
        table.add_row("Successful", str(result.successful_requests))
        table.add_row("Blocked (429)", str(result.blocked_requests))
        table.add_row("First Block At", f"Request #{result.first_block_at}" if result.first_block_at else "Never")
        table.add_row("Retry-After Header", f"{result.retry_after}s" if result.retry_after else "Not present")
        table.add_row("Rate Limit Headers Found", str(len(result.rate_limit_headers)))
        table.add_row("Test Duration", f"{result.window_seconds}s")
        table.add_row("Notes", result.notes)

        console.print(table)