import requests
import time
from dataclasses import dataclass, field
from typing import Any
from rich.console import Console
from rich.progress import track
from src.config import Config

console = Console()

@dataclass
class FuzzResult:
    endpoint: str
    payload: Any
    status_code: int
    response_time: float
    response_body: str
    error_leaked: bool = False
    interesting: bool = False
    notes: str = ""

class FuzzingEngine:
    """
    Core fuzzing engine. Sends malformed, unexpected, and boundary-breaking
    payloads to API endpoints and records anomalous responses.
    """

    # Payloads que usaremos para atacar los endpoints
    FUZZ_PAYLOADS = {
        "sql_injection": [
            "' OR '1'='1", "'; DROP TABLE users;--", "1 UNION SELECT NULL--",
            "' OR 1=1--", "admin'--",
        ],
        "special_chars": [
            "", " ", "null", "undefined", "NaN", "Infinity", "-Infinity",
            "<script>alert(1)</script>", "../../etc/passwd",
            "%00", "%0a", "%0d%0a", "\x00", "\r\n",
        ],
        "type_confusion": [
            None, True, False, 0, -1, 99999999999,
            [], {}, [None], {"key": "value"},
            3.14, -0.0,
        ],
        "oversized": [
            "A" * 1000,
            "A" * 10000,
            "🔥" * 500,
            "SELECT" * 200,
        ],
        "boundary_values": [
            "0", "-1", "2147483647", "2147483648",
            "-2147483648", "9999999999999999999",
        ],
    }

    # Palabras clave que indican info interna expuesta en errores
    SENSITIVE_KEYWORDS = [
        "stack trace", "traceback", "exception", "error at line",
        "internal server", "database", "sql", "mongodb", "redis",
        "password", "secret", "token", "api_key", "private",
        "undefined", "cannot read property", "null pointer",
        "file not found", "/home/", "/var/", "c:\\",
    ]

    def __init__(self, auth_headers: dict):
        self.headers = auth_headers
        self.base_url = Config.SPOTIFY_BASE_URL
        self.results: list[FuzzResult] = []

    def _check_info_leak(self, response_body: str) -> bool:
        """Detecta si la respuesta expone información interna."""
        body_lower = response_body.lower()
        return any(keyword in body_lower for keyword in self.SENSITIVE_KEYWORDS)

    def _is_interesting(self, status_code: int, response_time: float) -> bool:
        """Marca respuestas que merecen atención especial."""
        return (
            status_code in [500, 502, 503]  # Server errors
            or status_code == 200           # Debería haber fallado pero no lo hizo
            or response_time > 5.0          # Respuesta sospechosamente lenta
        )

    def fuzz_endpoint(self, endpoint: str, param: str, method: str = "GET") -> list[FuzzResult]:
        """Fuzzea un endpoint específico con todos los payloads."""
        results = []
        all_payloads = [
            p for category in self.FUZZ_PAYLOADS.values() for p in category
        ]

        console.print(f"\n[bold cyan]🔍 Fuzzing:[/bold cyan] {endpoint} → param: [yellow]{param}[/yellow]")

        for payload in track(all_payloads, description="Sending payloads..."):
            try:
                start = time.time()
                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=self.headers,
                    params={param: payload},
                    timeout=Config.REQUEST_TIMEOUT,
                )
                elapsed = round(time.time() - start, 3)
                body = response.text

                result = FuzzResult(
                    endpoint=endpoint,
                    payload=payload,
                    status_code=response.status_code,
                    response_time=elapsed,
                    response_body=body[:500],  # limitamos para no llenar memoria
                    error_leaked=self._check_info_leak(body),
                    interesting=self._is_interesting(response.status_code, elapsed),
                )

                if result.error_leaked:
                    result.notes = "⚠️  Possible info disclosure in error response"
                    console.print(f"  [bold red]LEAK DETECTED[/bold red] payload={str(payload)[:40]} status={result.status_code}")
                elif result.interesting:
                    console.print(f"  [bold yellow]INTERESTING[/bold yellow] payload={str(payload)[:40]} status={result.status_code}")

                results.append(result)
                time.sleep(0.1)  # Respetar rate limits

            except requests.exceptions.Timeout:
                results.append(FuzzResult(
                    endpoint=endpoint, payload=payload,
                    status_code=0, response_time=Config.REQUEST_TIMEOUT,
                    response_body="TIMEOUT", interesting=True,
                    notes="Request timed out — possible DoS vector"
                ))
            except requests.exceptions.RequestException as e:
                console.print(f"  [red]Request error:[/red] {e}")

        self.results.extend(results)
        return results