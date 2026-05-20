import requests
import json
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table
from src.config import Config

console = Console()

@dataclass
class ErrorFinding:
    endpoint: str
    trigger_payload: str
    status_code: int
    severity: str          # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    category: str          # Tipo de leak detectado
    evidence: str          # Fragmento de la respuesta que lo prueba
    recommendation: str

class ErrorDetector:
    """
    Probes API endpoints with crafted inputs designed to trigger
    verbose error messages. Analyzes responses for information disclosure:
    stack traces, internal paths, DB names, framework details, etc.
    """

    # Payloads específicamente diseñados para triggear errores verbose
    ERROR_TRIGGERS = {
        "invalid_id_formats": [
            "undefined", "null", "NaN", "0", "-1",
            "99999999999999", "' OR 1=1", "<>", "{}",
        ],
        "missing_required": [
            "", "   ", "\t", "\n",
        ],
        "type_breaking": [
            "true", "false", "[]", "{}", "[[]]",
            "1e999", "1/0",
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f",
        ],
        "format_breaking": [
            "2024-99-99",           # fecha inválida
            "not-a-spotify-id",     # ID mal formado
            "spotify:track:",       # URI incompleto
            "http://evil.com",      # URL injection
        ],
    }

    # Patrones que revelan info interna — clasificados por severidad
    LEAK_PATTERNS = {
        "CRITICAL": [
            ("stack trace", "Stack trace exposed"),
            ("traceback (most recent", "Python traceback exposed"),
            ("at com.", "Java stack trace exposed"),
            ("microsoft.aspnet", "ASP.NET framework disclosed"),
            ("password=", "Credentials in error message"),
            ("secret=", "Secret key in error message"),
            ("api_key=", "API key in error message"),
        ],
        "HIGH": [
            ("internal server error", "Verbose internal error"),
            ("sqlexception", "SQL exception exposed"),
            ("database error", "Database error exposed"),
            ("mongodb", "MongoDB mentioned in error"),
            ("redis", "Redis mentioned in error"),
            ("psycopg2", "PostgreSQL driver exposed"),
            ("/home/", "Unix home path exposed"),
            ("c:\\users\\", "Windows path exposed"),
            ("/var/www/", "Server path exposed"),
        ],
        "MEDIUM": [
            ("version", "Version info in error"),
            ("framework", "Framework info disclosed"),
            ("debug", "Debug mode possibly enabled"),
            ("exception", "Exception details exposed"),
            ("undefined method", "Method name exposed"),
            ("cannot read property", "JS runtime error exposed"),
        ],
        "LOW": [
            ("invalid parameter", "Parameter name confirmed"),
            ("required field", "Field name confirmed"),
            ("must be", "Validation logic exposed"),
        ],
    }

    def __init__(self, auth_headers: dict):
        self.headers = auth_headers
        self.base_url = Config.SPOTIFY_BASE_URL
        self.findings: list[ErrorFinding] = []

    def _analyze_response(self, endpoint: str, payload: str, response: requests.Response) -> list[ErrorFinding]:
        """Analiza una respuesta buscando patrones de info disclosure."""
        findings = []
        body = response.text.lower()

        try:
            json_body = response.json()
            body_str = json.dumps(json_body).lower()
        except Exception:
            body_str = body

        for severity, patterns in self.LEAK_PATTERNS.items():
            for keyword, description in patterns:
                if keyword in body_str:
                    # Extraer contexto alrededor del keyword
                    idx = body_str.find(keyword)
                    evidence = body_str[max(0, idx-30):idx+80].strip()

                    finding = ErrorFinding(
                        endpoint=endpoint,
                        trigger_payload=str(payload)[:100],
                        status_code=response.status_code,
                        severity=severity,
                        category=description,
                        evidence=f"...{evidence}...",
                        recommendation=self._get_recommendation(severity, description),
                    )
                    findings.append(finding)
                    break  # Un finding por severidad por response

        return findings

    def _get_recommendation(self, severity: str, category: str) -> str:
        recommendations = {
            "CRITICAL": "Immediately sanitize error responses. Never expose stack traces in production.",
            "HIGH": "Configure generic error messages. Hide infrastructure details from API consumers.",
            "MEDIUM": "Review error handling middleware. Ensure debug mode is disabled in production.",
            "LOW": "Consider generic validation messages to avoid confirming parameter names.",
        }
        return recommendations.get(severity, "Review error handling practices.")

    def scan_endpoint(self, endpoint: str, param: str) -> list[ErrorFinding]:
        """Escanea un endpoint buscando information disclosure en errores."""
        console.print(f"\n[bold cyan]🔎 Error Disclosure Scan:[/bold cyan] {endpoint}")
        findings = []

        all_triggers = [
            payload
            for payloads in self.ERROR_TRIGGERS.values()
            for payload in payloads
        ]

        for payload in all_triggers:
            try:
                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=self.headers,
                    params={param: payload},
                    timeout=Config.REQUEST_TIMEOUT,
                )

                new_findings = self._analyze_response(endpoint, payload, response)

                for f in new_findings:
                    severity_color = {
                        "CRITICAL": "bold red",
                        "HIGH": "red",
                        "MEDIUM": "yellow",
                        "LOW": "blue",
                    }.get(f.severity, "white")

                    console.print(
                        f"  [{severity_color}][{f.severity}][/{severity_color}] "
                        f"{f.category} — payload: {str(payload)[:30]}"
                    )
                    findings.append(f)

            except requests.exceptions.RequestException as e:
                console.print(f"  [red]Request error:[/red] {e}")

        self.findings.extend(findings)
        self._print_summary(findings, endpoint)
        return findings

    def _print_summary(self, findings: list[ErrorFinding], endpoint: str):
        if not findings:
            console.print(f"  [green]✅ No information disclosure detected in {endpoint}[/green]")
            return

        table = Table(title=f"Error Disclosure Findings — {endpoint}", style="red")
        table.add_column("Severity", style="bold")
        table.add_column("Category")
        table.add_column("Payload")
        table.add_column("Evidence")

        for f in findings:
            color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "blue"}.get(f.severity, "white")
            table.add_row(
                f"[{color}]{f.severity}[/{color}]",
                f.category,
                f.trigger_payload[:40],
                f.evidence[:60],
            )

        console.print(table)