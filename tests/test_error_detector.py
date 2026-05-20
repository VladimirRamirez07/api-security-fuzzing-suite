import pytest
from unittest.mock import patch, MagicMock
from src.error_detector.error_detector import ErrorDetector, ErrorFinding


class TestErrorDetector:

    def setup_method(self):
        self.detector = ErrorDetector(
            auth_headers={"Authorization": "Bearer fake_token"}
        )

    def test_detects_critical_stack_trace(self):
        """Debe detectar stack traces como CRITICAL."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Traceback (most recent call last): file.py line 42"
        mock_response.json.side_effect = Exception("not json")

        findings = self.detector._analyze_response("/search", "bad_input", mock_response)
        severities = [f.severity for f in findings]
        assert "CRITICAL" in severities

    def test_detects_high_database_leak(self):
        """Debe detectar menciones de base de datos como HIGH."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "database error: connection refused"
        mock_response.json.side_effect = Exception("not json")

        findings = self.detector._analyze_response("/search", "bad", mock_response)
        severities = [f.severity for f in findings]
        assert "HIGH" in severities

    def test_clean_response_returns_no_findings(self):
        """Una respuesta limpia no debe generar findings."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = '{"error": {"status": 400, "message": "Bad request"}}'
        mock_response.json.return_value = {"error": {"status": 400, "message": "Bad request"}}

        findings = self.detector._analyze_response("/search", "bad", mock_response)
        assert findings == []