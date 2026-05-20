import pytest
from unittest.mock import patch, MagicMock
from src.fuzzer.fuzzer import FuzzingEngine, FuzzResult


class TestFuzzingEngine:

    def setup_method(self):
        self.engine = FuzzingEngine(
            auth_headers={"Authorization": "Bearer fake_token"}
        )

    def test_check_info_leak_detects_keywords(self):
        """Debe detectar keywords sensibles en respuestas."""
        assert self.engine._check_info_leak("stack trace found at line 42") is True
        assert self.engine._check_info_leak("internal server error") is True
        assert self.engine._check_info_leak("everything is fine") is False

    def test_is_interesting_detects_500(self):
        """Status 500 debe marcarse como interesante."""
        assert self.engine._is_interesting(500, 1.0) is True

    def test_is_interesting_detects_slow_response(self):
        """Respuestas lentas deben marcarse como interesantes."""
        assert self.engine._is_interesting(200, 6.0) is True

    def test_is_interesting_normal_response(self):
        """Respuestas normales no deben marcarse como interesantes."""
        assert self.engine._is_interesting(400, 0.5) is False

    def test_fuzz_endpoint_returns_results(self):
        """fuzz_endpoint debe retornar lista de FuzzResult."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = '{"error": "bad request"}'

        with patch("requests.get", return_value=mock_response):
            results = self.engine.fuzz_endpoint("/search", "q")
            assert isinstance(results, list)
            assert len(results) > 0
            assert all(isinstance(r, FuzzResult) for r in results)