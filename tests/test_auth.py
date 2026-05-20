import pytest
from unittest.mock import patch, MagicMock
from src.auth import GitHubAuth


class TestGitHubAuth:

    def test_missing_token_raises_error(self):
        """Debe fallar si no hay token en el entorno."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(EnvironmentError):
                GitHubAuth()

    def test_auth_headers_format(self):
        """auth_headers debe retornar el formato Bearer correcto."""
        with patch.dict("os.environ", {"GITHUB_TOKEN": "fake_token"}):
            auth = GitHubAuth()
            headers = auth.auth_headers
            assert headers["Authorization"] == "Bearer fake_token"
            assert headers["Accept"] == "application/vnd.github+json"
            assert "X-GitHub-Api-Version" in headers

    def test_verify_returns_user_data(self):
        """verify() debe retornar datos del usuario autenticado."""
        with patch.dict("os.environ", {"GITHUB_TOKEN": "fake_token"}):
            auth = GitHubAuth()
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "login": "VladimirRamirez07",
                "name": "Vladimir Ramirez"
            }

            with patch("requests.get", return_value=mock_response):
                user = auth.verify()
                assert user["login"] == "VladimirRamirez07"

    def test_token_present_no_error(self):
        """No debe lanzar error si el token está presente."""
        with patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_testtoken123"}):
            auth = GitHubAuth()
            assert auth.token == "ghp_testtoken123"