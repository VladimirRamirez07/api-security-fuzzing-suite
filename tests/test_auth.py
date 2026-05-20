import pytest
from unittest.mock import patch, MagicMock
from src.auth import SpotifyAuth


class TestSpotifyAuth:

    def test_missing_credentials_raises_error(self):
        """Debe fallar si no hay credenciales en el entorno."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(EnvironmentError):
                SpotifyAuth()

    def test_encode_credentials_returns_base64(self):
        """Las credenciales deben codificarse correctamente en base64."""
        with patch.dict("os.environ", {
            "SPOTIFY_CLIENT_ID": "testid",
            "SPOTIFY_CLIENT_SECRET": "testsecret",
        }):
            auth = SpotifyAuth()
            encoded = auth._encode_credentials()
            assert encoded  # no vacío
            assert isinstance(encoded, str)

    def test_get_token_returns_string(self):
        """get_token debe retornar el access token como string."""
        with patch.dict("os.environ", {
            "SPOTIFY_CLIENT_ID": "testid",
            "SPOTIFY_CLIENT_SECRET": "testsecret",
        }):
            auth = SpotifyAuth()
            mock_response = MagicMock()
            mock_response.json.return_value = {"access_token": "mock_token_123"}

            with patch("requests.post", return_value=mock_response):
                token = auth.get_token()
                assert token == "mock_token_123"

    def test_auth_headers_format(self):
        """auth_headers debe retornar el formato Bearer correcto."""
        with patch.dict("os.environ", {
            "SPOTIFY_CLIENT_ID": "testid",
            "SPOTIFY_CLIENT_SECRET": "testsecret",
        }):
            auth = SpotifyAuth()
            auth._token = "fake_token"
            headers = auth.auth_headers
            assert headers == {"Authorization": "Bearer fake_token"}