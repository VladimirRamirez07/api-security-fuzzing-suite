import os
import base64
import requests
from dotenv import load_dotenv

load_dotenv()

class SpotifyAuth:
    """
    Handles Spotify OAuth2 Client Credentials Flow.
    Used for testing endpoints that require authentication.
    """

    TOKEN_URL = "https://accounts.spotify.com/api/token"

    def __init__(self):
        self.client_id = os.getenv("SPOTIFY_CLIENT_ID")
        self.client_secret = os.getenv("SPOTIFY_CLIENT_SECRET")
        self._token: str | None = None

        if not self.client_id or not self.client_secret:
            raise EnvironmentError(
                "Missing SPOTIFY_CLIENT_ID or SPOTIFY_CLIENT_SECRET in .env"
            )

    def _encode_credentials(self) -> str:
        raw = f"{self.client_id}:{self.client_secret}"
        return base64.b64encode(raw.encode()).decode()

    def get_token(self) -> str:
        """Fetches a fresh access token via Client Credentials."""
        headers = {
            "Authorization": f"Basic {self._encode_credentials()}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {"grant_type": "client_credentials"}

        response = requests.post(self.TOKEN_URL, headers=headers, data=data)
        response.raise_for_status()

        self._token = response.json()["access_token"]
        return self._token

    @property
    def auth_headers(self) -> dict:
        """Returns headers ready to use in any request."""
        if not self._token:
            self.get_token()
        return {"Authorization": f"Bearer {self._token}"}