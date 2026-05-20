import os
from dotenv import load_dotenv

load_dotenv()

class GitHubAuth:
    """
    Handles GitHub API authentication via Personal Access Token.
    """

    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN")

        if not self.token:
            raise EnvironmentError(
                "Missing GITHUB_TOKEN in .env"
            )

    @property
    def auth_headers(self) -> dict:
        """Returns headers ready to use in any GitHub API request."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def verify(self) -> dict:
        """Verifica que el token es válido consultando el usuario actual."""
        import requests
        response = requests.get(
            "https://api.github.com/user",
            headers=self.auth_headers,
            timeout=10,
        )
        response.raise_for_status()
        return response.json()