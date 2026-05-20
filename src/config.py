import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    GITHUB_BASE_URL = os.getenv("GITHUB_BASE_URL", "https://api.github.com")

    GITHUB_ENDPOINTS = [
        "/users/{username}",
        "/repos/{owner}/{repo}",
        "/search/repositories",
        "/search/users",
        "/repos/{owner}/{repo}/issues",
        "/repos/{owner}/{repo}/commits",
    ]

    REQUEST_TIMEOUT = 10
    RATE_LIMIT_REQUESTS = 60
    RATE_LIMIT_WINDOW = 60  # segundos