import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SPOTIFY_BASE_URL = os.getenv("SPOTIFY_BASE_URL", "https://api.spotify.com/v1")

    SPOTIFY_ENDPOINTS = [
        "/search",
        "/tracks/{id}",
        "/albums/{id}",
        "/artists/{id}",
        "/playlists/{id}",
        "/recommendations",
    ]

    REQUEST_TIMEOUT = 10
    RATE_LIMIT_REQUESTS = 50
    RATE_LIMIT_WINDOW = 30  # segundos