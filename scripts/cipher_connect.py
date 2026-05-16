"""
cipher_connect.py
Authenticated session manager for Thales CipherTrust Manager REST API.
Handles token acquisition, refresh, and reuse via context manager pattern.
"""

import os
import requests
import yaml
import logging
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


class CipherTrustSession:
    """
    Context manager for authenticated CipherTrust API sessions.

    Usage:
        with CipherTrustSession() as ct:
            keys = ct.get("/v1/vault/keys")
    """

    TOKEN_ENDPOINT = "/api/v1/auth/tokens"
    TOKEN_LIFESPAN_MINUTES = 30
    CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"

    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path or self.CONFIG_PATH)
        self.host = self.config["ciphertrust"]["host"].rstrip("/")
        self.token = None
        self.token_expires_at = None
        self.session = requests.Session()
        self.session.verify = self.config["ciphertrust"].get("verify_ssl", True)

    def _load_config(self, config_path: str) -> dict:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        # Resolve environment variable references
        ct = config["ciphertrust"]
        ct["username"] = os.environ.get("CT_USERNAME", ct.get("username", ""))
        ct["password"] = os.environ.get("CT_PASSWORD", ct.get("password", ""))
        return config

    def _authenticate(self):
        payload = {
            "grant_type": "password",
            "username": self.config["ciphertrust"]["username"],
            "password": self.config["ciphertrust"]["password"],
            "domain": self.config["ciphertrust"].get("domain", "root"),
        }
        url = f"{self.host}{self.TOKEN_ENDPOINT}"
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        self.token = data["jwt"]
        self.token_expires_at = datetime.utcnow() + timedelta(
            minutes=self.TOKEN_LIFESPAN_MINUTES - 2  # 2-minute buffer
        )
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})
        logger.info("CipherTrust authentication successful")

    def _ensure_token(self):
        if not self.token or datetime.utcnow() >= self.token_expires_at:
            self._authenticate()

    def get(self, endpoint: str, params: dict = None) -> dict:
        self._ensure_token()
        response = self.session.get(f"{self.host}/api{endpoint}", params=params)
        response.raise_for_status()
        return response.json()

    def post(self, endpoint: str, payload: dict) -> dict:
        self._ensure_token()
        response = self.session.post(f"{self.host}/api{endpoint}", json=payload)
        response.raise_for_status()
        return response.json()

    def patch(self, endpoint: str, payload: dict) -> dict:
        self._ensure_token()
        response = self.session.patch(f"{self.host}/api{endpoint}", json=payload)
        response.raise_for_status()
        return response.json()

    def delete(self, endpoint: str) -> bool:
        self._ensure_token()
        response = self.session.delete(f"{self.host}/api{endpoint}")
        response.raise_for_status()
        return True

    def __enter__(self):
        self._authenticate()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()
        logger.debug("CipherTrust session closed")
        return False
