from __future__ import annotations

import os

from typing import Optional

import httpx


class IdentityAPIError(Exception):
    pass


class IdentityClient:
    """HTTP client for the identity mock API (Okta/Azure AD-shaped)."""

    def __init__(self, base_url: Optional[str] = None,
                 client: Optional[httpx.Client] = None) -> None:
        self.base_url = (base_url or os.environ.get("IDENTITY_API_URL",
                                                    "http://localhost:8001")).rstrip("/")
        self._client = client or httpx.Client(timeout=20)

    def list_users(self, username: Optional[str] = None) -> list[dict]:
        params = {"username": username} if username else None
        return self._get("/users", params=params)

    def get_user(self, user_id: int) -> dict:
        return self._get(f"/users/{user_id}")

    def get_user_by_username(self, username: str) -> Optional[dict]:
        for user in self.list_users(username=username):
            return user
        return None

    def login_history(self, user_id: int, limit: int = 100,
                      since: Optional[str] = None) -> list[dict]:
        params: dict = {"limit": limit}
        if since:
            params["since"] = since
        return self._get(f"/users/{user_id}/login_history", params=params)

    def risk_factors(self, user_id: int) -> dict:
        return self._get(f"/users/{user_id}/risk_factors")

    def _get(self, path: str, params: Optional[dict] = None) -> object:
        resp = self._client.get(f"{self.base_url}{path}", params=params)
        if resp.status_code >= 400:
            raise IdentityAPIError(f"identity API {resp.status_code}: {resp.text[:300]}")
        return resp.json()

    def close(self) -> None:
        self._client.close()


class EDRAPIError(Exception):
    pass


class EDRClient:
    """HTTP client for the EDR mock API (CrowdStrike Falcon-shaped)."""

    def __init__(self, base_url: Optional[str] = None,
                 client: Optional[httpx.Client] = None) -> None:
        self.base_url = (base_url or os.environ.get("EDR_API_URL",
                                                    "http://localhost:8002")).rstrip("/")
        self._client = client or httpx.Client(timeout=20)

    def list_endpoints(self) -> list[dict]:
        return self._get("/endpoints")

    def get_endpoint(self, endpoint_id: str) -> dict:
        return self._get(f"/endpoints/{endpoint_id}")

    def processes(self, endpoint_id: str, limit: int = 200,
                  since: Optional[str] = None) -> list[dict]:
        params: dict = {"limit": limit}
        if since:
            params["since"] = since
        return self._get(f"/endpoints/{endpoint_id}/processes", params=params)

    def network(self, endpoint_id: str, limit: int = 200,
                since: Optional[str] = None) -> list[dict]:
        params: dict = {"limit": limit}
        if since:
            params["since"] = since
        return self._get(f"/endpoints/{endpoint_id}/network", params=params)

    def files(self, endpoint_id: str, limit: int = 200,
              since: Optional[str] = None) -> list[dict]:
        params: dict = {"limit": limit}
        if since:
            params["since"] = since
        return self._get(f"/endpoints/{endpoint_id}/files", params=params)

    def _get(self, path: str, params: Optional[dict] = None) -> object:
        resp = self._client.get(f"{self.base_url}{path}", params=params)
        if resp.status_code >= 400:
            raise EDRAPIError(f"EDR API {resp.status_code}: {resp.text[:300]}")
        return resp.json()

    def close(self) -> None:
        self._client.close()