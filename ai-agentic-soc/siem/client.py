from __future__ import annotations

import os
from typing import Any, Optional

import httpx

from schemas.wazuh import WazuhAgent, WazuhAlert

DEFAULT_URL = "https://localhost:55000"


class WazuhAPIError(Exception):
    pass


class WazuhClient:
    """Minimal client for the Wazuh 4.x REST API.

    Handles the JWT auth flow (POST /security/user/authenticate) and exposes
    the endpoints the investigation engine needs: security-event queries,
    agent lookups, and alert retrieval.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_tls: Optional[bool] = None,
        timeout: float = 30.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.base_url = (base_url or os.environ.get("WAZUH_API_URL", DEFAULT_URL)).rstrip("/")
        self.username = username or os.environ.get("WAZUH_API_USER", "")
        self.password = password or os.environ.get("WAZUH_API_PASSWORD", "")
        self.verify_tls = bool(
            verify_tls if verify_tls is not None
            else os.environ.get("WAZUH_VERIFY_TLS", "false").lower() == "true"
        )
        self._client = client or httpx.Client(verify=self.verify_tls, timeout=timeout)
        self._token: Optional[str] = None

    def authenticate(self) -> str:
        resp = self._client.post(
            f"{self.base_url}/security/user/authenticate",
            auth=(self.username, self.password),
        )
        self._raise_on_error(resp)
        self._token = resp.json()["data"]["token"]
        return self._token

    def query_alerts(
        self,
        q: Optional[str] = None,
        filters: Optional[dict[str, Any]] = None,
        limit: int = 100,
        offset: int = 0,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> list[WazuhAlert]:
        params: dict[str, Any] = {"offset": offset, "limit": limit}
        if q:
            params["q"] = q
        if since:
            params["start"] = since
        if until:
            params["end"] = until
        if filters:
            params.update(filters)
        data = self._get("/security-events", params=params)
        return [WazuhAlert.model_validate(item) for item in data.get("affected_items", [])]

    def get_alert(self, alert_id: str) -> Optional[WazuhAlert]:
        data = self._get("/security-events", params={"limit": 1, "filters.id": alert_id})
        items = data.get("affected_items", [])
        return WazuhAlert.model_validate(items[0]) if items else None

    def list_agents(self, active_only: bool = True) -> list[WazuhAgent]:
        params: dict[str, Any] = {"limit": 100}
        if active_only:
            params["q"] = "status=active"
        data = self._get("/agents", params=params)
        return [WazuhAgent.model_validate(item) for item in data.get("affected_items", [])]

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        data = self._get(f"/agents/{agent_id}")
        return data.get("affected_items", [{}])[0] if data.get("affected_items") else {}

    def close(self) -> None:
        self._client.close()

    def _get(self, path: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        if not self._token:
            self.authenticate()
        resp = self._client.get(
            f"{self.base_url}{path}",
            params=params,
            headers={"Authorization": f"Bearer {self._token}"},
        )
        if resp.status_code == 401 and self._token:
            self.authenticate()
            resp = self._client.get(
                f"{self.base_url}{path}",
                params=params,
                headers={"Authorization": f"Bearer {self._token}"},
            )
        self._raise_on_error(resp)
        return resp.json()["data"]

    @staticmethod
    def _raise_on_error(resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            raise WazuhAPIError(
                f"Wazuh API {resp.status_code}: {resp.text[:500]}"
            )