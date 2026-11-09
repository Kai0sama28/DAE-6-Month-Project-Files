from __future__ import annotations

import os
from typing import Any, Optional

import httpx

from schemas.wazuh import WazuhAlert

DEFAULT_URL = "https://localhost:9200"
DEFAULT_INDEX_PATTERN = "wazuh-alerts-*"

_TIMESTAMP_FIELD = "timestamp"


class IndexerAPIError(Exception):
    pass


class IndexerClient:
    """Minimal client for the Wazuh indexer (OpenSearch 2.x) REST API.

    Wazuh 4.x removed the 3.x ``/security-events`` API route, so alerts are
    only reachable through the indexer that filebeat ships them into. That is
    also where the Wazuh dashboard reads them from.

    Documents in ``wazuh-alerts-*`` carry the same fields as the manager's
    ``alerts.json``, so results are returned as :class:`WazuhAlert` and
    :func:`siem.normalizer.normalize_wazuh_alert` works unchanged.

    Auth is HTTP Basic (no JWT, no token refresh). Credentials come from
    ``WAZUH_INDEXER_USER`` / ``WAZUH_INDEXER_PASSWORD``.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        index_pattern: Optional[str] = None,
        verify_tls: Optional[bool] = None,
        timeout: float = 30.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.base_url = (base_url or os.environ.get("WAZUH_INDEXER_URL", DEFAULT_URL)).rstrip("/")
        self.username = username or os.environ.get("WAZUH_INDEXER_USER", "")
        self.password = password or os.environ.get("WAZUH_INDEXER_PASSWORD", "")
        self.index_pattern = (
            index_pattern or os.environ.get("WAZUH_INDEXER_INDEX", DEFAULT_INDEX_PATTERN)
        )
        self.verify_tls = bool(
            verify_tls if verify_tls is not None
            else os.environ.get("WAZUH_VERIFY_TLS", "false").lower() == "true"
        )
        self._client = client or httpx.Client(
            auth=(self.username, self.password),
            verify=self.verify_tls,
            timeout=timeout,
        )
        self._owns_client = client is None

    def ping(self) -> bool:
        """Return True when the indexer answers at all, whatever the HTTP status.

        Callers that care about health should inspect the cluster status
        themselves; this only proves the network path and credentials work.
        """
        try:
            self._get("/_cluster/health")
            return True
        except httpx.HTTPError:
            return False

    def query_alerts(
        self,
        q: Optional[str] = None,
        filters: Optional[dict[str, Any]] = None,
        limit: int = 100,
        offset: int = 0,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> list[WazuhAlert]:
        """Return alerts matching the query, newest first.

        ``filters`` uses the Wazuh API dotted-field convention
        (``{"rule.id": "5763", "agent.id": "002"}``); values may be scalars or
        lists. ``since`` / ``until`` are ISO-8601 strings applied to
        ``timestamp``.
        """
        body: dict[str, Any] = {
            "size": limit,
            "from": offset,
            "track_total_hits": True,
            "query": _build_query(q, filters, since, until),
            "sort": [{_TIMESTAMP_FIELD: {"order": "desc"}}],
        }
        data = self._request(f"/{self.index_pattern}/_search", body, {"hits": {"hits": []}})
        return [_to_alert(hit) for hit in data.get("hits", {}).get("hits", [])]

    def count_alerts(
        self,
        filters: Optional[dict[str, Any]] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> int:
        """Return how many alerts match the filters, ignoring pagination."""
        body = {"query": _build_query(None, filters, since, until)}
        data = self._request(f"/{self.index_pattern}/_count", body, {"count": 0})
        return int(data.get("count", 0))

    def get_alert(self, alert_id: str) -> Optional[WazuhAlert]:
        """Look up one alert by its Wazuh alert id, falling back to the indexer doc id."""
        found = self.query_alerts(filters={"id": alert_id}, limit=1)
        if found:
            return found[0]
        data = self._get_doc(f"/{self.index_pattern}/_doc/{alert_id}")
        return _to_alert({"_id": alert_id, "_source": data}) if data else None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _request(
        self,
        path: str,
        body: Optional[dict[str, Any]],
        default: dict[str, Any],
    ) -> dict[str, Any]:
        resp = self._client.post(
            f"{self.base_url}{path}",
            json=body,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 404 and _is_index_not_found(resp):
            return dict(default)
        self._raise_on_error(resp)
        payload = resp.json()
        return payload if isinstance(payload, dict) else dict(default)

    def _get_doc(self, path: str) -> Optional[dict[str, Any]]:
        resp = self._client.get(f"{self.base_url}{path}")
        if resp.status_code == 404:
            return None
        self._raise_on_error(resp)
        payload = resp.json()
        if not isinstance(payload, dict) or not payload.get("found"):
            return None
        source = payload.get("_source")
        return source if isinstance(source, dict) else None

    def _get(self, path: str) -> httpx.Response:
        return self._client.get(f"{self.base_url}{path}")

    @staticmethod
    def _raise_on_error(resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            raise IndexerAPIError(f"Wazuh indexer {resp.status_code}: {resp.text[:500]}")


def _to_alert(hit: dict[str, Any]) -> WazuhAlert:
    source = dict(hit.get("_source") or {})
    if not source.get("id"):
        source["id"] = hit.get("_id")
    return WazuhAlert.model_validate(source)


def _build_query(
    q: Optional[str],
    filters: Optional[dict[str, Any]],
    since: Optional[str],
    until: Optional[str],
) -> dict[str, Any]:
    clauses: list[dict[str, Any]] = list(_parse_q(q))
    for field, value in (filters or {}).items():
        clauses.append(_clause(field, value))
    window: dict[str, str] = {}
    if since:
        window["gte"] = since
    if until:
        window["lte"] = until
    if window:
        clauses.append({"range": {_TIMESTAMP_FIELD: window}})
    if not clauses:
        return {"match_all": {}}
    return {"bool": {"filter": clauses}}


def _parse_q(q: Optional[str]) -> list[dict[str, Any]]:
    """Parse the ``field=value;field!=value`` subset of the Wazuh API q syntax."""
    clauses: list[dict[str, Any]] = []
    for token in (q or "").split(";"):
        token = token.strip()
        if not token:
            continue
        if "!=" in token:
            field, _, value = token.partition("!=")
            clauses.append({"bool": {"must_not": [_clause(field.strip(), value)]}})
        elif "=" in token:
            field, _, value = token.partition("=")
            clauses.append(_clause(field.strip(), value))
        else:
            raise ValueError(
                f"unsupported q expression {token!r}; use 'field=value' or 'field!=value'"
            )
    return clauses


def _clause(field: str, value: Any) -> dict[str, Any]:
    if not field:
        raise ValueError("filter field cannot be empty")
    if field == _TIMESTAMP_FIELD or field.endswith("." + _TIMESTAMP_FIELD):
        return {"range": {field: {"gte": value, "lte": value}}}
    if isinstance(value, (list, tuple, set)):
        values = [str(v) for v in value]
        if len(values) == 1:
            return {"term": {field: values[0]}}
        return {"terms": {field: values}}
    return {"term": {field: str(value)}}


def _is_index_not_found(resp: httpx.Response) -> bool:
    try:
        payload = resp.json()
    except ValueError:
        return False
    error = payload.get("error", {}) if isinstance(payload, dict) else {}
    if isinstance(error, dict):
        return error.get("type") == "index_not_found_exception"
    return False