from __future__ import annotations

from fastapi.testclient import TestClient

from apis.edr.app import app


def test_health():
    with TestClient(app) as c:
        assert c.get("/health").json() == {"status": "ok"}


def test_endpoints_seeded():
    with TestClient(app) as c:
        eps = c.get("/endpoints").json()
        assert len(eps) == 5
        assert {e["endpoint_id"] for e in eps} == {
            "ep-001", "ep-002", "ep-003", "ep-004", "ep-005"}


def test_ransomware_endpoint_has_suspicious_processes():
    with TestClient(app) as c:
        procs = c.get("/endpoints/ep-005/processes").json()
        suspicious = [p for p in procs if p["suspicious"]]
        indicators = {p["indicator"] for p in suspicious}
        assert "bulk_encryption" in indicators
        assert "vssadmin_shadow_delete" in indicators


def test_brute_force_endpoint_outbound_to_bad_ip():
    with TestClient(app) as c:
        net = c.get("/endpoints/ep-002/network").json()
        dsts = {n["dst_ip"] for n in net}
        assert "203.0.113.77" in dsts


def test_ransomware_endpoint_file_creations():
    with TestClient(app) as c:
        files = c.get("/endpoints/ep-005/files").json()
        assert len(files) > 0
        assert all(f["path"].endswith(".encrypted") for f in files)


def test_missing_endpoint_404():
    with TestClient(app) as c:
        assert c.get("/endpoints/ep-999").status_code == 404