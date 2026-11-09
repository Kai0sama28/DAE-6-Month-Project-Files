import socket
import threading
import time
from datetime import datetime

import uvicorn

from apis.clients import EDRClient, IdentityClient
from apis.edr.app import app as edr_app
from apis.identity.app import app as identity_app
from investigation.evidence import gather_evidence
from schemas import RelatedEvent
from siem.normalizer import normalize_wazuh_alert

BRUTE_FORCE_ALERT = {
    "id": "1726100520.123456",
    "timestamp": "2026-09-10T14:22:07.481+0000",
    "rule": {
        "id": "100010",
        "level": 10,
        "description": "SSHD brute force: multiple failed logins from same source in 2 minutes",
        "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
        "groups": ["authentication_failures"],
    },
    "agent": {"id": "011", "name": "kali-lab-02", "ip": "10.11.3.57"},
    "data": {"srcip": "203.0.113.77", "srcport": 51422, "dstuser": "root"},
    "full_log": "sshd[2211]: Failed password for root from 203.0.113.77 port 51422 ssh2",
}


class _Server(uvicorn.Server):
    def install_signal_handlers(self):
        pass


def _serve(app):
    port = _free_port()
    server = _Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    server.thread = thread
    return server, port


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_end_to_end_evidence_gathering():
    id_server, id_port = _serve(identity_app)
    edr_server, edr_port = _serve(edr_app)
    try:
        identity = IdentityClient(base_url=f"http://127.0.0.1:{id_port}")
        edr = EDRClient(base_url=f"http://127.0.0.1:{edr_port}")

        alert = normalize_wazuh_alert(BRUTE_FORCE_ALERT)

        def siem_probe():
            return [RelatedEvent(
                alert_id="1726100520.888",
                event_time=datetime.utcnow(),
                rule_id="5716",
                title="sshd: authentication failure",
                severity=5,
                summary="6 failed logins from 203.0.113.77 in the last 120s",
            )]

        bundle = gather_evidence(alert, identity, edr, siem_probe=siem_probe)

        assert bundle.alert.dst_user == "root"
        assert bundle.siem is not None
        assert bundle.siem.related_count == 1
        assert bundle.endpoint["hostname"] == "kali-lab-02"
        assert bundle.processes
        suspicious = [p for p in bundle.processes if p.get("suspicious")]
        assert any(p["indicator"] == "repeated_ssh_handshake" for p in suspicious)
        assert len(bundle.network) > 0
        assert "203.0.113.77" in {n["dst_ip"] for n in bundle.network}
        assert bundle.evidence_summary.startswith("alert:")
    finally:
        id_server.should_exit = True
        edr_server.should_exit = True
        id_server.thread.join(timeout=5)
        edr_server.thread.join(timeout=5)