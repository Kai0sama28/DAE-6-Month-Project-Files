from __future__ import annotations

#!/usr/bin/env python3
"""Verify the agent can talk to the live Wazuh stack.

Prints API auth status, registered agents, and a sample of recent security
events. Alerts are read from the Wazuh indexer because Wazuh 4.x has no
/security-events route. Credentials come from WAZUH_API_USER /
WAZUH_API_PASSWORD and WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD in the
environment or the local .env file.
"""

import os
import sys
from pathlib import Path

import httpx

from siem.normalizer import normalize_wazuh_alert

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass


def main() -> int:
    from siem.client import WazuhClient, WazuhAPIError
    from siem.indexer_client import IndexerClient, IndexerAPIError

    client = WazuhClient()
    indexer = IndexerClient()
    try:
        token = client.authenticate()
        print(f"[ok] authenticated to Wazuh API ({client.base_url})")
        print(f"     token: {token[:24]}... ({len(token)} chars)")

        agents = client.list_agents()
        print(f"[ok] {len(agents)} active agent(s):")
        for a in agents:
            print(f"     - id={a.id}  name={a.name}  ip={a.ip}")

        if not indexer.ping():
            print(f"[error] Wazuh indexer unreachable at {indexer.base_url}")
            print("        Check WAZUH_INDEXER_URL / _USER / _PASSWORD in .env")
            return 1
        print(f"[ok] Wazuh indexer reachable ({indexer.base_url}, {indexer.index_pattern})")

        alerts = indexer.query_alerts(limit=5)
        print(f"[ok] {len(alerts)} recent security events (sample of 5):")
        for raw in alerts:
            n = normalize_wazuh_alert(raw)
            mitre = ",".join(n.mitre_technique_ids) or "-"
            print(f"     - [{n.severity}/10] rule {n.source_rule_id} "
                  f"{n.title} (MITRE: {mitre}) agent={n.agent_name} src={n.source_ip}")

        brute_force = indexer.count_alerts(
            filters={"rule.id": ["5760", "5763"]},
            since="now-30d",
        )
        print(f"[ok] {brute_force} ssh brute-force alert(s) (rules 5760/5763) in the last 30 days")
        return 0
    except (WazuhAPIError, IndexerAPIError, httpx.HTTPError) as exc:
        print(f"[error] could not reach the Wazuh stack: {exc}")
        return 1
    finally:
        client.close()
        indexer.close()


if __name__ == "__main__":
    sys.exit(main())