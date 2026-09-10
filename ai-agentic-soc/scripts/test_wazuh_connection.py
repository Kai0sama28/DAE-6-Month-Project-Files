from __future__ import annotations

#!/usr/bin/env python3
"""Verify the agent can talk to the live Wazuh API.

Prints auth status, registered agents, and a sample of recent security events.
Credentials come from WAZUH_API_USER / WAZUH_API_PASSWORD in the environment
or the local .env file.
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

    client = WazuhClient()
    try:
        token = client.authenticate()
        print(f"[ok] authenticated to Wazuh API ({client.base_url})")
        print(f"     token: {token[:24]}... ({len(token)} chars)")

        agents = client.list_agents()
        print(f"[ok] {len(agents)} active agent(s):")
        for a in agents:
            print(f"     - id={a.id}  name={a.name}  ip={a.ip}")

        alerts = client.query_alerts(limit=5)
        print(f"[ok] {len(alerts)} recent security events (sample of 5):")
        for raw in alerts:
            n = normalize_wazuh_alert(raw)
            mitre = ",".join(n.mitre_technique_ids) or "-"
            print(f"     - [{n.severity}/10] rule {n.source_rule_id} "
                  f"{n.title} (MITRE: {mitre}) agent={n.agent_name} src={n.source_ip}")
        return 0
    except (WazuhAPIError, httpx.HTTPError) as exc:
        print(f"[error] could not reach Wazuh API: {exc}")
        print("        Check WAZUH_API_URL / WAZUH_API_USER / WAZUH_API_PASSWORD in .env")
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())