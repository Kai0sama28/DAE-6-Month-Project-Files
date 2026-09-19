# Windows Wazuh Agent Deployment — Status / Handoff

**Date:** 2026-09-19
**Agent target:** This Windows host ("Kai")
**Manager:** Wazuh 4.14.7 (single-node Docker on the Mac), API :55000, dashboard :443
**Existing agent:** Kali VM (UTM) on the Mac's 10.11.0.0/22 network, already enrolled.

## Status: BLOCKED ON NETWORK

- Installer staged: `C:\Users\Kai\Downloads\wazuh-agent-4.14.7-1.msi`
  (5.9 MB, verified download from `https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi`, ETag `25e7f21e4d076221f54e9e877e0b5787`)
- Manager IP to use: `10.11.3.185`
- Ports required: TCP 1514 (events), TCP 1515 (agent enrollment)
- **Port check failed from this host:** 1514 UNREACHABLE, 1515 UNREACHABLE; ping to
  10.11.3.185 from this host -> "Packet filtered" via NAT gateway (67.83.230.160) on
  172.31.96.0/20. The Windows host and the Mac have no routable path (different networks).

## Install command (once network is fixed)

```
msiexec /i "C:\Users\Kai\Downloads\wazuh-agent-4.14.7-1.msi" WAZUH_MANAGER="10.11.3.185" /quiet
```

Agent name defaults to the Windows hostname; optional `WAZUH_AGENT_NAME=` and
`WAZUH_AGENT_GROUP=` can be appended.

## Recommended next steps

1. When on the same network as the Mac (or over VPN/port-forward):
   - Re-test: `nc -vz 10.11.3.185 1514` and `nc -vz 10.11.3.185 1515`
   - Run the msiexec command above (run as admin)
   - Back on the server/UTM side, make sure the manager's agent registration
     (port 1515) is enabled and a group exists if you plan to use custom groups.
2. Verify enrollment in the Wazuh dashboard under **Agents** (or via
   `scripts/test_wazuh_connection.py` + the Wazuh API `/agents` endpoint).
3. Optional hardening once enrolled: set the agent group, enable syscheck/fim
   modules as needed for the triage engine.