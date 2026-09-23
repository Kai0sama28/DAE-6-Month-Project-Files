# Windows Wazuh Agent Deployment — Status / Handoff

**Date:** 2026-09-23 (updated — previously 2026-09-19)
**Agent target:** This Windows host ("Kai")
**Manager:** Wazuh 4.14.7 (single-node Docker on the Mac), API :55000, dashboard :443
**Existing agent:** Kali VM (UTM) on the Mac's 10.11.0.0/22 network, already enrolled.

## Status: RESOLVED — agent enrolled and online ✅

- Installed: `C:\Program Files (x86)\ossec-agent` (wazuh-agent.exe v4.14.7).
- **Enrolled as `007 DESKTOP-VCKJCPV`** (2026-09-23). `client.keys` populated; connected to
  manager on TCP 1514; service `WazuhSvc` running. Manager pushed shared config and the agent
  reloaded/reconnected cleanly.
- Network path to `10.11.3.185` confirmed good (ping + TCP 1514/1515 OPEN).

### What was wrong and the fix

- `ossec.conf` still had the placeholder `<address>0.0.0.0</address>` — the MSI reconfiguration
  never applied `WAZUH_MANAGER` (MSI failures: 1602/1603/1625, and 1316 "specified account
  already exists"). Agent started then exited with `(4112) Invalid server address` /
  `(1215) No client configured`.
- **Fix:** edited `<address>` to `10.11.3.185` directly (original backed up as
  `ossec.conf.bak`), then started `WazuhSvc`. Enrollment succeeded without a registration
  password (manager currently allows passwordless enrollment).

## Notes for later

- If you want a custom agent name/group, re-enroll via `WAZUH_AGENT_NAME=` /
  `WAZUH_AGENT_GROUP=` (or set in the `<enrollment>` block and restart the service).
- Optional hardening once enrolled: set the agent group, enable syscheck/fim modules as
  needed for the triage engine.

## Original install command (network now works; direct config edit used instead)

```
msiexec /i "C:\Users\Kai\Downloads\wazuh-agent-4.14.7-1.msi" WAZUH_MANAGER="10.11.3.185" /quiet
```

## Recommended verification next steps

1. Confirm in the Wazuh dashboard under **Agents** (agent 007, DESKTOP-VCKJCPV,
   status Active/Connected), and/or via the Wazuh API `/agents` (e.g.
   `scripts/test_wazuh_connection.py` from the project venv on the Mac).
2. Optionally add the agent to a group and enable syscheck/fim tuning for the triage engine.