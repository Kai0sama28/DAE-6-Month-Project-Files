# Weekly Status Update — AI-Agentic SOC Triage & Investigation Engine

**Week ending:** 2026-10-01
**Project:** AI-Agentic SOC Triage & Investigation Engine (capstone, board week 5)
**Author:** Kyrell Green

## 1. Summary

This week I closed out the alert-ingestion blocker on the SIEM pillar. I got a real Wazuh
brute-force detection (rule 5763) firing end to end from live agent telemetry, then found and
fixed a design flaw that would have broken alert retrieval in the agent: Wazuh 4.x has no alerts
API route, so alerts have to come from the indexer.

## 2. What I completed

**a. Reverse-engineered the Wazuh sshd rule chain.** Brute-force runs were producing
5710 x1219 / 5712 x25 / 5758 x152 but never 5763. Root cause: `labtester` did not exist on the
Kali host, so every log line read `Failed password for invalid user ...`, which matches rule 5710.
Because 5710 becomes the last matched rule id, the downstream 5760 rule can never match.
Requirement for 5763 is therefore: a **valid** account, then 8 x 5760 within 120 seconds from one
source IP (`frequency=8`, `timeframe=120`, `ignore=60`, `same_source_ip`), level 10, MITRE T1110.

**b. Produced the 5763 detections.** Created the `labtester` test account on Kali
(`shell=/bin/bash`, confirmed via `/syscollector/002/users`) and re-ran Hydra against the Kali
agent with the real password excluded from the wordlist.

| Date (UTC) | Rule | Level | Agent | Source | User |
|---|---|---|---|---|---|
| 2026-09-30 18:35:30 → 18:42:39 | 5763 | 10 | 002 Kali | 192.168.64.3 | labtester |
| 2026-10-01 16:23:32 and 16:25:00 | 5763 | 10 | 002 Kali | 192.168.64.3 | labtester |

7 x 5763 total, backed by 599 rule 5760/5763 alerts in the last 30 days. Retained in
`/var/ossec/logs/alerts/2026/Sep/ossec-alerts-30.json.gz` and indexed as 7 documents in
`wazuh-alerts-4.x-*`, so they are visible in the Wazuh dashboard for screenshot evidence.

**c. Found and fixed the alert-API blocker.** `GET /security-events` returns 404 on Wazuh
4.14.7 — that route existed in 3.x only. Confirmed three ways: `api.log` shows a router miss,
`openapi.json` lists 150 paths with no alerts route, and the framework source only implements
`event:ingest` (pushing events *into* analysisd). Alerts live solely in the indexer, which is
also what the dashboard reads.

**d. Built `siem/indexer_client.py`.** HTTP Basic client for the OpenSearch indexer that mirrors
the existing `WazuhClient` surface, so callers swap without changes:
`query_alerts()` / `count_alerts()` / `get_alert()` / `ping()`, plus translation of the Wazuh
API conventions (`filters={"rule.id": "5763"}`, `q="rule.id=5763;agent.id!=002"`,
`since`/`until`, `offset`/`limit`) into indexer DSL. Results come back as `WazuhAlert`, so
`siem/normalizer.py` needed no changes. Added **19 tests** (20 → **39 passing**) and updated
`.env.example`, `tests/conftest.py`, `README.md`, `docs/ARCHITECTURE.md`, and
`scripts/test_wazuh_connection.py` — which now verifies the API, the indexer and the agent's
alert pipeline in one command.

## 3. Blockers / gotchas hit

- **Invalid vs valid usernames decide the whole chain.** `5710` shadows `5760`. Any brute-force
  test that uses a username absent from `/etc/passwd` will never produce 5760 or 5763.
- **Wazuh alerts are indexer-only in 4.x.** Any integration written against
  `/security-events` silently fails with 404.
- Rotated alert files (`ossec-alerts-*.json.gz`) are not shipped to the indexer; the indexer only
  gets the live `alerts.json`, so alerts are queryable there only while still in that file.
- The indexer `admin` account is a superuser with its password hardcoded in the compose file —
  needs a least-privilege reader before this goes in a portfolio repo.

## 4. Next week

1. Repoint the evidence gatherer (`investigation/evidence.py`) at `IndexerClient` and re-run the
   end-to-end test against the live indexer.
2. Create a read-only indexer user scoped to `wazuh-alerts-*`; populate `ai-agentic-soc/.env`
   (still missing) with API + indexer credentials.
3. Capture screenshot evidence for the submission: dashboard rule 5763 view, `fast.log` from the
   Suricata replay, TheHive case.
4. Wazuh ↔ Suricata integration is still not done — add an `eve.json` localfile plus the
   `0475-suricata_rules.xml` ruleset so network detections reach the same alert pipeline.
5. Start the weeks 5–7 LangGraph supervisor agent now that evidence sources are settled.