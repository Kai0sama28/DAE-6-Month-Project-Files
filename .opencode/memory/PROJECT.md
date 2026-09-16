# PROJECT — Living Memory Journal

Owner: Kyrell Green — 6-month cybersecurity program (SOC/security analyst track).
This journal is loaded every session in this workspace via `opencode.json` `instructions`.
Update it per the rules in AGENTS.md. NEVER store secrets/passwords/API keys here.

---

## Current status

**Latest: IR methodology rubric deliverable completed 2026-09-15 (this Windows/WSL box);
ready to commit + push with the rest of the semester work.**

New file: `cyber_threats_and_vulnerabilities_1/Incident_Response_Methodology.md` — a full
documentation deliverable for the "Document Incident Response Methodology" rubric. It uses the
SSH brute-force (Wazuh rule 100010 / MITRE T1110) scenario and TheHive as the case management
system. Sections map 1:1 to rubric lines (initial-response runbook, TheHive components,
escalation D1–D5 + comms, completed IR template, IR principles). Complements the existing
`Incident_Response_Plan.md`.

**Capstone (unchanged from 09-14): ai-agentic-soc weeks 1–4 committed, working tree clean on the
Mac. Next capstone step: weeks 5–7 LangGraph supervisor.**

What exists today (capstone):
- `ai-agentic-soc/docs/ARCHITECTURE.md` — design update adopting **real Wazuh 4.14.7** as the
  SIEM + alert source (supersedes the mock-SIEM design v0.2).
- `schemas/` — internal Pydantic models (Alert, Identity, EDR, SIEM) + Wazuh raw models.
- `siem/client.py` — Wazuh REST client (JWT auth via `/security/user/authenticate`, token
  refresh, `/security-events` + `/agents` queries).
- `siem/normalizer.py` — Wazuh alert → internal `Alert` with MITRE preserved + severity clamped.
- `apis/identity/` — FastAPI mock (Okta-shaped): users, login history, risk factors,
  login-event injection; auto-seeds synthetic data (SQLite `data/identity.db`).
- `apis/edr/` — FastAPI mock (Falcon-shaped): 5 endpoints (incl. `kali-lab-02`),
  process/network/file telemetry for brute-force, credential-stuffing, phishing,
  ransomware-precursor scenarios (`data/edr.db`).
- `investigation/evidence.py` — gathers identity + EDR + SIEM into an `InvestigationBundle`
  (the seam the LangGraph agent will consume in weeks 5+).
- `database/engine.py` — SQLAlchemy `InvestigationRecord` store (SQLite default).
- `tests/` — 20 tests: 4 files (normalizer, wazuh client, identity API, EDR API) + a real
  end-to-end test that boots both APIs on ephemeral ports and runs the full evidence pipeline.
- `scripts/test_wazuh_connection.py` — verifies live Wazuh auth/agents/alerts (needs creds).

**Next steps**
1. Put Wazuh API credentials in `ai-agentic-soc/.env` (from `screenshots/wazuh password.png`)
   and run `scripts/test_wazuh_connection.py` against the live instance.
2. Weeks 5–7: LangGraph supervisor agent + tool-calling to the three pillars + correlation
   and MITRE timeline logic. Board week 5 (LangGraph) starts 2026-09-14.

## Environment (note: work also happens on a Windows/WSL box)

- On this Windows/WSL machine, **the `ai-agentic-soc/venv` is a macOS venv** (binaries symlink to
  `/Library/Developer/CommandLineTools/usr/bin/python3`) — it silently fails here. To run tests on
  this box, recreate a native venv (python 3.9/3.11) with `requirements.txt`. Local Python here is
  3.14.4. 20 tests were last confirmed passing on the Mac.
- **Screenshots hold live credentials:** `ai-agentic-soc/screenshots/wazuh password.png` is NOT in
  `.gitignore`. Confirm it is excluded or the repo is private before any public push.

## Environment (this Mac)

- Wazuh 4.14.7 single-node Docker: manager/API `https://localhost:55000`, dashboard `443`,
  indexer `9200`. Kali Linux in UTM has the Wazuh agent enrolled (`10.11.x.x`).
- Python system = 3.9.6. Project venv: `ai-agentic-soc/venv`.
- Docker Desktop CLI NOT on default PATH (`/Applications/Docker.app/Contents/Resources/bin/docker`).

## Decisions & gotchas

- **Real Wazuh design change (2026-09-10):** SIEM pillar switched from a mock (Splunk-shaped)
  to the real local Wazuh. Alert ingestion = live `/security-events` pull. Identity + EDR stay
  mocked (no real Okta/CrowdStrike). See `docs/ARCHITECTURE.md`.
- **Python 3.9 restrictions:* NO `X | None` unions (crash on FastAPI/Pydantic runtime
  evaluation). Use `Optional[...]`; `from __future__ import annotations` is present repo-wide.
- **Broken venv pip:** `ai-agentic-soc/venv/bin/pip` shebang points at old `/Users/Adult/
  ai-agentic-soc/venv`. Always `venv/bin/python -m pip`. (This is why pytest/dotenv initially
  landed in the wrong site-packages.)
- **Duplicate repo:** `/Users/Adult/ai-agentic-soc` is an older copy. Desktop is source of truth.
- **Wazuh API creds** live only in the `.env` file / `screenshots/wazuh password.png`.
- **httpx `ASGITransport` is async-only** — cannot back sync clients; tests boot real servers
  via uvicorn on ephemeral ports instead.
- **edr/identity DBs** under `data/`, `event_id` is a plain (non-PK) column; `id` autoincrements.
- **Wazuh API reachable:** connection test got a real 401 before creds were set — network path OK.

## Change log

- **2026-09-15** — Completed `cyber_threats_and_vulnerabilities_1/Incident_Response_Methodology.md`
  for the IR methodology rubric (SSH brute-force/T1110 scenario + TheHive case management).
  Journal updated on the Windows/WSL box; remembered the Mac venv can't run here and flagged the
  `screenshots/wazuh password.png` gitignore gap before the user's commit/push.
- **2026-09-14** — Weeks 1–4 code committed to portfolio repo (working tree clean); journal
  updated to reflect the committed state. Duplicate repo at `/Users/Adult/ai-agentic-soc` still
  to be deleted.
- **2026-09-10** — Added memory system (AGENTS.md + this journal + project opencode.json),
  project-scoped so other projects can have their own memories.
- **2026-09-10** — Weeks 1–4 foundation built + 20 tests passing; Wazuh design change adopted in
  `docs/ARCHITECTURE.md`. Live connection script confirmed Wazuh reachable (401 until creds).
- **2026-09-10** — Session start: reviewed Semester2 design PDFs; confirmed plan to wrap the
  build around the real local Wazuh deployment instead of a mock SIEM.