# PROJECT — Living Memory Journal

Owner: Kyrell Green — 6-month cybersecurity program (SOC/security analyst track).
This journal is loaded every session in this workspace via `opencode.json` `instructions`.
Update it per the rules in AGENTS.md. NEVER store secrets/passwords/API keys here.

---

## Current status

**Phase: ai-agentic-soc weeks 1–4 complete (2026-09-10).**

The AI-Agentic SOC Triage & Investigation Engine has a working foundation in the Desktop copy
of the repo. All 20 tests pass. Neither the phase-1 code nor this memory has been committed yet
(pending user decision).

What exists today:
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
2. Decide whether to commit the weeks 1–4 code (and delete the duplicate repo at
   `/Users/Adult/ai-agentic-soc`).
3. Weeks 5–7: LangGraph supervisor agent + tool-calling to the three pillars + correlation
   and MITRE timeline logic.

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

- **2026-09-10** — Added memory system (AGENTS.md + this journal + project opencode.json),
  project-scoped so other projects can have their own memories.
- **2026-09-10** — Weeks 1–4 foundation built + 20 tests passing; Wazuh design change adopted in
  `docs/ARCHITECTURE.md`. Live connection script confirmed Wazuh reachable (401 until creds).
- **2026-09-10** — Session start: reviewed Semester2 design PDFs; confirmed plan to wrap the
  build around the real local Wazuh deployment instead of a mock SIEM.