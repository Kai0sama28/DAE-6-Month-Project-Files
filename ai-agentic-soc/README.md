# AI-Agentic SOC Triage & Investigation Engine

An LLM-orchestrated investigation agent that autonomously triages security alerts **before**
a human analyst opens them. It pulls identity, SIEM, and endpoint evidence, correlates it
into a MITRE ATT&CK-mapped timeline, and produces a natural-language risk report — while a
human-in-the-loop approval gate keeps authority over any containment action.

## Architecture at a Glance

```
Wazuh 4.14.7 (real, Docker)  ──►  Alert + SIEM history evidence
Identity API (mock, Okta-shaped) ──►  user identity + login history
EDR API (mock, Falcon-shaped)   ──►  endpoint process/network telemetry
        │
        ▼
  LangGraph investigation engine  ──►  timeline + MITRE mapping ──►  report ──► approval gate
        │
        └──────────►  Streamlit dashboard (alert queue / reports / reasoning chain)
```

Wazuh is the real SIEM **and** the alert source (see `docs/ARCHITECTURE.md`). Identity and
EDR are schema-matched mocks, swappable for real Okta/CrowdStrike later.

## Repository Layout

| Path | Contents |
|---|---|
| `schemas/` | Internal, tool-agnostic Pydantic models (alert, identity, edr, siem) + Wazuh raw models |
| `siem/` | Wazuh API client (JWT auth) + alert normalizer (Wazuh → internal `Alert`) |
| `apis/identity/` | FastAPI mock of an Okta/Azure AD-shaped identity service with synthetic data |
| `apis/edr/` | FastAPI mock of a CrowdStrike-shaped EDR service with synthetic telemetry |
| `database/` | SQLAlchemy engine helper (SQLite default, Postgres via `DATABASE_URL`) |
| `agent/` | LangGraph orchestration (weeks 5–9; placeholder) |
| `frontend/` | Streamlit dashboard (week 11; placeholder) |
| `tests/` | Unit + end-to-end integration tests |
| `scripts/` | One-shot tools: seed data, test the live Wazuh connection |
| `docs/` | Design and architecture documentation |

## Quick Start

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env      # then fill in your Wazuh API credentials

# Run the Wazuh connection check (needs .env credentials)
python scripts/test_wazuh_connection.py

# Run both mock evidence APIs
uvicorn apis.identity.app:app --port 8001
uvicorn apis.edr.app:app --port 8002

# Run the full test suite
pytest
```

## Wazuh Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `WAZUH_API_URL` | `https://localhost:55000` | Wazuh API base URL |
| `WAZUH_API_USER` | — | API user (e.g. `wazuh-wui` or `admin`) |
| `WAZUH_API_PASSWORD` | — | API password (never committed) |
| `WAZUH_VERIFY_TLS` | `false` | Verify TLS for non-localhost deployments |
| `DATABASE_URL` | `sqlite:///./data/investigations.db` | Investigation state + results |

## Build Roadmap (12 weeks)

- **Weeks 1–4 (done here):** alert schema + normalizer, identity API, Wazuh connector, EDR API, end-to-end API integration.
- **Weeks 5–7:** LangGraph supervisor agent, tool-calling to the three pillars, correlation + MITRE mapping.
- **Weeks 8–12:** report synthesis, human-in-the-loop approval gate, Streamlit dashboard, labeled evaluation, docs + portfolio case study.

Project-level design decisions and the change log live in `docs/`.