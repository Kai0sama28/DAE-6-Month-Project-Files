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

Wazuh is the real SIEM **and** the alert source. Wazuh 4.x exposes no alerts API route, so
alerts are read from its indexer (`wazuh-alerts-*`), the same store the dashboard uses;
the Wazuh API supplies agents, rules and status. See `docs/ARCHITECTURE.md`. Identity and
EDR are schema-matched mocks, swappable for real Okta/CrowdStrike later.

## Repository Layout

| Path | Contents |
|---|---|
| `schemas/` | Internal, tool-agnostic Pydantic models (alert, identity, edr, siem) + Wazuh raw models |
| `siem/` | Wazuh API client (JWT auth: agents/rules/status) + indexer client (HTTP Basic: alerts, `wazuh-alerts-*`) + alert normalizer (Wazuh → internal `Alert`) |
| `apis/identity/` | FastAPI mock of an Okta/Azure AD-shaped identity service with synthetic data |
| `apis/edr/` | FastAPI mock of a CrowdStrike-shaped EDR service with synthetic telemetry |
| `database/` | SQLAlchemy engine helper (SQLite default, Postgres via `DATABASE_URL`) |
| `agent/` | **Background triage agent**: indexer watcher, settle window, deterministic correlation, timeline, LLM narrative, Markdown + HTML reports, desktop notification |
| `frontend/` | Streamlit dashboard (week 11; placeholder) |
| `tests/` | Unit + end-to-end integration tests (71 passing) |
| `scripts/` | One-shot tools: seed data, test the live Wazuh connection |
| `docs/` | Design and architecture documentation |

## Background Triage Agent

The agent runs continuously against the real Wazuh indexer and triages alerts *before*
an analyst opens them.

```bash
cd ai-agentic-soc
venv/bin/python -m agent.runner                 # background daemon
venv/bin/python -m agent.runner --once          # single watch cycle
venv/bin/python -m agent.runner --no-llm        # deterministic only, no API calls
venv/bin/python -m agent.runner --investigate <alert-id>   # triage one existing alert
venv/bin/python -m agent.runner --status        # show persisted state
```

What it does on every cycle:

1. **watch** — polls the Wazuh indexer for new alerts (read-only).
2. **settle** — waits `AGENT_SETTLE_SECONDS` so Wazuh's *correlation* rules (e.g. rule
   `100002`, level 12 "verified SSH brute force") fire before the agent picks a trigger.
3. **supervisor** — decides which evidence pillars this alert actually needs.
4. **siem** — correlates every related log by endpoint, source, account and rule family,
   and splits the window into **bursts** so "attack duration" is not inflated.
5. **reason** — hands the deterministic evidence pack to `nvidia/nemotron-3-ultra-550b-a55b:free`
   (OpenRouter) for the analyst narrative.
6. **report** — writes `reports/SOC-YYYYMMDD-NNN.md` **and** a styled
   `reports/SOC-YYYYMMDD-NNN.html` (self-contained, opens in the browser) with full provenance.
7. **notify** — macOS banner + sound + a **clickable dialog** that opens the HTML report.

Two rules shape the whole design:

- **Code owns the facts, the LLM owns the prose.** Counts, timestamps, relations, phases
  and the timeline are computed in Python and are reproducible from the indexer. The LLM
  only writes narrative sections.
- **The agent never executes containment.** Recommendations are advisory; a human
  approves. The report is stamped `DRAFT — requires analyst review`.

See `docs/ARCHITECTURE.md` §9–16 for the full design.

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

## Agent Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `OPENROUTER_API_KEY` | — | Required for the LLM narrative (never committed) |
| `OPENROUTER_MODEL` | `nvidia/nemotron-3-ultra-550b-a55b:free` | Primary reasoning model |
| `OPENROUTER_FALLBACK_MODELS` | `nvidia/nemotron-3.5-lightning:free` | Models tried in order if the primary fails or returns unparsable JSON |
| `AGENT_POLL_INTERVAL` | `5.0` | Seconds between indexer polls |
| `AGENT_SETTLE_SECONDS` | `25.0` | Wait for Wazuh correlation rules before triggering |
| `AGENT_LLM_TIMEOUT` | `150` | Per-request timeout when calling OpenRouter |
| `AGENT_LLM_MAX_RETRIES` | `1` | Retries per request (1 = no retry; the model chain is the fallback) |
| `AGENT_LLM_BUDGET` | `600` | Hard wall-clock budget for the narrative step; over budget the report ships deterministic-only |
| `AGENT_MIN_LEVEL` | `4` | Minimum rule level collected as correlation context |
| `AGENT_TRIGGER_MIN_LEVEL` | `10` | Minimum rule level allowed to start an investigation (keeps benign level-5 noise out of the report queue) |
| `AGENT_LOOKBACK_MINUTES` | `30` | Correlation window before the trigger |
| `AGENT_POST_WINDOW_MINUTES` | `15` | Correlation window after the trigger |
| `AGENT_BURST_GAP_SECONDS` | `120.0` | Silence gap that separates two bursts |
| `AGENT_DEDUPE_WINDOW_MINUTES` | `2` | Suppress duplicate incidents for the same source (lowered to 2 min so repeated demo attacks each produce a fresh report) |
| `AGENT_NOTIFY` / `_SOUND` / `_OPEN_REPORT` | `true` | Desktop notification layers |

## Build Roadmap (12 weeks)

- **Weeks 1–4 (done here):** alert schema + normalizer, identity API, Wazuh connector, EDR API, end-to-end API integration.
- **Weeks 5–7 (done here):** LangGraph supervisor agent, tool-calling to the three pillars, correlation + MITRE mapping.
- **Weeks 8–11 (done here):** background triage agent, report synthesis, desktop notification, deterministic correlation with burst delineation.
- **Weeks 11–12:** Streamlit dashboard, human-in-the-loop approval gate, labeled evaluation, docs + portfolio case study.

Project-level design decisions and the change log live in `docs/`.