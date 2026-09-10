# AGENTS.md — Workspace Guide & Memory Rules

This file is loaded at the start of every opencode session. Read it fully before working.
The living project journal is `.opencode/memory/PROJECT.md` — also auto-loaded. Read it too;
when anything about the project changes, update it (rules below).

## Who / What this is

- Owner: **Kyrell Green** — cybersecurity student on a 6-month program (SOC/security analyst track).
- This folder is Kyrell's **portfolio + coursework workspace** and the git repo is the portfolio repo.
- The GitHub Pages site source lives in `docs/` (Jekyll: `_config.yml`, `index.md`, `about.md`, `projects.md`, `contact.md`).

## Workspace map

| Path | What it is |
|---|---|
| `ai-agentic-soc/` | **ACTIVE CAPSTONE PROJECT** — AI-Agentic SOC Triage & Investigation Engine (see below) |
| `docs/` | GitHub Pages portfolio source (public site — do not put secrets here) |
| `Semester1/` .. `Semester3/` | Coursework evidence (PDFs, screenshots, status updates) |
| `python_1/` | Python coursework apps (Tracker Keeper, Home Destiny Guru) |
| `cyber_threats_and_vulnerabilities_1/`, `network_security_1/` | SOC module work: malware analysis, firewall/IDS/IPS reports, Wazuh lab |
| `unix_1/`, `unix_2/`, `version_control_1/`, `design_1/`, `figma_1/`, `logic_1/`, `prompt_engineering_1/` | Module evidence |

## Active project: ai-agentic-soc

An LLM-orchestrated agent that autonomously triages security alerts before a human analyst
opens them. Evidence pillars: **Identity** (mock, Okta-shaped), **SIEM** (REAL Wazuh 4.14.7,
Docker), **EDR** (mock, CrowdStrike-shaped). Output: MITRE-mapped timeline, natural-language risk
summary, auditable reasoning chain, with a hard human-in-the-loop approval gate. Orchestrated with
LangGraph; Claude API; Streamlit dashboard (weeks 8–11).

- **Current phase:** weeks 1–4 complete (alert schema + Wazuh normalizer, identity mock API,
  Wazuh connector, EDR mock API, end-to-end evidence gatherer, 20 passing tests).
  **Next:** weeks 5–7 — LangGraph supervisor agent.
- Full design: `ai-agentic-soc/docs/ARCHITECTURE.md` (includes the design change: real Wazuh
  replaces mock SIEM).
- Wazuh is live on this Mac: manager/API on `55000`, dashboard `443`, indexer `9200`
  (Docker Desktop). Kali Linux UTM VM has the Wazuh agent enrolled.

## Development conventions (ai-agentic-soc)

- **Python is 3.9.6** (system). Do NOT use `X | None` union syntax or `list[...]`/`dict[...]`
  annotations without `from __future__ import annotations`, and NEVER use `X | None` anywhere
  FastAPI evaluates at runtime — use `Optional[...]` from `typing` instead. Pydantic/FastAPI
  forward-ref evaluation crashes on 3.9.
- Use the project venv for ALL python: `ai-agentic-soc/venv/bin/python`.
- Run pytest from `ai-agentic-soc/` with: `PYTHONPATH=. ai-agentic-soc/venv/bin/python -m pytest`.
- **Never use `ai-agentic-soc/venv/bin/pip`** — its shebang points at the OLD venv at
  `/Users/Adult/ai-agentic-soc/venv` (installs land in the wrong place). Use
  `ai-agentic-soc/venv/bin/python -m pip install ...` instead.
- Seeded/state DB files (SQLite) live under `ai-agentic-soc/data/` and are gitignored.
- Secrets (`.env`, API keys, Wazuh credentials) are gitignored. Never commit them.
- There is a **duplicate repo copy at `/Users/Adult/ai-agentic-soc`** (same venv origin, older
  tree). The Desktop workspace copy is the source of truth for new work.

## Memory system rules (IMPORTANT)

1. **At session start:** the memory journal is auto-loaded via `opencode.json` `instructions`.
   If anything is stale or missing, correct it.
2. **Update the journal automatically** (`.opencode/memory/PROJECT.md`) whenever any of these
   happen — do not wait to be asked:
   - a milestone/phase completes (e.g., weeks 5–7 agent wired up);
   - a design decision or scope change is made;
   - a blocker or gotcha is discovered (e.g., Wazuh behavior, Python version gotcha);
   - the "Current status / Next steps" changes.
3. Journal edits: update `## Current status` and `## Change log` (newest entry on top). Keep
   entries short and factual. Preserve other section structure.
4. Do NOT put secrets, passwords, or API keys in the journal (Mark only *where* they live,
   e.g. ".env file", "screenshots/wazuh password.png").
5. When the user commits the portfolio repo, memory under `.opencode/` may be committed too —
   keep it professional (it is a student portfolio that will be pushed publicly).

## General rules

- Follow the 12-week roadmap in `ai-agentic-soc/docs/ARCHITECTURE.md` and the design doc in
  `Semester2/Project Ideas Security Analyst/` (PDF source of truth for the capstone).
- Verify work with the test suite before calling a task done.
- Keep responses concise; match the user's communication style.