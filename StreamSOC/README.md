# StreamSOC

A Streamlit SOC analyst dashboard built from the **AI-Agentic SOC Triage &
Investigation Engine** in `DAE-6-Month-Project-Files/ai-agentic-soc`.

The original project already contains the hard parts: Wazuh ingestion, mock
identity/EDR evidence APIs, a LangGraph investigation graph, deterministic
correlation, MITRE ATT&CK mapping, Markdown + HTML incident reports, a FastAPI
control plane, a 50-case labelled evaluation set, and tests. What it lacked was
a complete analyst-facing Streamlit application that could be demonstrated
without the whole live stack running.

StreamSOC adds that layer and keeps the original engine untouched in
`ai-agentic-soc/`.

## What is in the box

| Path | Purpose |
|---|---|
| `app.py` | Streamlit entry point |
| `frontend/report_parser.py` | Parses report metadata, timeline, MITRE, evidence, metrics |
| `frontend/backends.py` | Live API backend + offline local-report backend |
| `frontend/views.py` | Overview, cases, timeline, MITRE, evidence, report, decision views |
| `ai-agentic-soc/` | Copy of the original triage engine, reports, evals, tests and docs |
| `reference/` | Architecture notes, security reporting write-up, presentation |
| `data/` | Local analyst decisions (`triage_decisions.json`, created at runtime) |
| `ASSESSMENT.md` | Detailed "sufficient vs needs improvement" review |

## What was sufficient

- A working end-to-end investigation pipeline and a real Wazuh connector.
- Deterministic correlation, burst splitting and MITRE mapping in Python.
- 12 real incident reports (Markdown + HTML) and a 50-case evaluation dataset.
- A FastAPI control plane with case/report/decision endpoints.
- A human-in-the-loop approval model with no automatic containment.
- A test suite and architecture documentation.

## What was improved

- Replaced the minimal API-only Streamlit page with a full SOC application:
  overview, queue, filters, case detail, timeline, MITRE, evidence, report,
  approval gate, investigation queue, and evaluation views.
- Added **offline/local mode** so the dashboard runs from the existing reports
  with no Wazuh, API, database or LLM key.
- Added **Auto mode**: use the API when it is healthy, otherwise fall back to
  local reports.
- Added report parsing for the timeline, ATT&CK table, rule/relation/flag
  breakdowns, recommendations, evidence gaps and provenance.
- Added a metrics/health panel, severity and decision charts, and search/filter.
- Added local decision persistence and a clear approval-state pipeline.
- Added an evaluation view over the labelled dataset and measured results.
- Added Windows/WSL-friendly setup, run scripts, dark theme, and tests.

See `ASSESSMENT.md` for the full review and remaining limitations.

## Quick start — dashboard only (offline)

This works on the included reports and needs only Python + Streamlit.

### Windows

```bat
cd C:\Users\Kai\Desktop\StreamSOC
run_streamsoc.bat
```

### WSL / Linux / macOS

```bash
cd /mnt/c/Users/Kai/Desktop/StreamSOC
./run_streamsoc.sh
```

Or manually:

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
python -m streamlit run app.py --server.address 127.0.0.1
```

Open <http://127.0.0.1:8501>. The sidebar defaults to **Auto**; with no API
running it loads the 12 reports from `ai-agentic-soc/reports/`.

## Live mode — triage API + Wazuh + agent

The dashboard can queue new investigations when the control plane is running.

```bash
cd ai-agentic-soc
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env            # fill in Wazuh + OpenRouter values

python -m services.triage_api   # http://127.0.0.1:8080
```

Then run the dashboard and set **Data source** to `Auto` or `Triage API`.
The agent can also run continuously:

```bash
python -m agent.runner
python -m agent.runner --once
python -m agent.runner --no-llm
```

`run_api.sh` / `run_api.bat` automate the API setup from this folder.

## Dashboard views

- **Overview** — case count, high/critical, pending review, correlated events,
  ATT&CK technique count, severity/decision charts, case volume, top tactics
  and rules, recent incidents.
- **Cases** — search and filter by severity/decision/host, queue table, and a
  full case view with:
  - Summary, severity rationale, key findings, risk assessment
  - Incident timeline table + event-level-over-time chart + phase/burst split
  - MITRE ATT&CK table and tactic chart
  - Correlation relations, rule breakdown, deterministic flags, evidence gaps,
    recommended actions and provenance
  - Full Markdown/HTML report with downloads
  - Approve/Reject decision form with analyst and note
- **Investigate** — queue an alert, poll the job, and inspect recent jobs
  (API mode only).
- **Evaluation** — labelled dataset distribution plus the measured evaluation
  and processing-time reports.
- **About** — architecture, operating modes, safety model and the full
  assessment.

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

The 11 tests cover report parsing, decision persistence, report serving and
metrics. They do not need Streamlit, Wazuh or an LLM key. The UI was also
verified with Streamlit's `AppTest` harness across all five views.

Use **Python 3.11–3.13** for the dashboard. Python 3.14 may not have prebuilt
Streamlit/pandas wheels yet.

## Safety

- The dashboard records analyst decisions; it does not execute containment.
- The agent's reports are stamped `DRAFT — requires analyst review`.
- The API and dashboard have no authentication. Keep them on loopback, or put
  them behind an authenticated reverse proxy.

## Source

Copied from:

```text
/mnt/c/Users/Kai/Desktop/DAE-6-Month-Project-Files/ai-agentic-soc
```

The original folder was not modified.
