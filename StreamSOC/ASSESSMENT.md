# Sufficiency Assessment

**Subject:** `DAE-6-Month-Project-Files/ai-agentic-soc` — AI-Agentic SOC Triage &
Investigation Engine
**Deliverable:** `StreamSOC` — analyst-facing Streamlit dashboard over the same
engine
**Date:** 6 November 2026

## 1. Executive verdict

The original project is **substantially sufficient as an investigation engine**
and as evidence of the six-month project. It already has a real Wazuh
connector, mock identity and EDR services, a LangGraph agent, deterministic
correlation, MITRE ATT&CK mapping, report generation, a FastAPI control plane,
a labelled evaluation dataset, measured results, tests and documentation.

It is **not sufficient as the Week 10 Streamlit deliverable on its own**. The
existing Streamlit page is a thin API-dependent front end: it does not show the
timeline, identity/SIEM/endpoint findings, MITRE coverage, AI summary or stored
analyst decisions that the project board asks for, and it cannot be demonstrated
without the live API, Wazuh and the agent.

StreamSOC closes that gap without rewriting the engine. The original project is
copied intact into `ai-agentic-soc/`; the new dashboard reads its reports
offline and can optionally use the live API.

## 2. What already exists

| Area | Evidence in the original project | Assessment |
|---|---|---|
| Wazuh ingestion | `wazuh/`, indexer client, alert polling | Sufficient |
| Identity evidence | Mock identity API with login/profile/risk data | Sufficient for the lab |
| Endpoint evidence | Mock EDR API with process/network/file events | Sufficient for the lab |
| Agent orchestration | LangGraph graph, tools, state, guardrails | Sufficient |
| Correlation | Deterministic burst splitting, relations, phase counts | Strong |
| ATT&CK mapping | Technique/tactic extraction and report tables | Sufficient |
| Reporting | Markdown + HTML renderer, 12 incident cases | Strong |
| Control plane | FastAPI triage API with cases, jobs, reports, decisions | Sufficient |
| Evaluation | 50 labelled cases, evaluation + processing-time results | Strong |
| Tests | Agent, correlation, API and report tests | Sufficient |
| Documentation | README, AGENTS.md, architecture, reporting write-up, presentation | Strong |
| Analyst UI | Minimal Streamlit page tied to the API | **Insufficient for Week 10** |

Case inventory:

- 12 `SOC-*.md` incident reports in `ai-agentic-soc/reports/`.
- 11 matching HTML reports; `SOC-20261027-011` is Markdown only.
- 50 labelled evaluation cases across 5 categories (BF, BN, CS, PH, RP).
- Full evaluation report, processing-time report, CSV/JSONL results and
  per-case reports in `ai-agentic-soc/evals/results/`.

## 3. What is sufficient

1. **The detection-to-report pipeline is real and demonstrable.** Alerts are
   ingested, correlated, investigated, mapped to ATT&CK and written as reports.
2. **The safety model is correct.** The agent recommends actions but does not
   execute containment; reports are drafts requiring analyst review.
3. **The evaluation is credible.** There is a labelled dataset, a scoring
   harness, measured accuracy and processing-time evidence.
4. **The report format is rich enough to drive a dashboard.** The Markdown
   reports contain metadata, summary, findings, detection facts, timeline,
   relations, rule breakdown, flags, ATT&CK table, risk, recommendations,
   evidence gaps, metrics and provenance.
5. **The API contract is usable.** Cases, reports, decisions, jobs and metrics
   are exposed over HTTP, so a dashboard can be layered on top.
6. **The documentation is presentation-ready.** Architecture, reporting and
   project-board material already exist.

## 4. What needed improvement

| # | Gap | Why it matters | Severity | Status |
|---|---|---|---|---|
| 1 | Streamlit UI only worked against the API | The dashboard could not be demoed without Wazuh, Docker, an LLM key and the agent running | High | Fixed: offline local-report backend |
| 2 | No timeline, MITRE, evidence or provenance views | Week 10 explicitly asks for these; the reports contained the data but the UI did not expose it | High | Fixed: dedicated tabs and charts |
| 3 | No case overview or queue | Analysts could not triage by severity, decision, host or search text | High | Fixed: overview metrics, filters and queue table |
| 4 | No stored analyst decisions in local mode | Approve/reject was not demonstrable without the API | High | Fixed: atomic local JSON decision store |
| 5 | No evaluation view | The strongest evidence of project quality was buried in files | Medium | Fixed: dataset + measured-results view |
| 6 | No Auto mode | Users had to know whether the API was running | Medium | Fixed: API health check with local fallback |
| 7 | macOS-oriented setup | The original virtualenv did not transfer to Windows/WSL | Medium | Fixed: Windows and WSL/Linux run scripts |
| 8 | Minimal visual hierarchy | A dashboard needs severity/decision badges, charts and a clear case layout | Medium | Fixed: dark theme, badges, metrics, charts |
| 9 | No dashboard tests | New parsing and persistence code would be unverified | Medium | Fixed: parser/backend tests |
| 10 | No authentication | Anyone who can reach the port can record decisions | Medium | Documented; keep on loopback |
| 11 | Decisions are JSON, not a database | Fine for a single analyst demo; weak for multi-user audit | Low | Accepted for this scope |
| 12 | Duplicate/legacy code paths remain in the original | Adds maintenance noise | Low | Left untouched to preserve the source project |

## 5. What StreamSOC adds

| File | Responsibility |
|---|---|
| `app.py` | Page config, sidebar data-source selector, analyst identity, navigation |
| `frontend/report_parser.py` | Markdown report parser, case loading, aggregation |
| `frontend/backends.py` | `LocalBackend` (offline) and `ApiBackend` (live), Auto selection |
| `frontend/views.py` | Overview, cases, detail tabs, investigate, evaluation, about |
| `tests/` | Parser, decision persistence, report serving and metrics tests |
| `.streamlit/config.toml` | Loopback binding and dark theme |
| `run_streamsoc.*`, `run_api.*` | Windows/WSL setup scripts |
| `README.md` | Operating instructions |
| `reference/` | Original architecture, reporting, presentation and board documents |

### Operating modes

| Mode | Reads from | Can queue investigations | Decision storage |
|---|---|---|---|
| Local reports | `ai-agentic-soc/reports/*.md` | No | `data/triage_decisions.json` |
| Triage API | FastAPI `127.0.0.1:8080` | Yes, if Wazuh + agent run | API store |
| Auto | API if healthy, otherwise local | Depends on backend | Depends on backend |

### Analyst workflow

1. **Overview** — severity, pending review, correlated events, ATT&CK coverage,
   volume by day, top tactics and rules, recent incidents.
2. **Cases** — search/filter, open a case, read summary and key findings.
3. **Timeline** — event table, level-over-time chart, phase and burst split,
   CSV download.
4. **MITRE ATT&CK** — technique/tactic table and tactic chart.
5. **Evidence** — relations, rule breakdown, deterministic flags, recommended
   actions, containment caveats, evidence gaps and provenance.
6. **Full report** — rendered Markdown and downloadable Markdown/HTML.
7. **Decision** — approve/reject with analyst name and note; the state pipeline
   and stored decision are shown. No containment is executed.
8. **Investigate** — queue a Wazuh alert and poll the job (API mode).
9. **Evaluation** — labelled dataset distribution and measured results.

## 6. Verification performed

- `python3 -m compileall app.py frontend tests` — passed.
- A standalone smoke test exercised the real report folder and confirmed:
  - 12 reports parsed;
  - incident metadata, severity, timeline count, ATT&CK techniques and
    recommendations extracted correctly;
  - decisions written, reloaded and merged into cases;
  - Markdown/HTML report serving;
  - invalid decisions and unknown cases rejected;
  - local mode refuses to queue investigations;
  - aggregation and metrics correct.
- **11 pytest tests passed** in a Python 3.11.9 Windows virtual environment.
- **Streamlit AppTest executed the real app** with no exceptions on Overview,
  Cases, Investigate, Evaluation and About. It also confirmed the case detail
  tabs (Summary, Timeline, MITRE ATT&CK, Evidence, Full report, Decision), the
  three download buttons and the decision form render correctly.
- The live API path was reviewed against `services/triage_api` and the API
  schema was checked for compatibility, but it was not executed end to end
  because this environment has no Wazuh and no agent runtime.

**Environment note:** the WSL system Python is 3.14.4 without `pip` or
`venv`/`ensurepip`. Verification used the existing Windows Python 3.11.9 to
create a temporary virtual environment. Use Python 3.11–3.13 for the full UI;
Python 3.14 may not have prebuilt Streamlit/pandas wheels yet.

## 7. Remaining limitations and recommended next steps

1. **Pin a supported Python version.** Streamlit and pandas are safest on
   Python 3.11–3.13. Add this to onboarding and CI.
2. **Add authentication** before exposing the dashboard beyond loopback. A
   simple OIDC proxy or Streamlit authenticator is enough for the lab.
3. **Move decisions to SQLite/Postgres** if multiple analysts or an audit trail
   are required. Keep the append-only decision history, not just the latest row.
4. **Validate the API schema end to end.** Run the FastAPI service and confirm
   `/api/v1/cases`, `/api/v1/metrics` and `/api/v1/jobs` match the fields the
   dashboard expects. The local mode is independent of this.
5. **Add CI** that runs `pytest`, `compileall` and a headless Streamlit health
   check on every change.
6. **Redact secrets from screenshots and reports** before submission. The lab
   reports and presentation should not contain real API keys, tokens or public
   IPs that identify the author.
7. **Containerise the demo** (dashboard + API + mock services) so the live mode
   is reproducible on any machine.
8. **Decide the containment story explicitly.** The current design is
   recommend-only, which is safe. If execution is ever added, require a second
   approver and a full audit log.

## 8. Bottom line

The original project already does the difficult engineering. StreamSOC turns it
into a complete, demonstrable SOC analyst application and preserves the engine
as the source of truth. For the Week 10 requirement, the combination is
sufficient: the dashboard shows the alert summary, timeline, identity/SIEM/
endpoint evidence, MITRE ATT&CK mapping, AI summary, approve/reject controls
and stored analyst decisions, and it still works when the live stack is off.
