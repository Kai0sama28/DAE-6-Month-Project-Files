# Implement Open or Secured APIs

**Rubric line:** *Formatted user-friendly data using public API or private API.*

**Verdict: Met.** The project implements both sides of this criterion:

- a **public API** is consumed — OpenRouter's public chat-completions endpoint, using a key — and
  its response is turned into an analyst-readable report;
- **private/secured APIs** are consumed — the lab's Wazuh manager and indexer (HTTPS + Basic/JWT),
  and TheHive (Bearer/Basic + organisation header);
- the project also **serves its own private APIs** — the Triage API and two mock evidence APIs —
  and renders their data in a user-friendly Streamlit dashboard and HTML/Markdown reports.

---

## 1. Public API — OpenRouter

| Item | Detail | Evidence |
|---|---|---|
| Provider endpoint | `https://openrouter.ai/api/v1` (public, commercial LLM gateway) | `ai-agentic-soc/agent/llm.py:80`; `ai-agentic-soc/.env.example:32` |
| Method / route | `POST /chat/completions` (OpenAI-compatible) | `ai-agentic-soc/agent/llm.py:4,14,135` |
| Security | Bearer API key in `Authorization`; key stored in gitignored `.env` | `agent/llm.py:245-249`; `.env.example:24-33`; `AGENTS.md:52` |
| Model | `nvidia/nemotron-3-ultra-550b-a55b:free` primary, lightning free model as fallback | `.env.example:28-31`; `.opencode/memory/PROJECT.md` 2026-10-22 entry |
| User-friendly output | LLM prose becomes the narrative sections of a Markdown + styled HTML incident report | `agent/report.py:238,640-676`; `README.md:90-94` |
| Failure handling | JSON repair loop, model fallback, retry/backoff, hard time budget | `agent/llm.py:139-234,299-316`; `.env.example:48-51` |

This is the clearest "public API" evidence: an external, key-protected REST service whose response
is formatted for an analyst rather than shown as raw JSON.

---

## 2. Private / secured APIs consumed by the engine

| API | Transport & auth | Purpose | Evidence |
|---|---|---|---|
| Wazuh manager API | `https://localhost:55000`; HTTP Basic to obtain JWT, then `Authorization: Bearer`; `401` refresh | Agent inventory, rules, status, logtest | `siem/client.py:10,48-55,85-115` |
| Wazuh indexer (OpenSearch) | `https://localhost:9200`; HTTP Basic (`WAZUH_INDEXER_USER/PASSWORD`); indexed alerts in `wazuh-alerts-*` | The real alert source (Wazuh 4.x removed `/security-events`) | `siem/indexer_client.py:10,45-59,74-98`; `README.md:21-24` |
| TheHive case API | `http://localhost:9000`; Bearer API key **or** Basic user/password, plus `X-Organisation`; optional `THEHIVE_VERIFY_TLS` | Mirrors approved decisions into cases with tags and comments | `services/triage_api/thehive.py:36,58-88,164-181,235-301` |
| Identity mock (Okta-shaped) | `http://127.0.0.1:8001`; no auth, loopback only | Users, login history, risk factors | `apis/identity/app.py:15,48-126`; `TECHNICAL_DOCUMENTATION.md:555-664` |
| EDR mock (Falcon-shaped) | `http://127.0.0.1:8002`; no auth, loopback only | Endpoints, process/network/file telemetry | `apis/edr/app.py:13,43-117`; `TECHNICAL_DOCUMENTATION.md:666-758` |

Wazuh 4.x has no alerts API route, so the indexer is the authoritative alert store; the manager
API is only used for agent inventory. This distinction is stated in `README.md:21-24` and
`docs/TECHNICAL_DOCUMENTATION.md:931-944`.

---

## 3. Private APIs served by this project

`ai-agentic-soc/services/triage_api/app.py` exposes a FastAPI control plane on `127.0.0.1:8080`:

- `GET /api/v1/health`, `/cases`, `/cases/{id}`, `/jobs`, `/metrics`;
- `POST /api/v1/investigations` (returns `202`),
  `POST /api/v1/cases/{id}/decision`;
- `GET /api/v1/cases/{id}/report?format=markdown|html`.

No authentication is implemented on these routes. The source docstring explicitly says the server
binds to loopback by default and should stay that way unless an authenticated reverse proxy is put
in front (`services/triage_api/app.py:1-9`), and the API documentation repeats the warning
(`docs/TECHNICAL_DOCUMENTATION.md:760-765`). The identity and EDR mocks are similarly unauthenticated
and intended for local synthetic evidence (`TECHNICAL_DOCUMENTATION.md:559,670`).

---

## 4. User-friendly presentation of the API data

| Presentation layer | What the analyst sees | Evidence |
|---|---|---|
| Streamlit dashboard (StreamSOC) | Case dropdown, severity/confidence/events/duration metrics, decision banner, Markdown report, embedded HTML report, decision form, job status, health sidebar | `frontend/app.py:57-113,116-161,164-199` |
| HTML incident report | Self-contained styled page with severity badge, summary, detection facts, timeline table, MITRE tags, recommendations; values HTML-escaped | `agent/report.py:640-676,729-904` |
| Markdown incident report | Structured sections with tables, report status `DRAFT — requires analyst review` | `agent/report.py:238`; `tests/test_triage_api.py:12-39` |
| Interactive API docs | FastAPI's `/docs` page, advertised by `GET /` | `services/triage_api/app.py:75-77` |

The dashboard is started with `venv/bin/streamlit run frontend/app.py --server.address 127.0.0.1`
after starting the API (`frontend/app.py:3-9`). Recorded screenshots of the running dashboard live
in `docs/assets/images/ai-agentic-soc/` (see the 2026-11-10 entry in
`.opencode/memory/PROJECT.md`).

---

## 5. Security controls that are actually present

- **Secrets stay out of source control.** API keys and Wazuh credentials are read from environment
  variables / gitignored `.env` (`.env.example:1-12,24-33`; `AGENTS.md:52`).
- **HTTPS to the lab SIEM.** Manager and indexer default URLs are `https://...`
  (`.env.example:2,9`).
- **Authenticated outbound calls.** Bearer for OpenRouter and TheHive, Basic→Bearer for Wazuh
  manager, Basic for the indexer (`agent/llm.py:245-251`; `siem/client.py:48-55,99-115`;
  `siem/indexer_client.py:55-59`; `services/triage_api/thehive.py:164-181`).
- **Input validation.** Pydantic models constrain request bodies, query parameters and status
  literals (`services/triage_api/schemas.py:19-78`; `app.py:102-104,131-135`).
- **HTML escaping** in the generated report and table helpers (`agent/report.py:610-634,675-676`).
- **Human-in-the-loop gate.** The engine records approve/reject decisions but never executes
  containment (`README.md:96-102`; `services/triage_api/thehive.py:1-14`).

---

## 6. Honest limitations

- The project's own APIs have **no built-in authentication**; they are safe only because they bind
  to loopback. Exposing them would require an authenticated proxy or adding auth.
- `WAZUH_VERIFY_TLS` defaults to `false` (`.env.example:5`), so the lab's self-signed certificate
  is not validated by the Wazuh clients, even though the transport is HTTPS.
- TheHive synchronisation is optional and failure-tolerant: if it is unconfigured or unreachable,
  the decision is still stored locally and an error/status is returned
  (`services/triage_api/thehive.py:9-13,297-325`).
- No public data is served to the internet. "Public API" here means the externally hosted
  OpenRouter service that this private project calls.

**Related evidence:** `ai-agentic-soc/docs/TECHNICAL_DOCUMENTATION.md` §6 (lines 553-944) and §8
(lines 1181-1247), `ai-agentic-soc/README.md:8-24,155-159`.
