# RESTful API Method Utilization

**Rubric line:** *Use of at least two different RESTful API requests to fetch or send data.*

**Verdict: Met.** The AI-Agentic SOC Triage Engine uses several distinct HTTP methods across its
own services and the APIs it consumes. `GET` is used to fetch data and `POST` is used to send
data or submit a query; `PATCH` is additionally used by the optional TheHive integration.

All paths in this document are relative to the workspace root
`C:\Users\Kai\Desktop\DAE-6-Month-Project-Files`.

---

## 1. Methods actually implemented

| Method | Purpose | Endpoint / caller | Evidence in repo |
|---|---|---|---|
| `GET` | Fetch case list | `GET /api/v1/cases` (Triage API) | `ai-agentic-soc/services/triage_api/app.py:113-122` |
| `GET` | Fetch one job's status | `GET /api/v1/jobs/{job_id}` | `ai-agentic-soc/services/triage_api/app.py:106-111` |
| `GET` | Fetch user login history | `GET /users/{user_id}/login_history` | `ai-agentic-soc/apis/identity/app.py:77-89`; client at `ai-agentic-soc/apis/clients.py:35-40` |
| `GET` | Fetch endpoint process telemetry | `GET /endpoints/{endpoint_id}/processes` | `ai-agentic-soc/apis/edr/app.py:75-87`; client at `ai-agentic-soc/apis/clients.py:74-79` |
| `GET` | Fetch Wazuh agent inventory | `GET /agents` | `ai-agentic-soc/siem/client.py:85-90` |
| `POST` | Send an investigation request | `POST /api/v1/investigations` | `ai-agentic-soc/services/triage_api/app.py:91-100` |
| `POST` | Create a login event | `POST /users/{user_id}/login_events` | `ai-agentic-soc/apis/identity/app.py:92-113` |
| `POST` | Send a search query | `POST /wazuh-alerts-*/_search` (indexer) | `ai-agentic-soc/siem/indexer_client.py:90-98,123-138` |
| `POST` | Create a case / comment | `POST /api/v1/case`, `POST /api/v1/case/{id}/comment` | `ai-agentic-soc/services/triage_api/thehive.py:220-233,285-289` |
| `POST` | Request an LLM completion | `POST https://openrouter.ai/api/v1/chat/completions` | `ai-agentic-soc/agent/llm.py:104-135,242-268` |
| `PATCH` | Add tags to an existing case | `PATCH /api/v1/case/{id}` | `ai-agentic-soc/services/triage_api/thehive.py:265-270` |

The two-method minimum is therefore satisfied many times over: `GET` + `POST` are used in the
Triage API, in the identity mock, and by the external API clients.

---

## 2. Fetch example — `GET`

The Streamlit dashboard fetches the case list, then fetches the selected case detail
(`ai-agentic-soc/frontend/app.py:57-75`):

```python
cases = api_get(base, "/api/v1/cases", {"limit": 200}) or []
...
detail = api_get(base, "/api/v1/cases/%s" % incident_id)
```

`api_get()` issues `client.get(base + path, params=params)` and converts the JSON response to a
Python object (`frontend/app.py:24-32`). The server-side handler validates `limit` and `severity`
and returns a `List[CaseSummary]` (`services/triage_api/app.py:113-122`).

Equivalent curl command from the demo runbook (`ai-agentic-soc/docs/DEMO_SCRIPT.md:598`):

```bash
curl -s http://127.0.0.1:8080/api/v1/cases | venv/bin/python -m json.tool
```

Other `GET` fetches used by the agent at runtime:

- `IdentityClient.list_users()`, `.get_user()`, `.login_history()`, `.risk_factors()` — all call
  `httpx.Client.get()` (`apis/clients.py:23-49`).
- `EDRClient.list_endpoints()`, `.processes()`, `.network()`, `.files()` — same pattern
  (`apis/clients.py:68-99`).
- `WazuhClient.list_agents()` / `.get_agent()` fetch manager inventory over HTTPS
  (`siem/client.py:85-94`).

---

## 3. Send example — `POST`

### 3.1 Queue an investigation

The dashboard sends an alert id to the control plane (`frontend/app.py:125-136`):

```python
job = api_post(
    base,
    "/api/v1/investigations",
    {"alert_id": alert_id.strip(), "force": force},
)
```

The FastAPI route accepts the JSON body as an `InvestigationRequest` and returns `202 Accepted`
with a `JobView` (`services/triage_api/app.py:91-100`; model at
`services/triage_api/schemas.py:19-32`). Duplicate active jobs are deduplicated unless
`force=true` (verified by `tests/test_triage_api.py:160-186`).

Reproduction command (`ai-agentic-soc/docs/DEMO_SCRIPT.md:601-604`):

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/investigations \
  -H 'Content-Type: application/json' \
  -d '{"alert_id":"1792695015.328031","force":false}'
```

### 3.2 Send a search body to the Wazuh indexer

`IndexerClient.query_alerts()` builds a DSL body and posts it to `/wazuh-alerts-*/_search`
(`siem/indexer_client.py:90-98,123-138`). This is a `POST` used to *send* a query rather than to
create a record — still a RESTful request against the OpenSearch REST API.

### 3.3 Record an analyst decision

`POST /api/v1/cases/{incident_id}/decision` persists an approve/reject decision
(`services/triage_api/app.py:146-153`; dashboard call at `frontend/app.py:99-113`). The optional
TheHive mirror then uses `POST` for the case and its comment and `PATCH` to add review tags
(`services/triage_api/thehive.py:220-233,265-289`).

---

## 4. Method coverage against the rubric

| Rubric requirement | How it is met |
|---|---|
| At least two different RESTful API requests | `GET` and `POST` are both implemented and exercised. |
| Fetch data | `GET /cases`, `GET /users/...`, `GET /endpoints/...`, `GET /agents`. |
| Send data | `POST /investigations`, `POST /decision`, `POST /login_events`, `POST /_search`, `POST /chat/completions`. |
| More than the minimum | `PATCH /api/v1/case/{id}` in the optional TheHive sync. |

---

## 5. Honest scope notes

- `PUT` and `DELETE` are **not** used anywhere in this project. The rubric asks for two methods,
  so this is not a gap, but it is stated for accuracy.
- The `IdentityClient` and `EDRClient` classes implement only `GET` client-side; the identity
  mock does expose `POST /users/{user_id}/login_events` for injecting synthetic events, but the
  agent itself does not call it (`apis/clients.py:14-102` vs `apis/identity/app.py:92-113`).
- TheHive synchronisation is optional: without `THEHIVE_*` credentials a no-op client is used
  (`services/triage_api/thehive.py:304-325`). The core `GET` + `POST` evidence does not depend on it.
- The verification tests were not re-executed in this Windows mount — the project's `venv` is a
  macOS venv and is not present here (see `.opencode/memory/PROJECT.md`, Environment section).
  The cited test results come from the checked-in test code and project documentation.

**Related evidence:** `ai-agentic-soc/docs/TECHNICAL_DOCUMENTATION.md` §6 (API Documentation,
lines 553-944) and `ai-agentic-soc/docs/DEMO_SCRIPT.md` lines 595-627.
