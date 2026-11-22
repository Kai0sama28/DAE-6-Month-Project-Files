# Format and Display API Data

**Rubric line:** *Pre-formatted data using at least one HTTPs method.*

**Verdict: Met.** The project both consumes HTTPS APIs that return structured, ready-to-render
payloads (OpenRouter chat completions and the Wazuh indexer/manager) and exposes its own data in
pre-formatted JSON, Markdown and HTML. A Streamlit dashboard renders those formats for an analyst.

---

## 1. HTTPS methods used

| HTTPS endpoint | Method | Auth | Pre-formatted data returned | Evidence |
|---|---|---|---|---|
| `https://openrouter.ai/api/v1/chat/completions` | `POST` | Bearer API key | JSON with `choices[].message.content`, `usage`, `model`, `finish_reason` | `ai-agentic-soc/agent/llm.py:12-20,80,242-283` |
| `https://localhost:9200/wazuh-alerts-*/_search` | `POST` | HTTP Basic | JSON `hits.hits[]._source` alert documents | `ai-agentic-soc/siem/indexer_client.py:10,45-59,90-98` |
| `https://localhost:55000/security/user/authenticate` | `POST` | HTTP Basic | JSON `data.token` (JWT) | `ai-agentic-soc/siem/client.py:10,48-55` |
| `https://localhost:55000/agents` | `GET` | Bearer JWT | JSON `data.affected_items[]` | `ai-agentic-soc/siem/client.py:85-90,99-115` |

The demo runbook also lists the HTTPS services explicitly
(`ai-agentic-soc/docs/DEMO_SCRIPT.md:623-626`): Wazuh dashboard `https://localhost/`, indexer
`https://localhost:9200`, Wazuh API `https://localhost:55000`. The local Triage API, identity mock
and EDR mock are deliberately plain HTTP on loopback (`127.0.0.1`), not TLS services.

---

## 2. Pre-formatted data from an HTTPS method

### 2.1 OpenRouter JSON response

The request contract is documented at the top of `agent/llm.py:12-20`, and the client builds the
body and parses the response:

```python
body = {
    "model": model or self.model,
    "messages": payload_messages,
    "temperature": ...,
    "max_tokens": ...,
    "response_format": {"type": "json_object"},   # when json_mode=True
}
data = self._post("/chat/completions", body, timeout=timeout, deadline=deadline)
```

`_to_result()` maps the received JSON into the `LLMResult` dataclass, extracting text, model,
finish reason and token counts (`agent/llm.py:319-338`). `chat_json()` additionally parses a JSON
object out of the model reply and repairs malformed replies (`agent/llm.py:139-234,350-399`). This
is a direct example of consuming **pre-formatted data over HTTPS**.

### 2.2 Wazuh indexer JSON response

`IndexerClient.query_alerts()` posts a search body to the indexer and converts each `_source`
document into a validated `WazuhAlert` Pydantic model (`siem/indexer_client.py:160-164`):

```python
def _to_alert(hit: dict[str, Any]) -> WazuhAlert:
    source = dict(hit.get("_source") or {})
    if not source.get("id"):
        source["id"] = hit.get("_id")
    return WazuhAlert.model_validate(source)
```

The normalizer then turns that into the project's internal `Alert` model, so downstream report
rendering never has to re-parse raw SIEM JSON.

---

## 3. Formatted data served by the project's own API

The Triage API returns three presentation formats from one endpoint
(`services/triage_api/app.py:131-144`):

| Request | Response media type | Formatting |
|---|---|---|
| `GET /api/v1/cases/{id}/report?format=markdown` | `text/markdown; charset=utf-8` | PlainTextResponse of the report Markdown |
| `GET /api/v1/cases/{id}/report?format=html` | `text/html` | `FileResponse` of the styled, self-contained HTML report |
| `GET /api/v1/cases`, `GET /api/v1/cases/{id}`, `GET /api/v1/health` | `application/json` | Pydantic response models (`services/triage_api/schemas.py:10-78`) |

The HTML report itself is generated in `agent/report.py:640-676` (self-contained page, CSS,
escaped values) and the Markdown report in `agent/report.py:238`. Both are written to
`reports/SOC-YYYYMMDD-NNN.md` / `.html` by the agent.

---

## 4. Display to the analyst

The Streamlit dashboard (`ai-agentic-soc/frontend/app.py`) calls the Triage API and formats the
returned values:

- `st.metric()` tiles for severity, confidence, correlated events and attack duration
  (`frontend/app.py:77-81`).
- `st.markdown()` for the report body and `components.html()` for the HTML report
  (`frontend/app.py:92-97`).
- `st.success()` / `st.warning()` for the recorded analyst decision (`frontend/app.py:83-90`).
- `st.json()` for a succeeded job's structured result (`frontend/app.py:152-157`).
- Sidebar health status and recent jobs from `GET /api/v1/health` and `GET /api/v1/jobs`
  (`frontend/app.py:167-190`).

Screenshots of this running dashboard are recorded in
`docs/assets/images/ai-agentic-soc/` (per `.opencode/memory/PROJECT.md`, 2026-11-10 entry);
the dashboard is started with `venv/bin/streamlit run frontend/app.py --server.address 127.0.0.1`
(`frontend/app.py:3-9`).

---

## 5. Honest scope notes

- Only the **external/private APIs** in this project use HTTPS. The project's own FastAPI services
  bind to loopback over plain HTTP. If the rubric requires every displayed request to be TLS, the
  qualifying examples are the OpenRouter completion and the Wazuh indexer/manager calls above.
- TLS certificate verification for the Wazuh clients defaults to **off**
  (`WAZUH_VERIFY_TLS=false` in `ai-agentic-soc/.env.example:5`, implemented in
  `siem/client.py:41-45` and `siem/indexer_client.py:51-59`). The transport is HTTPS but the
  self-signed lab certificate is not validated by default. This is documented as a lab-only
  setting, not a production security control.
- The LLM's prose is advisory: counts, timeline and MITRE mapping are computed deterministically
  in Python before the HTTPS call ("code owns the facts, the LLM owns the prose",
  `ai-agentic-soc/README.md:96-102`).

**Related evidence:** `ai-agentic-soc/docs/TECHNICAL_DOCUMENTATION.md` §6 (lines 553-944) and
`ai-agentic-soc/docs/DEMO_SCRIPT.md` lines 595-627.
