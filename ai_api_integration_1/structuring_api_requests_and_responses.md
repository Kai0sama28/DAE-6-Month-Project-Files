# Structuring API Requests and Responses

**Rubric line:** *Structured API Request and response using HTTPs methods, endpoints/URL, request
body, header and status code upon request.*

**Verdict: Met.** The OpenRouter client is a complete worked example: HTTPS endpoint, explicit
headers, JSON request body, typed JSON response and status-code handling. The same discipline is
repeated in the Wazuh clients and in the FastAPI control plane, where Pydantic models and explicit
status codes structure both sides of the exchange.

---

## 1. Element-by-element coverage

| Required element | Where it appears | Evidence |
|---|---|---|
| HTTPS method | `POST` to OpenRouter; `POST`/`GET` to Wazuh | `agent/llm.py:265-268`; `siem/client.py:49-52,102-106`; `siem/indexer_client.py:129-133,141-152` |
| Endpoint / URL | `https://openrouter.ai/api/v1/chat/completions` | `agent/llm.py:14,80`; asserted in `tests/test_agent.py:161` |
| Request body | JSON object with `model`, `messages`, `temperature`, `max_tokens`, optional `response_format` | `agent/llm.py:126-135`; asserted in `tests/test_agent.py:164-165` |
| Headers | `Authorization: Bearer <key>`, `Content-Type: application/json`, `X-Title`, optional `HTTP-Referer` | `agent/llm.py:245-251`; asserted in `tests/test_agent.py:147-148,162-163` |
| Structured response | `choices[0].message.content`, `usage`, `model`, `finish_reason` parsed into `LLMResult` | `agent/llm.py:274-283,319-338` |
| Status codes | `200` success; retry on `408/425/429/500/502/503/504/529`; `400/404/422` trigger plain-text fallback; `>=400` raises `OpenRouterError` with status | `agent/llm.py:33,169-181,274-305` |

---

## 2. Worked example — OpenRouter chat completion over HTTPS

**Endpoint:** `POST https://openrouter.ai/api/v1/chat/completions`
(`agent/llm.py:12-20,80`).

**Request headers** (`agent/llm.py:245-251`):

```
Authorization: Bearer <OPENROUTER_API_KEY>
Content-Type: application/json
X-Title: AI-Agentic SOC Triage Engine
HTTP-Referer: <optional attribution URL>
```

**Request body** (`agent/llm.py:121-135`):

```json
{
  "model": "nvidia/nemotron-3-ultra-550b-a55b:free",
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."}
  ],
  "temperature": 0.2,
  "max_tokens": 8000,
  "response_format": {"type": "json_object"}
}
```

**Response body** (shape consumed at `agent/llm.py:319-338`):

```json
{
  "model": "nvidia/nemotron-3-ultra-550b-a55b:free",
  "choices": [
    {"message": {"role": "assistant", "content": "..."},
     "finish_reason": "stop"}
  ],
  "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
}
```

**Status handling** (`agent/llm.py:274-305`):

- `200` → parse JSON, reject unexpected shapes, return payload.
- Retryable statuses `408, 425, 429, 500, 502, 503, 504, 529` → retry with backoff and honour
  the `retry-after` response header (`agent/llm.py:33,299-316`).
- `400`, `404`, `422` from a JSON-mode request → retry without `response_format` for providers
  that do not support it (`agent/llm.py:169-181`).
- Any other `>=400` → raise `OpenRouterError` carrying the status code and payload
  (`agent/llm.py:293-303`).

`tests/test_agent.py:142-165` verifies the exact URL, `Bearer` header, `X-Title` header and body
contents using `httpx.MockTransport`; `tests/test_agent.py:260` verifies a `401` becomes an
`OpenRouterError` with `status_code == 401`.

---

## 3. Second HTTPS example — Wazuh authentication and agents

`ai-agentic-soc/siem/client.py` implements a two-step structured flow over
`https://localhost:55000`:

1. `POST /security/user/authenticate` with HTTP Basic credentials from environment variables.
   The JSON response's `data.token` becomes the bearer token (`siem/client.py:48-55`).
2. `GET /agents` with `Authorization: Bearer <token>` and query parameter
   `q=status=active`; response is read from `data.affected_items` and validated into
   `WazuhAgent` models (`siem/client.py:85-90,99-115`).
3. A `401` triggers one re-authentication and retry; `>=400` raises `WazuhAPIError` with the status
   and response text (`siem/client.py:107-122`).

The indexer client follows the same pattern over `https://localhost:9200`: `POST
/wazuh-alerts-*/_search` with `Content-Type: application/json` and a JSON DSL body, `404` with
`index_not_found_exception` treated as an empty result, other `>=400` raising `IndexerAPIError`
(`siem/indexer_client.py:90-98,123-138,154-157,221-229`).

---

## 4. Structuring the API the project serves

`ai-agentic-soc/services/triage_api/` applies the same structure server-side:

| Concern | Implementation | Evidence |
|---|---|---|
| Request models | Pydantic `BaseModel` classes: `InvestigationRequest`, `DecisionRequest` with `Field` constraints and `Literal` choices | `services/triage_api/schemas.py:19-21,35-38` |
| Response models | `response_model=` on routes: `JobView`, `CaseSummary`, `CaseDetail`, `DecisionRecord`, `HealthResponse`, `MetricsResponse` | `services/triage_api/app.py:79-89,91-100,113-129,146-168`; `schemas.py:10-78` |
| Query validation | `Query(50, ge=1, le=500)` and `pattern="^(markdown\|html)$"` | `services/triage_api/app.py:102-104,113-117,131-135` |
| Status codes | `200` default, `202 Accepted` for queued work, `201` for identity login-event creation, `404` missing case/job/user/endpoint, `422` invalid body | `app.py:91-99,106-111,124-153`; `apis/identity/app.py:92-97`; `apis/identity/app.py:71`; `apis/edr/app.py:63` |
| Error shape | `HTTPException(status_code=..., detail="...")` producing `{"detail": "..."}` | `services/triage_api/app.py:99,110,129,139,142,151` |
| Custom media type | `text/markdown; charset=utf-8` and `text/html` report responses | `services/triage_api/app.py:131-144` |

Documented, copyable examples for every route are in
`ai-agentic-soc/docs/TECHNICAL_DOCUMENTATION.md:553-929` (§6.1–6.3).

---

## 5. Status-code reference observed in code and tests

| Code | Meaning in this project | Source |
|---|---|---|
| `200` | Successful GET/POST; OpenRouter success; report served | `tests/test_triage_api.py:54,67,78,86,90,107`; `agent/llm.py:274` |
| `201` | Identity login event created | `apis/identity/app.py:92` |
| `202` | Investigation queued (work runs asynchronously) | `services/triage_api/app.py:94`; `tests/test_triage_api.py:149` |
| `400 / 404 / 422` | JSON-mode fallback for OpenRouter | `agent/llm.py:170` |
| `401` | Wazuh token refresh; OpenRouter auth error surfaced | `siem/client.py:107`; `tests/test_agent.py:260` |
| `404` | Missing case/job/user/endpoint/HTML report or missing index | `services/triage_api/app.py:110,129,139,142`; `tests/test_triage_api.py:124`; `tests/test_edr_api.py:46` |
| `422` | Pydantic validation failure (e.g. `decision: "maybe"`) | `tests/test_triage_api.py:114-118` |
| `408/425/429/500/502/503/504/529` | Retryable OpenRouter failures | `agent/llm.py:33,299-302` |

---

## 6. Honest scope notes

- The `retry-after` header is a **response** header from OpenRouter, used to pace retries; it is
  not sent by this project.
- The tests were not re-run in this Windows mount (the project `venv` is not present here); the
  assertions cited above come from the checked-in test files.
- Credentials are read from environment variables / gitignored `.env`
  (`ai-agentic-soc/.env.example:1-12,24-33`); no real key or password appears in this write-up.

**Related evidence:** `ai-agentic-soc/docs/TECHNICAL_DOCUMENTATION.md` §6 (lines 553-944),
`ai-agentic-soc/tests/test_agent.py:142-174,250-265`, and
`ai-agentic-soc/tests/test_triage_api.py:62-124`.
