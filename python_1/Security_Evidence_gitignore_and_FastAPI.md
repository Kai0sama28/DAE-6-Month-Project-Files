# Security Setup Evidence — Git Secrets Handling and FastAPI Hardening

This note cites security controls that **already exist** in the portfolio repository. All paths are
relative to the workspace root (`Kai-DAE 6Month Project Files`), and line numbers refer to the files
as they exist at the time of writing. It covers two of the evidence areas required for the
development-environment security rubric:

1. `.gitignore` setup and Git secrets handling.
2. Basic security features configured in a web framework (FastAPI / Pydantic and the HTML renderers).

Quotes below are taken directly from the cited files and contain no credentials.

---

## 1. Git security configuration — `.gitignore` and secrets handling

### 1.1 Primary evidence: the root `.gitignore`

**File:** `.gitignore` (74 lines, tracked in git)

The file opens with an explicit secrets policy and then whitelists only the safe example file:

- `.gitignore:1-6`

  ```gitignore
  # ---------------------------------------------------------------------------
  # Secrets & credentials — NEVER commit these
  # ---------------------------------------------------------------------------
  .env
  .env.*
  !.env.example
  ```

- `.gitignore:7-17` — excludes private key and credential material: `*.pem`, `*.p12`, `*.pfx`,
  `*.jks`, `id_rsa*`, `id_ed25519*`, `credentials.json`, `service-account*.json`,
  `.streamlit/secrets.toml`.
- `.gitignore:19-25` — excludes screenshots that may contain live credentials, with both
  top-level and recursive rules: `screenshots/*password*`, `screenshots/*token*`,
  `screenshots/*secret*`, `**/screenshots/*password*`, `**/screenshots/*token*`,
  `**/screenshots/*secret*`.
- `.gitignore:43-50` — excludes virtual environments, including the specific mistake remediation
  `ai-agentic-soc/venv/` ("Virtual environment checked in by mistake (kept on disk, untracked)").
- `.gitignore:55-63` — excludes runtime state that can contain sensitive data: `ai-agentic-soc/data/`,
  `*.db`, `*.sqlite`, `*.sqlite3`, `*.log`, `*.pcap`, `*.pcapng`, `core.*`.
- `.gitignore:71-74` — excludes the separate lab tree `soc-lab/`.

**Commit evidence:** the current root ignore file was introduced in commit `2058d14`,
*"Add learning notes and triage chain; harden .gitignore, untrack venv and .DS_Store"*.

### 1.2 Nested `.gitignore` files reinforce the same rules

- `ai-agentic-soc/.gitignore:3` — `.env`; lines 11-13 comment *"Credentials — do not commit
  screenshots containing secrets"* with `screenshots/*password*` and `screenshots/*token*`.
- `StreamSOC/.gitignore:3,13-15` — same `.env` and credential-screenshot rules.
- `StreamSOC/ai-agentic-soc/.gitignore:3,11-13` — same rules.

### 1.3 Documentation that explains and enforces the secret-handling rule

- `AGENTS.md:51-52`
  > Seeded/state DB files (SQLite) live under `ai-agentic-soc/data/` and are gitignored.
  > Secrets (`.env`, API keys, Wazuh credentials) are gitignored. Never commit them.
- `cybersecurity_basics_1/Comprehensive_Security_Policy.md:38-44` — "Rule 2 — Credential & Secret
  Management":
  > Secrets (**API keys, Wazuh credentials, `.env` files**) are never committed to version
  > control or written into code, logs, or documentation. In this repo they live only in the
  > gitignored `.env` and never in the public portfolio site.

  The same rule requires hashed passwords, scheduled/on-exposure credential rotation, and MFA.
- `ai-agentic-soc/docs/TECHNICAL_DOCUMENTATION.md:369-382` — installation step `cp .env.example .env`,
  the list of secret variables (`WAZUH_API_USER`/`WAZUH_API_PASSWORD`,
  `WAZUH_INDEXER_USER`/`WAZUH_INDEXER_PASSWORD`, `OPENROUTER_API_KEY`, `EVAL_DATABASE_URL`), and:
  > Never commit `.env`. It is gitignored.
- `security_monitoring_1/Monitoring Environment Setup.md:58-72` — records that engine credentials
  live in the gitignored `.env` and are never committed, and shows only a placeholder
  `.env.example` with `change-me` values.
- `ai-agentic-soc/docs/DEMO_SCRIPT.md:122,134,155,450` — privacy checklist for demonstrations:
  do not show `.env`, API keys, Wazuh passwords, or credential-bearing screenshots on camera.

### 1.4 Real incident write-up (secret scanning in practice)

`.opencode/memory/PROJECT.md` records how a push was blocked by GitHub Push Protection (GH013) and
how the repository was remediated:

- `PROJECT.md:114-123` — the push was rejected because two unpushed commits contained a rules file
  with sample OAuth strings and a TheHive `.env`; the fix added the root `.gitignore`, squashed the
  two commits, untracked the venv and `.DS_Store` files, and pushed `2058d14`. It also records the
  open risk that a credential-bearing screenshot is already in pushed history, so the Wazuh admin
  password should be rotated.
- `PROJECT.md:840-849` — the change-log entry adds the operational lesson: GitHub scans **every
  commit in the push range**, so deleting a secret in a follow-up commit is insufficient; the
  offending commit must be rewritten or squashed.

Note: this write-up lives in the project memory journal rather than a portfolio-facing page.

---

## 2. Basic web-framework security features (FastAPI / Pydantic)

The web tier of the AI-Agentic SOC project is FastAPI plus a Streamlit dashboard. No Flask or
Django code exists in the repository. The configured security features are input validation,
allow-listing before filesystem access, output escaping, and loopback-only exposure.

### 2.1 Strict request validation (Pydantic models)

**File:** `ai-agentic-soc/services/triage_api/schemas.py`

- Line 20: `alert_id: str = Field(..., min_length=1, max_length=256)` — bounds the investigation
  identifier length.
- Line 27: `status: Literal["queued", "running", "succeeded", "failed"]` — response values are
  constrained to an allow-list.
- Lines 35-38: `DecisionRequest` restricts `decision` to `Literal["approved", "rejected"]` and bounds
  `analyst` (200 chars) and `note` (4000 chars).
- Line 43: the same `Literal` allow-list is applied to stored `DecisionRecord` values.

### 2.2 Server-side validation and parameter constraints in the API

**File:** `ai-agentic-soc/services/triage_api/app.py`

- Lines 7-8 (module docstring):
  > The server binds to loopback by default. Keep it that way unless you put an authenticated
  > reverse proxy in front of it.
- Lines 96-100 — trims input and rejects a blank identifier with HTTP 422:
  `alert_id = payload.alert_id.strip()` / `if not alert_id: raise HTTPException(status_code=422, ...)`.
- Line 103: `limit: int = Query(50, ge=1, le=500)`; line 115: `limit: int = Query(100, ge=1, le=500)`
  — numeric bounds on query parameters.
- Line 134: `format: str = Query("markdown", pattern="^(markdown|html)$")` — regex allow-list so an
  arbitrary report format cannot be requested.
- Lines 146-153 — decisions are validated by the request model before being persisted.

**File:** `ai-agentic-soc/services/triage_api/__main__.py:11-18` — the Uvicorn server defaults to
`TRIAGE_API_HOST=127.0.0.1`, port `8080`, `workers=1`, `reload=False`.

### 2.3 Identifier allow-listing before filesystem access

**File:** `ai-agentic-soc/services/triage_api/cases.py`

- Lines 17-18: `CASE_ID_RE = re.compile(r"^SOC-\d{8}-\d{3}$")` and
  `CASE_FILE_RE = re.compile(r"^(SOC-\d{8}-\d{3})\.md$")`.
- Lines 118-120: only filenames matching the strict pattern are listed from `reports_dir`.
- Lines 129-134: `get_case()` validates the incident ID against `CASE_ID_RE` **before** constructing
  `path = self.reports_dir / (incident_id + ".md")`, then verifies `path.is_file()`; invalid IDs raise
  `CaseNotFound` (mapped to HTTP 404 at `app.py:124-129`). This prevents path traversal through the
  case ID.

The same pattern is used by the mock APIs: `ai-agentic-soc/apis/identity/app.py:78-80`
(`limit: int = Query(100, le=500)`) and `ai-agentic-soc/apis/edr/app.py:76-78,91-93,106-108`
(`limit: int = Query(200, le=1000)`).

### 2.4 Output escaping (XSS hardening in rendered HTML)

- `ai-agentic-soc/agent/report.py:610-617` — a dedicated escaping helper applied to all web-rendered
  report values:

  ```python
  def _html_escape(value: Any) -> str:
      text = "" if value is None else str(value)
      return (
          text.replace("&", "&amp;")
          .replace("<", "&lt;")
          .replace(">", "&gt;")
          .replace('"', "&quot;")
      )
  ```

  Call sites include `report.py:629` (table headers), `report.py:634` (table cells), and further uses
  in `render_report_html()` (title, heading and summary, e.g. lines 677, 729, 733, 742-743).
- `StreamSOC/frontend/views.py:69-73` — `_badge()` escapes text injected into an HTML string
  (`html.escape(text or "Unrated")`).
- `StreamSOC/frontend/views.py:130-136` — `render_page_header()` escapes the kicker, title and
  subtitle before passing `unsafe_allow_html=True`.
- `StreamSOC/frontend/views.py:650-658` — pipeline step labels are escaped with `html.escape(label)`
  before rendering.

### 2.5 Test evidence that validation is actually enforced

**File:** `ai-agentic-soc/tests/test_triage_api.py:114-118`

```python
response = client.post(
    "/api/v1/cases/SOC-20261026-001/decision",
    json={"decision": "maybe", "analyst": "Kyrell"},
)
assert response.status_code == 422
```

A decision value outside the allow-list is rejected with HTTP 422. Lines 120-124 also assert HTTP 404
for an unknown case ID, confirming the case lookup guard.

---

## 3. Scope note — gaps in the wider rubric item

For transparency, the following are **not** present in the repository and should not be claimed as
existing evidence:

- **VS Code installation/configuration documentation, SonarLint, and GitGuardian** — no files,
  extension lists, install commands, or screenshots reference these anywhere in the workspace.
- **Git commit signing / GPG keys, branch protection, pre-commit hooks, or hardened `git config`** —
  not configured beyond the ignore rules above (`.git/hooks/` contains only default `*.sample` files).
- **Framework-level CORS, security headers, CSRF tokens, secure session/cookie settings, or
  authentication/role checks** — not implemented; the documentation deliberately states the API and
  dashboard have no authentication and must remain on loopback.

Supporting screenshots for the two evidenced areas above were not located; the citations in this note
are to tracked source files and git history only.
