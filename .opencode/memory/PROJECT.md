# PROJECT — Living Memory Journal

Owner: Kyrell Green — 6-month cybersecurity program (SOC/security analyst track).
This journal is loaded every session in this workspace via `opencode.json` `instructions`.
Update it per the rules in AGENTS.md. NEVER store secrets/passwords/API keys here.

---

## Current status

**Latest: 3 network_security_1 deliverables drafted 2026-09-17 — Topology report, Protocols &
Architectures report, and Network Security Tools report — closing the two "partial" rubric gaps
(§1 Topologies, §2 Protocols & Architectures) and the missing §6 Security Tools.**

New files in `network_security_1/`:
- `Network_Topology_Implementation_Report.md` — LAN (star) topology chosen/justified; Mermaid
  logical diagram + inventory; how the LAN supports secure communication (firewall/edge scoping,
  TLS agent channel) and network management (fleet view, central logging, diagnostics).
- `Network_Protocols_and_Architectures_Report.md` — OSI + TCP/IP model for one device
  (`ubuntu-endpoint-01`); subnetting worksheet for `10.11.0.0/22` with allocation table; secure
  architecture protocol matrix (SSH key-only, TLS, HTTPS, ufw scoping, rule 100010).
- `Network_Security_Tools_Report.md` — Wireshark capture + analysis (SSH brute-force replay),
  Nmap 7.94 NSE vuln scan against `10.11.3.185`, Hydra SSH brute-force pentest output tied to
  SOC-CASE-2026-0142.

These use the same lab facts as the existing reports (10.11.0.0/22, kali-lab-02, ubuntu-endpoint-01,
rule 100010, 203.0.113.77). **Student must verify/capture real screenshots** (Wireshark protocol
hierarchy, Nmap output, Hydra output) and confirm the Hydra `labtester` test-account run actually
happened before submission.

**Rubric completeness for network_security_1 (7 line items):** §3 Firewall/IDS/IPS ✓ (2 PDFs),
§4 Access Control ✓, §5 Wireless ✓, §7 Monitor & Respond ✓ + now §1 Topologies ✓, §2 Protocols &
Architectures ✓, §6 Security Tools ✓ — all seven criteria now have deliverables.

**Sibling-deliverable housekeeping (2026-09-17):** student reorganised module folders — SOC
deliverables moved into `security_operations_center_1/` (SOC_Operations.md, SIEM_Implementation.md)
and the policy/IR docs into `cybersecurity_basics_1/` (Comprehensive_Security_Policy.md,
Encryption_Techniques_Demo.md, Incident_Response_Methodology.md, Incident_Response_Plan.md). Git
tree shows those as deletions pending the student's `git add`/commit.

**Capstone (unchanged from 09-14): ai-agentic-soc weeks 1–4 committed, working tree clean on the
Mac. Next capstone step: weeks 5–7 LangGraph supervisor.**

What exists today (capstone):
- `ai-agentic-soc/docs/ARCHITECTURE.md` — design update adopting **real Wazuh 4.14.7** as the
  SIEM + alert source (supersedes the mock-SIEM design v0.2).
- `schemas/` — internal Pydantic models (Alert, Identity, EDR, SIEM) + Wazuh raw models.
- `siem/client.py` — Wazuh REST client (JWT auth via `/security/user/authenticate`, token
  refresh, `/security-events` + `/agents` queries).
- `siem/normalizer.py` — Wazuh alert → internal `Alert` with MITRE preserved + severity clamped.
- `apis/identity/` — FastAPI mock (Okta-shaped): users, login history, risk factors,
  login-event injection; auto-seeds synthetic data (SQLite `data/identity.db`).
- `apis/edr/` — FastAPI mock (Falcon-shaped): 5 endpoints (incl. `kali-lab-02`),
  process/network/file telemetry for brute-force, credential-stuffing, phishing,
  ransomware-precursor scenarios (`data/edr.db`).
- `investigation/evidence.py` — gathers identity + EDR + SIEM into an `InvestigationBundle`
  (the seam the LangGraph agent will consume in weeks 5+).
- `database/engine.py` — SQLAlchemy `InvestigationRecord` store (SQLite default).
- `tests/` — 20 tests: 4 files (normalizer, wazuh client, identity API, EDR API) + a real
  end-to-end test that boots both APIs on ephemeral ports and runs the full evidence pipeline.
- `scripts/test_wazuh_connection.py` — verifies live Wazuh auth/agents/alerts (needs creds).

**Next steps**
1. Put Wazuh API credentials in `ai-agentic-soc/.env` (from `screenshots/wazuh password.png`)
   and run `scripts/test_wazuh_connection.py` against the live instance.
2. Weeks 5–7: LangGraph supervisor agent + tool-calling to the three pillars + correlation
   and MITRE timeline logic. Board week 5 (LangGraph) starts 2026-09-14.

## Environment (note: work also happens on a Windows/WSL box)

- On this Windows/WSL machine, **the `ai-agentic-soc/venv` is a macOS venv** (binaries symlink to
  `/Library/Developer/CommandLineTools/usr/bin/python3`) — it silently fails here. To run tests on
  this box, recreate a native venv (python 3.9/3.11) with `requirements.txt`. Local Python here is
  3.14.4. 20 tests were last confirmed passing on the Mac.
- **Screenshots hold live credentials:** `ai-agentic-soc/screenshots/wazuh password.png` is NOT in
  `.gitignore`. Confirm it is excluded or the repo is private before any public push.

## Environment (this Mac)

- Wazuh 4.14.7 single-node Docker: manager/API `https://localhost:55000`, dashboard `443`,
  indexer `9200`. Kali Linux in UTM has the Wazuh agent enrolled (`10.11.x.x`).
- Python system = 3.9.6. Project venv: `ai-agentic-soc/venv`.
- Docker Desktop CLI NOT on default PATH (`/Applications/Docker.app/Contents/Resources/bin/docker`).

## Decisions & gotchas

- **Real Wazuh design change (2026-09-10):** SIEM pillar switched from a mock (Splunk-shaped)
  to the real local Wazuh. Alert ingestion = live `/security-events` pull. Identity + EDR stay
  mocked (no real Okta/CrowdStrike). See `docs/ARCHITECTURE.md`.
- **Python 3.9 restrictions:* NO `X | None` unions (crash on FastAPI/Pydantic runtime
  evaluation). Use `Optional[...]`; `from __future__ import annotations` is present repo-wide.
- **Broken venv pip:** `ai-agentic-soc/venv/bin/pip` shebang points at old `/Users/Adult/
  ai-agentic-soc/venv`. Always `venv/bin/python -m pip`. (This is why pytest/dotenv initially
  landed in the wrong site-packages.)
- **Duplicate repo:** `/Users/Adult/ai-agentic-soc` is an older copy. Desktop is source of truth.
- **Wazuh API creds** live only in the `.env` file / `screenshots/wazuh password.png`.
- **httpx `ASGITransport` is async-only** — cannot back sync clients; tests boot real servers
  via uvicorn on ephemeral ports instead.
- **edr/identity DBs** under `data/`, `event_id` is a plain (non-PK) column; `id` autoincrements.
- **Wazuh API reachable:** connection test got a real 401 before creds were set — network path OK.

## Change log

- **2026-09-17** — Drafted 3 more `network_security_1/` deliverables: `Network_Topology_
  Implementation_Report.md` (LAN/star topology, secure-communication + management rationale),
  `Network_Protocols_and_Architectures_Report.md` (OSI/TCP-IP for ubuntu-endpoint-01, 10.11.0.0/22
  subnetting worksheet + allocation, secure-architecture protocol matrix), and `Network_Security_
  Tools_Report.md` (Wireshark SSH-replay capture + analysis, Nmap 7.94 NSE vuln scan of 10.11.3.185,
  Hydra brute-force output tied to SOC-CASE-2026-0142). All 7 network_security_1 rubric items now
  have deliverables. Screenshots + the Hydra run need student verification. Journal updated.
- **2026-09-17** — Drafted `network_security_1/Monitor_and_Respond_Network_Security_Events.md`
  (network-monitoring + incident + IR report for SOC-CASE-2026-0142, log/screenshot evidence).
  Also noted the student's folder reorganisation: SOC docs → `security_operations_center_1/`,
  policy/IR docs → `cybersecurity_basics_1/` (currently un-staged deletions in git). Journal
  updated.
- **2026-09-16** — Drafted `cyber_threats_and_vulnerabilities_1/SIEM_Implementation.md` for the
  SIEM Implementation rubric (Wazuh 4.14.7 architecture + Mermaid data flow, correlation rule
  100010 documented element-by-element, 3 log sources, ossec.conf notification config, screenshot
  captions). Student to verify smtp/level values + screenshots against the live manager. Journal
  updated; also removed a duplicated Capstone line left over from the previous edit.
- **2026-09-16** — Drafted `cyber_threats_and_vulnerabilities_1/SOC_Operations.md` for the SOC
  Operations rubric (SOC tools, Mermaid alert-handling + escalation workflows, shift
  transition/handover, incident-handling steps, screenshot captions). Screenshot captions are
  best-effort — student to verify against live consoles. Journal updated.
- **2026-09-15** — Completed `cyber_threats_and_vulnerabilities_1/Incident_Response_Methodology.md`
  for the IR methodology rubric (SSH brute-force/T1110 scenario + TheHive case management).
  Journal updated on the Windows/WSL box; remembered the Mac venv can't run here and flagged the
  `screenshots/wazuh password.png` gitignore gap before the user's commit/push.
- **2026-09-14** — Weeks 1–4 code committed to portfolio repo (working tree clean); journal
  updated to reflect the committed state. Duplicate repo at `/Users/Adult/ai-agentic-soc` still
  to be deleted.
- **2026-09-10** — Added memory system (AGENTS.md + this journal + project opencode.json),
  project-scoped so other projects can have their own memories.
- **2026-09-10** — Weeks 1–4 foundation built + 20 tests passing; Wazuh design change adopted in
  `docs/ARCHITECTURE.md`. Live connection script confirmed Wazuh reachable (401 until creds).
- **2026-09-10** — Session start: reviewed Semester2 design PDFs; confirmed plan to wrap the
  build around the real local Wazuh deployment instead of a mock SIEM.