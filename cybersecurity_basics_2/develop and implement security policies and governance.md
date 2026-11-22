# Develop and Implement Security Policies and Governance

**Workspace:** `DAE-6-Month-Project-Files` (DAE 6-month cybersecurity program, capstone `ai-agentic-soc`)
**Prepared:** 2026-11-22
**Purpose:** Map existing artifacts to the policy/governance rubric — a policy covering access control, data protection and system use; governance roles and accountability; a recognized standard or framework; implementation/enforcement; and communication. All claims are tied to checked-in files and line numbers, with documented/desired configuration separated from live-verified behavior.

The rubric mapping is confirmed by `Kyrell_s_Project_Board_AI_agentic_SOC_triage_engine_with_rubrics.xlsx`, sheet `updates`, cell `G30`:
> "Cybersecurity Basics1: Create an Incident Response Plan, Develop a Comprehensive Security Policy, Apply Encryption Techniques, Demonstrate Legal and Ethical Compliance."

---

## Rubric coverage at a glance

| Rubric requirement | Status | Primary evidence |
|---|---|---|
| Security policy covering access control, data protection, system use | **Met** — six rules, breach runbook, CIA mapping, rubric-coverage table | `cybersecurity_basics_1/Comprehensive_Security_Policy.md` |
| Governance roles / responsibilities / accountability | **Partially met** — functional roles, tiers and human authority documented; one person holds all roles, no enforced RBAC or independent approver | `Design_Documentation_1/Project_Design_Document.md` §5; `Incident_Response_Methodology.md` §3–4 |
| ≥1 standard or framework applied | **Met for named frameworks; partial as compliance program** — NIST SP 800-61/800-86, SANS, MITRE ATT&CK, CIS SCA, GDPR/UK DPA 2018, CMA/CFAA applied; no ISO 27001/NIST CSF/SOC 2 or formal audit | `Incident_Response_Plan.md`; `Threat_Detection_Principles.md`; `Digital Evidence Management.md` |
| Communication and enforcement | **Partially met** — written handover rule, notification paths, audit trails, secrets controls and human approval gate implemented; project APIs/dashboard have **no authentication or RBAC**, MFA is data-only | `Comprehensive_Security_Policy.md` §4; `SOC_Operations.md` §3; `ai-agentic-soc/README.md:179–182` |

---

## 1. Security policy — access control, data protection, system use

`cybersecurity_basics_1/Comprehensive_Security_Policy.md` (author Kyrell Green, 2026-09-14) is the controlling policy. Scope and authority (lines 14–19): "This policy defines the security rules every user, administrator, and automated system in the cybersecurity lab must follow… Compliance is verified through the monitoring controls described in this document; violations should be reported per Section 4 (Escalation) rather than silenced or fixed silently."

- **Access control — Rule 1 (25–33):** "Every user, service, and API account gets **only the rights required to do its job** — no exception accounts on the Wazuh manager, no standing root on shared hosts"; "Admin/API access (e.g., Wazuh API `55000`) requires unique accounts and **strong passwords or keys**; never shared logins"; "Interactive SSH to lab endpoints must use **key-based authentication**"; "Access is reviewed when a user changes role or leaves; access granted to the privileged set is logged."
- **Data protection — Rule 2 (38–47):** "Secrets (**API keys, Wazuh credentials, `.env` files**) are never committed to version control or written into code, logs, or documentation"; "Passwords are stored hashed (never plaintext); API credentials are rotated on a schedule and immediately on any suspected exposure"; "MFA is required wherever the platform supports it before privileged actions."
- **System use — Rule 5 (73–81):** "All security-relevant events … are collected in Wazuh and retained for the defined retention period"; "Monitored systems are for **authorized lab and coursework use only** — no personal data, no unauthorized scanning outside the lab scope." Rule 3 (49–59) sets the endpoint baseline and patching duty; Rule 4 (61–68) requires segmentation, a deny-all quarantine segment, and "**No exposed management surface to the internet**" for Wazuh API `55000`/indexer `9200`; Rule 6 (83–86) makes incident reporting mandatory ("Reporting an incident is never itself a violation — concealing one is").
- **Breach response and human authority:** Section 3 (93–134) gives the six-step lifecycle; Step 3 (111–117) states "Containment is a **human-approved** action — never automatically executed by any automated or agentic system." Section 4 (138–148) assigns notification by severity (Low → security lead; Medium → security lead + system owner; High → security lead + full lab team). Section 5 (152–197) maps controls to the CIA triad; Section 6 (201–207) is an explicit rubric-coverage table.

Supporting artifacts: `cybersecurity_basics_1/Incident_Response_Plan.md`, `Incident_Response_Template.md`, `Encryption_Techniques_Demo.md`, and the capstone's design rule (`docs/ai-agentic-soc-case-study.md:35`). `StreamSOC/reference/AI_Agentic_SOC_Presentation.md:151–167` ties the policy, IR template, escalation matrix and monitoring into one governed flow: "Every rubric item is a building block."

**Policy-maturity caveat.** The policy has an author and date but no formal approver, version number, next-review date, acknowledgement record, exception register, or sanction/consequence matrix. These are governance-maturity gaps, not missing-policy gaps.

## 2. Governance roles, responsibilities, accountability

**Functional ownership.** `Design_Documentation_1/Project_Design_Document.md:84–97` explicitly lists eight roles (project owner/lead developer, SOC engineer/SIEM integrator, AI/agent engineer, backend/API engineer, frontend engineer, QA/evaluation engineer, technical writer, external services/mocks), but states at line 86: "This is an individual capstone. All roles below are held by **Kyrell Green** … The roles are listed explicitly to show the functional areas covered and where mock external services stand in for real vendors." This is an honest limitation: separation of duties is designed, not staffed.

**Escalation tiers and authority.** `security_operations_center_1/Incident_Response_Methodology.md:375–401` defines Tier 1 Triage, Tier 2 Investigation, Tier 3 Advanced/IR, Management/shift lead, and Advisory non-SOC owners, each with authority, triggers and owned work. `security_operations_center_1/Incident Response Documentation_ Case Management, Escalation, and Ransomware Report.md:68–98` adds severity/notification SLAs (SEV1 Critical → IC, CISO, executives, Legal, Communications, 24/7 bridge; SEV2 High → security manager, IT leadership, legal advisory) and communication ownership. `Comprehensive_Security_Policy.md:138–148` names the security lead / program instructor as the escalation authority.

**Human-in-the-loop authority is structurally enforced.** `ai-agentic-soc/docs/ARCHITECTURE.md:225`: "**Never executed** — The LLM emits recommendations; a human approves. The graph has no containment node and no credential path." `Design_Documentation_1/Project_Design_Document.md:230–232` records the same guardrail and loopback binding. `ai-agentic-soc/agent/report.py:247–251` stamps every report "DRAFT — requires analyst review before any response action"; `ai-agentic-soc/services/triage_api/decisions.py:1–5` stores decisions separately so "the report stays an immutable record"; `StreamSOC/frontend/views.py:3–6` states the dashboard "never executes a containment action."

**Documented access-control model.** `network_security_1/Access Control Implementation Report.pdf` (section references, no line numbers) states "Model Selected: DAC", shows `sudo chown socadmin:socanalysts /opt/soc/reports` and `sudo chmod 750 /opt/soc/reports`, and defines the SOC Analyst role as Alerts/Investigation Data/Reports/Reasoning Logs = READ, Containment = APPROVE, Containment Execute = DENIED, with an allow/deny event example. This is a DAC/permission example, not application RBAC.

**Case management governance.** `Incident_Response_Methodology.md:312–329` describes TheHive cases, tasks, observables, audit trails, permissions and roles; line 327 calls for "Named analyst accounts with role-based access (triage, responder, admin, read-only)". The worked case (`Case Management…Report.md:138`) names the Tier 1 owner and records explicit decisions for Tier 2, management, system owner, legal/privacy and external parties.

**Governance gaps.** Named roles are not enforced as platform permissions: `python_1/Security_Evidence_gitignore_and_FastAPI.md:200–202` states "authentication/role checks — not implemented"; the analyst name is free text (`StreamSOC/app.py:63–66`; `ai-agentic-soc/services/triage_api/schemas.py:35–38`); `StreamSOC/ASSESSMENT.md:83` notes "Decisions are JSON, not a database … weak for multi-user audit" with a recommendation for SQLite/Postgres and append-only history (lines 156–157). No formal policy approval, review, or exception process exists.

## 3. Implementation and enforcement in the lab

| Control | Documented? | Technically implemented? | Honest status |
|---|---:|---:|---|
| Least privilege / unique accounts | Yes | Only for Wazuh clients via env credentials; not in project login | **Partial** |
| RBAC / role checks | Named roles + DAC example | No application RBAC; free-text analyst | **Not enforced** |
| MFA | Policy requires it | Modeled in identity data (`apis/identity/db.py:23–25`; `data_generator.py:68–70,103–108`) and risk signal (`apis/identity/app.py:161–169`); no challenge or privileged-action gate | **Data-only** |
| Secrets in env / never committed | Strong | `.gitignore:1–17`, nested `ai-agentic-soc/.gitignore`, GitHub Push Protection (GH013) remediation; **one credential-bearing screenshot still in pushed history** | **Mostly implemented, open risk** |
| Encryption in transit | Yes | Wazuh/indexer HTTPS; project APIs plain HTTP on loopback; `WAZUH_VERIFY_TLS=false` default (`.env.example:2–5`) | **Partial / lab-acceptable caveat** |
| Encryption at rest / password hashing | Policy + AES-256/SHA-256 demo (`Encryption_Techniques_Demo.md:6–18,94–102`) and FIM hashing | No general at-rest configuration evidence | **Partial / unverified** |
| Network segmentation / no WAN exposure | Strong | UFW LAN-only Wazuh ports (`Firewall_IDS_IPS_Implementation_Report.md:23–40`); loopback binding (`services/triage_api/__main__.py:10–18`; `StreamSOC/.streamlit/config.toml:9–12`) | **Implemented for documented scope** |
| Logging / monitoring / provenance | Strong | Wazuh collection, deterministic evidence hashes, reports, atomic decision store (`decisions.py:35–68`), auditability requirement (`TECHNICAL_DOCUMENTATION.md:65–69`) | **Implemented** |
| Human approval / no auto-containment | Strong | DRAFT reports, decision endpoint/UI, no containment node | **Strongly implemented** |
| Formal governance lifecycle | Weak | No approver/version/review/ack/exception register | **Not met as enterprise governance** |

**Material gap — no authentication.** `ai-agentic-soc/README.md:179–182`: "Neither the API nor the dashboard has authentication; keep both on loopback or put them behind an authenticated proxy." `docs/TECHNICAL_DOCUMENTATION.md:762–765` repeats this for the Triage API and notes the identity/EDR mocks also have "No authentication" (lines 555–559, 666–670). `python_1/Security_Evidence_gitignore_and_FastAPI.md:200–202` adds that CORS, security headers, CSRF tokens, secure session settings and role checks are not implemented. `StreamSOC/ASSESSMENT.md:82` rates this Medium risk with the loopback compensating control. `docs/ai-agentic-soc-case-study.md:277–283` lists "Add authentication and role-based access before exposing the API or dashboard beyond loopback" as future work.

**Real enforcement that does exist.** Input validation and allow-listing (`services/triage_api/schemas.py:19–21,35–46`; `cases.py:17–18` with `CASE_ID_RE = ^SOC-\d{8}-\d{3}$`; tested in `tests/test_triage_api.py:114–124`), HTML escaping (`agent/report.py:610–617`; `StreamSOC/frontend/views.py:69–73,130–136`), authenticated Wazuh integration (`siem/client.py:38–55,99–113` — Basic auth → JWT → Bearer; `siem/indexer_client.py:31–32` — HTTP Basic on every call), and the secret-hygiene remediation recorded in `.opencode/memory/PROJECT.md:141–150` (GH013 rejection, history rewrite, `.env` never committed; **open risk:** `ai-agentic-soc/screenshots/wazuh password.png` in pushed history `e46c01a` means the Wazuh admin password should be rotated).

**Contradiction to avoid.** `ai-agentic-soc/Firewall_IDS_IPS_Implementation_Report.md:76–80` describes Wazuh Active Response `firewall-drop` as automatically blocking sources — this conflicts with the policy's human-approval rule (line 116–117) and with later evidence that Active Response is disabled/desired (`Security_Monitoring_1/Security Reporting.md:274–278`; `security_operations_center_1/Threat_Detection_Principles.md:45–49`). Cite the firewall rule as implemented network hardening; cite Active Response as documented/desired, not live.

## 4. Standards, compliance, monitoring and improvement

**Applied standards and frameworks** (no ISO 27001, NIST CSF or SOC 2 exists in the repository — do not claim them):

- **NIST SP 800-61** — `cybersecurity_basics_1/Incident_Response_Plan.md:12–18` ("using the NIST SP 800-61 incident-response lifecycle (Preparation → Detection & Analysis → Containment → Eradication → Recovery → Post-Incident)"); `Threat_Detection_Principles.md:574` uses it as "The lifecycle spine".
- **NIST SP 800-86 and SANS DFIR** — `Security_Monitoring_1/Digital Evidence Management.md:407–427`, with order of volatility, hashes before/after, chain of custody, hashdeep audits, and references to both.
- **MITRE ATT&CK and compliance tags** — `Threat_Detection_Principles.md:154–156`: "Compliance mappings (PCI-DSS, HIPAA, GDPR, NIST 800-53, TSC, GPG) | Carried on every alert in this lab, e.g. `5763` → PCI `11.4`, `10.2.4`, `10.2.5`"; line 505 records GDPR tags on `5763`.
- **GDPR / UK Data Protection Act 2018 / Computer Misuse Act 1990 / US CFAA** — `Incident_Response_Plan.md:195–215,237–244` maps Articles 5, 32, 33–34 (including the 72-hour notification duty), authorized-access-only scope, and ethical proportionality; `Threat_Detection_Principles.md:505` ties personal-data scope to notification duties.
- **CIS Benchmark / SCA** — `Security_Monitoring_1/Monitoring Implementation.md:176` (DS-4), `Security Reporting.md:268–278`: "SCA assessment shows 27% compliance (304 failed / 425 checks)" with a High-priority recommendation to address critical CIS findings. This is a **finding**, not compliance success.

**Monitoring and continual improvement.** `Comprehensive_Security_Policy.md:73–75` requires security-relevant events to be collected in Wazuh; `Monitoring Environment Setup.md:56–61` records the configuration and credential handling. The capstone measures success with 99 passing tests, a 50-case labeled evaluation (45/50 completed, ATT&CK 43/50 = 86.0%, lenient recommendation 40/50 = 80.0%) and "100% of reports remain DRAFT with provenance; zero auto-executed containment actions" (`Project_Design_Document.md:239–245`). Section 6 (249–257) lists next steps: wire approvals into TheHive or an approved executor, real vendor connectors, durable job queue and authentication before non-loopback deployment, and credential rotation (including any exposed in earlier history). Post-incident lessons I.1–I.11 with owners/dates are at `Incident_Response_Methodology.md:730–770`; `docs/ai-agentic-soc-case-study.md:269–275` records the design lessons ("Human-in-the-loop is a product requirement"; "Scope boundaries build trust").

**Compliance gaps.** No formal compliance audit against a named framework, no training/acknowledgement records, no annual review log, no exception register, the open historical credential screenshot, 27% CIS/SCA compliance with remediation not shown closed, and no closed remediation cycle for all findings.

## 5. Evidence of communication

- **Policy communication:** Section 4 of the policy publishes escalation severity, contacts and channels (`Comprehensive_Security_Policy.md:138–148`); the IR plan and template are checked in and referenced across the capstone (`StreamSOC/reference/AI_Agentic_SOC_Presentation.md:159`: "Security policy, incident response plan → Comprehensive Security Policy, IR Plan → Human approval gate; containment never auto-executed").
- **Written-handover rule:** `SOC_Operations.md:191–194` — "verbal-only handovers are not permitted in this SOC. The communication rule: if it isn't written in TheHive, it isn't handed over", with a full written template at lines 227–241.
- **Incident communications protocol:** `Case Management…Report.md:86–98` assigns audience, owner, cadence and content (response team status every 30–60 min on SEV1; executives every 2–4 h; Legal immediately for data exposure) and requires "every communication logged in the ticket"; the worked case's communications log is at `Incident_Response_Methodology.md:717–728`.
- **Accountability:** TheHive's append-only log is described as "**Chain of custody and accountability**: reconstruct exactly who did what and when … This is what proves the approval gate was respected" (`Incident_Response_Methodology.md:322`).

## 6. Honest qualifications

1. **Do not claim ISO 27001, NIST CSF or SOC 2** — none appear in the repository. NIST SP 800-61/800-86, SANS, MITRE ATT&CK, CIS SCA and GDPR/DPA/CMA/CFAA do.
2. **Policy intent ≠ full enforcement** — no authentication or RBAC on the project API/dashboard, MFA only modeled in mock identity data, TLS verification off by default, encryption at rest unverified, and one credential-bearing screenshot still in history requiring rotation.
3. **Single-person project** — all functional roles held by Kyrell Green; role separation is designed/simulated, and analyst identity is free text rather than authenticated.
4. **Case-management connector** — RBAC and audit trails are documented capabilities, but `Incident_Response_Methodology.md:338–350` records "G1 — No alert connector. Wazuh → TheHive is not wired"; `thehive.py` is an optional decision mirror.
5. **Open corrective actions** — follow-ups I.1–I.9 remain open with owners and dates (`Incident_Response_Methodology.md:769`); CIS/SCA compliance is 27%.
6. **Stale Active Response claim** — treat `firewall-drop` as desired configuration, not live policy enforcement.

## 7. Conclusion

The policy requirement is fully met: a comprehensive policy covers access control, data protection and system use, with a breach runbook, severity escalation and CIA mapping. Governance roles, standards and communication are well documented, and several controls are genuinely enforced — secrets hygiene, LAN-only exposure, loopback binding, validation, audit trails and, most strongly, the code-enforced human approval gate. The limits are honest ones: governance is documented rather than institutionally matured (one person, no approver/review/exception register), application RBAC/MFA/authentication are absent, and compliance is partial with an open credential-rotation risk. The defensible claim is **policies and governance are documented and partly operationalized; enforcement is partial**, not a fully implemented enterprise GRC program.

### Related rubric write-ups

- `implement and explain advanced cybersecurity defense strategies.md`
- `implement incident response and handling.md`
- `demonstrate soc fundamentals.md`
- `produce effective security documentation.md`
