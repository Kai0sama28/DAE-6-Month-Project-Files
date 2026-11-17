# AI-Agentic SOC — 5–10 Minute Demo Script & Video Plan

**Project:** AI-Agentic SOC Triage & Investigation Engine  
**Presenter:** Kyrell Green  
**Target runtime:** 9 minutes (hard stop at 10:00)  
**Audience:** instructors, SOC analysts, portfolio reviewers  
**Demo type:** live screen recording with voiceover  
**Source of truth:** `agent/graph.py`, `agent/report.py`, `services/triage_api/`, `frontend/app.py`

---

## 1. Demo at a glance

**One-sentence pitch**

> This project is an LLM-orchestrated SOC analyst that receives a Wazuh alert, gathers identity,
> endpoint, and SIEM evidence, builds a MITRE-mapped incident timeline, writes an analyst-ready
> report, and stops at a human approval gate before any response action.

**The seven-stage story**

```
Receive Alert
    ↓
Run Investigation
    ↓
Timeline Created
    ↓
ATT&CK Mapping
    ↓
AI Report
    ↓
Approve
    ↓
Close Alert
```

**What is real vs simulated**

| Pillar | Status | What the demo shows |
|---|---|---|
| SIEM / alert source | **Real** | Wazuh 4.14.7 in Docker; alerts read from the `wazuh-alerts-*` indexer |
| Identity | Mock, Okta-shaped | FastAPI service on `127.0.0.1:8001`; user profile, login history, risk factors |
| EDR | Mock, CrowdStrike-shaped | FastAPI service on `127.0.0.1:8002`; endpoint, process, network, file telemetry |
| Orchestration | Real | LangGraph graph: `watch → supervisor → identity → edr → siem → timeline → reason → report → notify` |
| Narrative | Real LLM | OpenRouter, default `nvidia/nemotron-3-ultra-550b-a55b:free`, with fallback |
| Approval | Real, local | Streamlit + FastAPI; decisions persisted to `data/triage_decisions.json` |

**Scope boundary to state on camera**

> The engine never executes containment. “Approve” records the analyst decision. “Close Alert”
> means the case has been dispositioned; the current build does **not** write the closure back
> to Wazuh or TheHive. Automatic containment and ticket write-back are deliberately out of scope
> for this version.

This is a strength, not a gap to hide: the human-in-the-loop boundary is the safety story.

---

## 2. Flow → implementation map

| Stage | What the audience sees | Component | What the AI / agent is doing |
|---|---|---|---|
| 1. Receive Alert | A real Wazuh alert, then the agent log or dashboard job | `agent/graph.py::watch`, `IndexerClient` | **No LLM here.** The watcher polls the indexer every 5s, collects related events, waits a 25s settle window for Wazuh correlation rules, then selects the highest-level alert at or above level 10. Deterministic by design. |
| 2. Run Investigation | Dashboard “Investigate” tab, or daemon log `TRIGGER ... correlating` | LangGraph `supervisor`, `identity`, `edr`, `siem` nodes | The orchestrator plans which evidence pillars are required, calls the identity and EDR APIs, then queries the real Wazuh indexer for related events. The plan is deterministic and auditable. The LLM is not called yet. |
| 3. Timeline Created | Report §5 “Incident Timeline” | `agent/correlation.py` | **No LLM.** Python links every event by `SAME_AGENT`, `SAME_SOURCE_IP`, `SAME_USER`, `SAME_RULE_GROUP`, `PRIOR`, and `POST`; splits separate attack bursts; computes outcome flags and latency. These facts are reproducible from the indexer. |
| 4. ATT&CK Mapping | Report §7 “MITRE ATT&CK Mapping” | `correlation.py` + LLM `mitre_mapping` | Wazuh rule tags are extracted deterministically. The LLM maps observed behavior to techniques and must attach supporting evidence. The prompt forbids inventing techniques and allows an empty list for benign activity. |
| 5. AI Report | Report §1, §6, §8–§10 and §11 metrics | `agent/report.py`, `agent/llm.py` | The LLM writes the executive summary, attack narrative, severity rationale, false-positive assessment, recommendations, and data gaps. It receives only the deterministic evidence pack. If the LLM fails, the report still ships from the deterministic half. |
| 6. Approve | Dashboard “Record analyst decision” form | `frontend/app.py`, `services/triage_api/decisions.py` | **Human decision, no AI.** The analyst chooses `approved` or `rejected`, adds a note, and the decision is stored separately from the immutable report. |
| 7. Close Alert | Decision confirmation and metrics | `CaseRepository`, `DecisionStore`, `/api/v1/metrics` | The case is marked reviewed in the local control plane. No automatic Wazuh/TheHive closure and no containment execution. |

**Key design principle to repeat on camera**

> Code owns the facts. The LLM owns the prose. Every count, timestamp, relation, burst, and MITRE
> tag in the report can be re-derived from the Wazuh indexer.

---

## 3. Before you record — 15-minute checklist

### 3.1 Decide which investigation mode you will record

**Mode B — controlled and repeatable (recommended for the 9-minute video)**

Stop the background daemon, start the Triage API, and queue one known Wazuh alert ID through
the dashboard. This runs the exact same `investigate_now()` graph; only the initial watcher step
is bypassed. It is reliable, repeatable, and fits the time budget.

**Mode A — fully autonomous (optional live variation)**

Leave the daemon running and generate a fresh alert, for example by replaying the Responder pcap
on Kali. The daemon detects it, investigates it, writes the report, and fires a desktop
notification. This is more impressive but less predictable; keep Mode B as the fallback.

> Do **not** queue an API investigation while the daemon is running: both use
> `data/agent_state.json`, which assumes a single writer. Running the API only for report
> reading and decision recording is safe.

### 3.2 Start the supporting services

Run from `ai-agentic-soc/`:

```bash
cd "/Users/Adult/Desktop/Kai-DAE 6Month Project Files/ai-agentic-soc"

# Terminal 1 — identity mock
venv/bin/uvicorn apis.identity.app:app --host 127.0.0.1 --port 8001

# Terminal 2 — EDR mock
venv/bin/uvicorn apis.edr.app:app --host 127.0.0.1 --port 8002

# Terminal 3 — triage API
venv/bin/python -m services.triage_api

# Terminal 4 — dashboard
venv/bin/streamlit run frontend/app.py --server.address 127.0.0.1
```

### 3.3 Verify the environment

```bash
# Wazuh indexer reachable (credentials come from .env; do not show them on camera)
curl -k -u "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASSWORD" \
  https://localhost:9200/wazuh-alerts-*/_count

# Triage API healthy
curl -s http://127.0.0.1:8080/api/v1/health

# Identity and EDR mocks healthy
curl -s http://127.0.0.1:8001/health
curl -s http://127.0.0.1:8002/health
```

If the Wazuh variables are not exported in your shell, copy them from `.env` into the shell
without displaying them on screen (for example, `export WAZUH_INDEXER_USER=...`).

### 3.4 Pick the demo alert

Choose one recent alert from the Wazuh dashboard and copy its alert ID. For a repeatable
Mode B run, a known example from the lab is:

```
1794241003.7517
```

That is the trigger for `SOC-20261109-017` (Suricata NBT-NS poisoning, rule `100052`, level 10,
9 correlated events, 22.3s attack burst). The narration below uses this incident as the example;
swap in the current alert and its rule/host/source facts if you use a different one. Verify it
still exists before recording; if it has aged out of the index, copy a fresh ID from the Wazuh
dashboard.

### 3.5 Clean the stage

- Close unrelated browser tabs, terminals, Slack, email, and notifications.
- Do not show `.env`, API keys, Wazuh passwords, or the `screenshots/wazuh password.png` file.
- Confirm the dashboard is on `http://127.0.0.1:8501` and the API on `http://127.0.0.1:8080`.
- If re-recording, back up the decision file first:

```bash
cp data/triage_decisions.json data/triage_decisions.backup.json 2>/dev/null || true
rm -f data/triage_decisions.json
```

### 3.6 Do one timed rehearsal

Run the full flow once without recording. Confirm:

- The alert investigation completes and a new `reports/SOC-YYYYMMDD-NNN.md` and `.html` appear.
- The dashboard lists the case and shows severity, confidence, correlated events, and attack duration.
- The decision form records `approved` and the success banner appears.
- The HTML report opens directly in the browser.

---

## 4. Run of show — 9 minutes

| Time | Stage | On screen | Purpose |
|---|---|---|---|
| 0:00–0:40 | Intro | Title slide / architecture diagram | State the problem and the seven-stage flow |
| 0:40–1:40 | 1. Receive Alert | Wazuh dashboard alert detail, then daemon log or API | Prove the alert is real and explain trigger selection |
| 1:40–2:50 | 2. Run Investigation | Dashboard “Investigate” tab → job status → log | Show the orchestration and evidence gathering |
| 2:50–4:00 | 3. Timeline Created | Report §5 timeline | Show correlation, bursts, and deterministic facts |
| 4:00–5:00 | 4. ATT&CK Mapping | Report §7 mapping table | Show evidence-backed technique mapping |
| 5:00–6:40 | 5. AI Report | Report §1, §6, §8–§10 | Show the LLM narrative and risk reasoning |
| 6:40–8:00 | 6. Approve | Dashboard decision form | Show the human gate and stored decision |
| 8:00–9:00 | 7. Close Alert | Decision confirmation + metrics | Show disposition and scope boundary |
| 9:00–9:20 | Wrap | Architecture diagram / roadmap | Close with the safety and evaluation story |

---

## 5. Word-for-word demo script

### 0:00–0:40 — Intro

**[ON SCREEN]** Title slide: “AI-Agentic SOC Triage & Investigation Engine.” Then a simple
architecture diagram: Wazuh → LangGraph agent → timeline + ATT&CK → report → human approval.

**[SAY]**

> SOC analysts are overloaded by alerts. The goal of this project is not to replace the analyst.
> It is to do the first pass automatically: receive the alert, gather the evidence a human would
> gather, build a timeline, map it to MITRE ATT&CK, and write a draft report. Then it stops and
> asks a human to approve.
>
> The flow I’m going to demonstrate is: receive alert, run investigation, timeline created,
> ATT&CK mapping, AI report, approve, and close alert. At every stage I’ll explain what is
> deterministic code and what the AI is actually doing.

**[TRANSITION]**

> Let’s start with a real alert from Wazuh.

---

### 0:40–1:40 — Stage 1: Receive Alert

**[ON SCREEN]** Wazuh dashboard → Security events → the selected alert. Show rule ID, level,
agent name, source IP, timestamp. If using Mode A, then switch to `data/agent_daemon.log` and
show the `TRIGGER ... correlating` line. If using Mode B, keep the alert on screen.

**[SAY]**

> This is a real Wazuh 4.14.7 alert, not a mock. The rule is `100052`, level 10: a Suricata
> detection for a Responder-style NBT-NS response. The monitored endpoint is the Kali agent, and
> the source is another lab host.
>
> In autonomous mode, the agent polls the Wazuh indexer every five seconds. It does not query the
> Wazuh API for alerts, because Wazuh 4.x has no alerts endpoint; it reads the same
> `wazuh-alerts-*` index that the dashboard uses.
>
> It collects related events, waits a 25-second settle window so Wazuh’s correlation rules can
> fire, then chooses the highest-level alert at or above level 10 to start an investigation.
> That threshold prevents routine level-5 noise from creating reports. This stage is pure code:
> no LLM, no cost, and fully reproducible.

**[AI EXPLANATION — say one sentence]**

> The AI is not involved yet. I deliberately kept ingestion deterministic so the trigger choice
> is auditable and the system cannot “decide” to ignore or invent an alert.

**[TRANSITION]**

> Now I’ll hand this alert to the investigation graph.

---

### 1:40–2:50 — Stage 2: Run Investigation

**[ON SCREEN]** Streamlit dashboard → “Investigate” tab. Paste the alert ID. Click “Queue
investigation.” Show the job status, clicking “Refresh job status” as needed, and let it go from
`queued` to `running` to `succeeded`. If using the daemon, show the log lines instead:
`supervisor`, evidence queries, `REPORT ...`. Then open the generated report.

**[SAY]**

> The investigation is a LangGraph workflow. The nodes are watch, supervisor, identity, EDR,
> SIEM, timeline, reason, report, and notify.
>
> The supervisor is a deterministic policy, not the LLM. It decides which evidence pillars this
> alert needs. For an authentication alert it pulls identity; for an endpoint alert it pulls EDR;
> it always pulls SIEM history. The plan is recorded in the report, so a reviewer can see why the
> agent looked where it looked.
>
> The identity and EDR services are schema-matched mocks — Okta-shaped and CrowdStrike-shaped —
> because I don’t have enterprise tenants in the lab. Wazuh is real. The agent pulls every related
> event from the indexer by endpoint, source IP, account, and rule family.
>
> This is the “agentic” part: the system chooses tools, gathers evidence, and assembles an
> investigation bundle. The LLM is still not writing anything at this point.

---

### 2:50–4:00 — Stage 3: Timeline Created

**[ON SCREEN]** Open the new HTML report in the browser. Scroll to **§5 Incident Timeline**.
Highlight the numbered rows, the `attack`/`context` burst labels, and the observation window.

**[SAY]**

> Here is the timeline. Every row is a real Wazuh event, ordered oldest to newest, with rule,
> level, host, source, user, and burst label.
>
> The correlation engine links events by shared endpoint, source address, target account, rule
> group, and whether they happened before or after the trigger. It also splits the window into
> separate bursts, so two attacks ten minutes apart are not reported as one long attack. In this
> case the trigger burst is about 22 seconds.
>
> The report also computes outcome flags: did we see authentication failures, a successful login,
> privilege changes, file-integrity changes, or a session? Those flags matter because the LLM is
> not allowed to guess the outcome from a pile of logs.

**[AI EXPLANATION — say one sentence]**

> The timeline is built by Python, not by the LLM. That is the core anti-hallucination control:
> the model can describe this timeline, but it cannot add, remove, or reorder events.

---

### 4:00–5:00 — Stage 4: ATT&CK Mapping

**[ON SCREEN]** Scroll to **§7 MITRE ATT&CK Mapping**. Point at the technique IDs, names,
tactics, and the “Supporting evidence” column.

**[SAY]**

> This section has two layers. First, the agent extracts the ATT&CK tags that Wazuh already put
> on the correlated rules. Second, the LLM maps the observed behavior to techniques and must
> attach evidence for each one.
>
> In this incident we see `T1557.001`, LLMNR/NBT-NS poisoning and SMB relay; `T1557.002`, ARP
> spoofing; `T1040`, network sniffing; and `T1562.001`, disable or modify tools, because the
> Wazuh agent stopped and restarted during the attack.
>
> The prompt explicitly says: only map techniques supported by the evidence, and return an empty
> list for benign activity. So the model cannot decorate a routine login with “credential
> dumping” just because that technique exists.

---

### 5:00–6:40 — Stage 5: AI Report

**[ON SCREEN]** Scroll through **§1 Executive Summary**, **§6 Attack Narrative**, **§8 Risk
Assessment**, **§9 Recommended Actions**, and **§10 Evidence Gaps**. Finish on **§11 Metrics**.

**[SAY]**

> This is the analyst-facing report. The AI wrote the executive summary, the attack story, the
> severity rationale, the false-positive assessment, the recommendations, and the evidence gaps.
>
> But look at what it was given: a deterministic evidence pack with the trigger, the correlation
> counts, the relation breakdown, the timeline, the outcome flags, and the latency. The system
> prompt says: use only these facts; if the evidence does not establish something, say so.
>
> That is why the report can say “the outcome of the SMB authentication is not visible” instead
> of inventing a credential theft. The evidence-gaps section is a required part of the output.
>
> The recommendations are advice only. The report is stamped “DRAFT — requires analyst review,”
> and the agent never executes containment.
>
> On the metrics page you can see the operational value: in this run, 9 events correlated, a
> 22-second attack burst, and triage took about two minutes against a 45-minute manual baseline.

**[AI EXPLANATION — say one sentence]**

> The division of labor is: code computes the facts and the report template; the LLM writes the
> interpretation. If the LLM is unavailable, the report still renders with the deterministic
> sections and clearly marks the narrative as unavailable.

---

### 6:40–8:00 — Stage 6: Approve

**[ON SCREEN]** Switch to Streamlit → “Cases” tab → select the incident. Show the four metrics
at the top: Severity, Confidence, Correlated events, Attack duration. Show the warning
“No analyst decision recorded yet.” Scroll to the bottom of the case view, to “Record analyst
decision.” Choose `approved`, enter `Kyrell Green`, add a short note, click “Record decision.”
Show the success banner and the decision summary.

**[SAY]**

> This is the human-in-the-loop gate. The analyst reviews the report and records a decision:
> approved or rejected, with a name and a note.
>
> The decision is stored separately from the report, in `data/triage_decisions.json`. The report
> itself is immutable. That matters for audit: you can always see what the engine produced, and
> separately what the human decided.
>
> I’m approving this one because the evidence is coherent: LLMNR and NBT-NS poisoning, ARP
> spoofing of the gateway, and an SMB authentication attempt to the attacker host. The
> recommendation is to isolate the source and review the victim, but nothing happens
> automatically. The analyst still owns the response.

---

### 8:00–9:00 — Stage 7: Close Alert

**[ON SCREEN]** Show the decision banner. Then open `http://127.0.0.1:8080/api/v1/metrics` and
show `by_decision` incrementing. Optionally show the case list with the decision attached.
If you have a Wazuh/TheHive workflow, show the manual closure there only if it is genuinely
wired; otherwise keep it verbal.

**[SAY]**

> Closing the alert in this build means recording the disposition and marking the case reviewed
> in the control plane. The metrics endpoint now shows the case under `approved`.
>
> I want to be precise about the boundary: the current build does not automatically close the
> Wazuh alert or update TheHive, and it does not execute containment. That is intentional. The
> next step is to wire the approved decision into an action layer — a TheHive case update or an
> explicit, audited containment executor — so the human approval becomes an enforceable gate
> rather than just a record.
>
> That is the whole loop: real alert, evidence gathering, deterministic timeline, evidence-backed
> ATT&CK mapping, AI-written report, human approval, and a recorded disposition.

---

### 9:00–9:20 — Wrap

**[ON SCREEN]** Return to the architecture diagram or the report list.

**[SAY]**

> To summarize: the SIEM is real Wazuh, identity and EDR are schema-matched mocks, the
> orchestration is LangGraph, and the LLM only writes prose over facts computed in code. The
> system is evaluated against a 50-case labeled dataset, and the human approval gate is the
> safety boundary. Thank you.

---

## 6. Stage-by-stage AI explanation (Q&A reference)

Use this section if a reviewer asks “where exactly is the AI?” or if you need a slower,
more technical voiceover.

| Stage | Deterministic code | LLM involvement | Why it is split this way |
|---|---|---|---|
| Receive Alert | Poll indexer, dedupe, settle window, trigger floor | None | Ingestion must be cheap, reliable, and auditable; no model should decide which alert exists. |
| Run Investigation | Supervisor plan, identity/EDR calls, SIEM correlation queries | None | Tool selection is rule-based so the evidence plan can be reviewed and reproduced. |
| Timeline Created | Relation linking, burst splitting, outcome flags, latency metrics | None | Timelines are facts; an LLM-generated timeline would be unverifiable. |
| ATT&CK Mapping | Extract Wazuh rule ATT&CK tags | Maps behavior to techniques with evidence, constrained by prompt | Combines authoritative rule tags with contextual explanation, while forbidding invented techniques. |
| AI Report | Report template, counts, metrics, provenance hashes | Executive summary, narrative, severity rationale, FP assessment, recommendations, gaps | “Code owns the facts, LLM owns the prose.” |
| Approve | Decision store, case repository | None | Response authority stays with the human. |
| Close Alert | Decision persistence, metrics aggregation | None | Closure is a disposition record; automated response is a separate, future action layer. |

**Three technical controls worth naming**

1. **Evidence-only prompt.** The LLM receives the trigger, correlation facts, timeline, flags,
   and latency. It is told not to invent events, timestamps, IPs, users, or techniques.
2. **Deterministic fallback.** If the LLM fails or the budget expires, the report still ships
   with the deterministic sections and an explicit “narrative engine unavailable” marker.
3. **Provenance.** The report records the model, run ID, evidence SHA-256, prompt SHA-256, token
   usage, and indexer query count.

---

## 7. Demo video production plan

### 7.1 Video specification

| Item | Recommendation |
|---|---|
| Resolution | 1920×1080 |
| Frame rate | 30 fps |
| Format | MP4 (H.264), AAC audio |
| Length | 9:00–9:30 |
| Audio | Clear voiceover; normalize to about −16 LUFS |
| Captions | Burned-in or sidecar `.srt` |
| File name | `ai-agentic-soc-demo-2026-11.mp4` |
| Privacy | No `.env`, API keys, Wazuh passwords, or personal data on screen |

### 7.2 Shot list

| Shot | Time | Visual | Action |
|---|---|---|---|
| 1 | 0:00 | Title slide | Project name, presenter, one-line pitch |
| 2 | 0:10 | Architecture diagram | Trace the seven-stage flow |
| 3 | 0:40 | Wazuh dashboard alert | Show rule, level, agent, source, timestamp |
| 4 | 1:10 | Agent log or dashboard job | Show trigger or queued investigation |
| 5 | 1:40 | Streamlit “Investigate” tab | Paste alert ID, queue, show job status |
| 6 | 2:20 | Terminal log | Show supervisor/evidence/report lines |
| 7 | 2:50 | HTML report §5 | Scroll the timeline; highlight bursts |
| 8 | 4:00 | HTML report §7 | Highlight technique IDs and evidence column |
| 9 | 5:00 | HTML report §1, §6, §8–§10 | Read key sentences; show data gaps |
| 10 | 6:20 | HTML report §11 | Show latency and events correlated |
| 11 | 6:40 | Streamlit “Cases” tab | Show metrics and decision form |
| 12 | 7:30 | Decision success | Show recorded decision banner |
| 13 | 8:00 | `/api/v1/metrics` | Show `by_decision` |
| 14 | 8:40 | Architecture/roadmap | Close with scope and next steps |

### 7.3 Editing notes

- Add lower-thirds for the seven stage names.
- Zoom 110–125% on the timeline, ATT&CK table, and decision banner.
- Keep terminal font large enough to read at 1080p; hide shell history prompts if needed.
- Use a cursor highlight or subtle zoom when pointing at report sections.
- Do not speed up the investigation so much that the audience cannot see the job transition;
  cut dead time with a short “investigation running” title card instead.
- If the LLM takes longer than expected, cut to the completed report and say the narrative step
  is live but the recording uses a completed run from the same pipeline. Do not fake a result.

---

## 8. Fallback and recovery

| Failure | Recovery on camera | What to say |
|---|---|---|
| LLM is slow or rate-limited | Open an existing completed report (`reports/LATEST.html`) and continue | “The narrative step is live, but the free-tier model can take a minute or two. Here is a completed run from the same pipeline.” |
| LLM fails entirely | Show the deterministic-only report | “The engine degrades gracefully: facts still render, and the report marks the narrative as unavailable.” |
| Wazuh indexer is down | Show a pre-recorded clip or an existing report; do not claim it is live | “The indexer is unavailable right now, so I’m using a recorded run; the pipeline is unchanged.” |
| Triage API is down | Restart `venv/bin/python -m services.triage_api` | “The control plane is a thin layer over the same agent graph.” |
| Dashboard is down | Use `curl` against the API, or open the report HTML directly | “The report is the source of truth; the dashboard is a viewer.” |
| Alert ID not found | Copy a fresh ID from the Wazuh dashboard | “The index retention window rolled; I’ll use a current alert.” |
| Port already in use | `lsof -i :8080` / `lsof -i :8501`; stop the old process | Keep this off camera if possible. |
| Notification popup does not appear | Continue; it is not part of the core flow | “Notifications are a convenience layer; the report is already written.” |

**Rule:** never present a stale report as a live investigation. State the mode.

---

## 9. Q&A cheat sheet

**Is the SIEM real?**  
Yes. Wazuh 4.14.7 runs in Docker; alerts come from the real `wazuh-alerts-*` indexer. Identity
and EDR are schema-matched mocks.

**Does the AI contain the host?**  
No. The engine is advisory. It recommends containment, and a human approves. Automatic
containment is a future action layer, not part of this build.

**How do you prevent hallucinations?**  
The LLM receives a deterministic evidence pack and is instructed to use only those facts. Counts,
timestamps, relations, bursts, and rule tags are computed in Python. The report includes evidence
gaps and provenance hashes. If the LLM fails, the deterministic report still ships.

**How do you know the AI is accurate?**  
There is a 50-case labeled evaluation set (10 each: credential stuffing, brute force, phishing,
ransomware precursor, benign). In the last full run, 45/50 completed; ATT&CK match was 43/50
(86.0%), exact ATT&CK was 13/50 (26.0%), recommendation exact was 17/50 (34.0%), and lenient
recommendation was 40/50 (80.0%). The five incomplete cases were blocked by free-tier rate limits
and are scored as incomplete, not silently passed.

**How fast is it?**  
In the sample report: 9 correlated events, a 22.3-second attack burst, MTTD about 5m26s, triage
about 1m51s, total about 7m17s against a 45-minute manual baseline. Times vary with the model and
the alert.

**What happens after approval?**  
The decision is persisted in `data/triage_decisions.json`; the report is unchanged. Wiring the
approved decision into TheHive or an audited containment executor is the next step.

**Is this exposed to the internet?**  
No. The API and dashboard bind to loopback (`127.0.0.1`). There is no authentication in this
build, so exposing them would require an authenticated reverse proxy first.

**Why LangGraph?**  
It gives an explicit, inspectable state machine. Each node has a narrow job, the state carries the
evidence, and the graph can be replayed in the evaluation harness.

---

## 10. Post-demo cleanup

```bash
# Stop the API, dashboard, and mock APIs with Ctrl+C in their terminals.

# If you used the daemon and want to stop it:
pkill -f "agent.runner"

# Restore decisions if you backed them up before a retake:
# cp data/triage_decisions.backup.json data/triage_decisions.json

# Keep the generated reports as demo evidence.
ls -lt reports/SOC-*.html | head
```

Do not delete reports from a successful demo; they are the evidence trail. If you need a clean
retake, archive them instead of overwriting.

---

## 11. Appendix — exact commands and endpoints

### 11.1 Services

```bash
cd "/Users/Adult/Desktop/Kai-DAE 6Month Project Files/ai-agentic-soc"

venv/bin/uvicorn apis.identity.app:app --host 127.0.0.1 --port 8001
venv/bin/uvicorn apis.edr.app:app --host 127.0.0.1 --port 8002
venv/bin/python -m services.triage_api
venv/bin/streamlit run frontend/app.py --server.address 127.0.0.1
```

### 11.2 Agent daemon

```bash
# Foreground, for a live Mode A demo
venv/bin/python -m agent.runner

# Background, supervised
nohup bash scripts/run_agent_daemon.sh 14400 >/dev/null 2>&1 &

# Investigate one alert directly, no daemon
venv/bin/python -m agent.runner --investigate 1794241003.7517

# Deterministic-only fallback
venv/bin/python -m agent.runner --no-llm
```

### 11.3 API calls

```bash
# Health
curl -s http://127.0.0.1:8080/api/v1/health | venv/bin/python -m json.tool

# List cases
curl -s http://127.0.0.1:8080/api/v1/cases | venv/bin/python -m json.tool

# Queue an investigation
curl -s -X POST http://127.0.0.1:8080/api/v1/investigations \
  -H 'Content-Type: application/json' \
  -d '{"alert_id":"1794241003.7517","force":false}' \
  | venv/bin/python -m json.tool

# Poll the job
curl -s http://127.0.0.1:8080/api/v1/jobs/<JOB_ID> | venv/bin/python -m json.tool

# Record the analyst decision (replace the case ID with the job result's incident_id)
curl -s -X POST http://127.0.0.1:8080/api/v1/cases/SOC-20261109-017/decision \
  -H 'Content-Type: application/json' \
  -d '{"decision":"approved","analyst":"Kyrell Green","note":"Reviewed evidence; approve containment recommendation."}' \
  | venv/bin/python -m json.tool

# Metrics
curl -s http://127.0.0.1:8080/api/v1/metrics | venv/bin/python -m json.tool
```

### 11.4 URLs

| Service | URL |
|---|---|
| Wazuh dashboard | `https://localhost/` |
| Wazuh indexer | `https://localhost:9200` |
| Wazuh API | `https://localhost:55000` |
| Triage API | `http://127.0.0.1:8080` |
| Triage API docs | `http://127.0.0.1:8080/docs` |
| Streamlit dashboard | `http://127.0.0.1:8501` |
| Identity mock | `http://127.0.0.1:8001` |
| EDR mock | `http://127.0.0.1:8002` |

---

## 12. Deliverable checklist

- [ ] Demo script rehearsed once end-to-end.
- [ ] Services running and health checks passed.
- [ ] Demo alert ID verified in the Wazuh index.
- [ ] Screen recording at 1920×1080 with clear audio.
- [ ] All seven stages shown on screen.
- [ ] AI explanation spoken at each stage.
- [ ] Human approval recorded and shown.
- [ ] Scope boundary (no automatic containment / no automatic Wazuh/TheHive closure) stated.
- [ ] No secrets or personal data visible.
- [ ] Video exported as `ai-agentic-soc-demo-2026-11.mp4`.
