---
layout: default
title: "AI-Agentic SOC Triage Engine"
permalink: /projects/ai-agentic-soc/
---

<div class="dae-brand">
  <img src="{{ site.branding.logo | relative_url }}" alt="{{ site.branding.logo_alt }}">
</div>

<nav class="portfolio-nav" aria-label="Portfolio navigation">
  {% for link in site.navigation %}
  <a href="{{ link.url | relative_url }}">{{ link.title }}</a>
  {% unless forloop.last %}<span aria-hidden="true"> · </span>{% endunless %}
  {% endfor %}
</nav>

# Building an AI-Agentic SOC Triage Engine

**A human-in-the-loop investigation pipeline that turns raw Wazuh alerts into a MITRE-mapped timeline, an evidence-backed risk narrative, and an analyst decision.**

| | |
|---|---|
| **Role** | Solo design and build |
| **Program** | DAE 6-month cybersecurity program, capstone project |
| **Stack** | Python 3.9, LangGraph, Wazuh 4.14.7, FastAPI, Streamlit, SQLite, PostgreSQL, Docker |
| **Repository** | [DAE-6-Month-Project-Files / ai-agentic-soc](https://github.com/Kai0sama28/DAE-6-Month-Project-Files/tree/main/ai-agentic-soc) |

## The problem

A SOC analyst does not usually start an investigation with a clean story. They start with an alert, then spend the next 30–45 minutes opening a SIEM, checking an identity provider, looking at endpoint telemetry, searching for related events, and rebuilding a timeline by hand.

That work is repetitive, but it is not low-skill. The analyst has to decide which evidence matters, which activity is benign, whether the alert is part of a larger pattern, and whether containment is justified. The bottleneck is not a lack of alerts. It is the time between receiving an alert and having enough context to make a defensible decision.

I built the AI-Agentic SOC Triage Engine to compress that first phase. The goal was not to replace the analyst or let a model take autonomous action. The goal was to hand the analyst a draft investigation: correlated events, a deterministic timeline, ATT&CK mapping, evidence gaps, and a written risk summary, all before they open the case.

## Why I built it

I wanted a capstone that connected the skills I was learning instead of treating them as separate exercises. That meant combining:

- real SIEM ingestion and alert triage;
- identity and endpoint evidence;
- log correlation and MITRE ATT&CK mapping;
- Python service development and testing;
- LLM orchestration with a hard safety boundary;
- a measurable evaluation, not just a demo.

The lab already had a real Wazuh 4.14.7 deployment running in Docker, with Kali, Ubuntu, and Windows agents enrolled. Using real Wazuh alerts made the project more useful than building against a synthetic SIEM. It also exposed real integration problems: API version changes, correlation timing, log rotation, alert volume, and evidence that is simply missing.

## Architecture and investigation flow

The engine runs a LangGraph investigation pipeline:

```text
Wazuh 4.14.7  ──►  indexer: wazuh-alerts-*  ──►  watcher
                                                    │
                                                    ▼
                                      supervisor / triage decision
                                                    │
                    ┌───────────────────────────────┼───────────────────────────────┐
                    ▼                               ▼                               ▼
          Identity evidence                 EDR evidence                    SIEM history
          (mock Okta-shaped)               (mock Falcon-shaped)             (real Wazuh)
                    └───────────────────────────────┼───────────────────────────────┘
                                                    ▼
                                  deterministic correlation + timeline
                                                    │
                                                    ▼
                                      MITRE ATT&CK mapping + flags
                                                    │
                                                    ▼
                                  LLM narrative over the evidence pack
                                                    │
                                                    ▼
                                  Markdown + HTML report + dashboard
                                                    │
                                                    ▼
                                     human approval gate
```

For every alert that passes the trigger threshold, the system:

1. **Watches** the Wazuh indexer for new alerts.
2. **Waits for a settle window** so Wazuh's aggregate rules can fire before the agent chooses a trigger.
3. **Selects evidence** through a supervisor step instead of querying every source blindly.
4. **Pulls identity, EDR, and SIEM history** for the affected endpoint, account, source address, and rule family.
5. **Correlates events deterministically** in Python, including relation counts, event phases, and separate attack bursts.
6. **Builds a timeline** and maps the evidence to MITRE ATT&CK.
7. **Asks the LLM for a narrative** using the deterministic evidence pack.
8. **Writes a draft report** in Markdown and HTML, with provenance hashes, model information, token usage, and indexer query counts.
9. **Stops at the approval gate**. The agent never executes containment.

The analyst-facing console is a Streamlit dashboard called **StreamSOC**. It renders the report queue, case detail, timeline, ATT&CK table, evidence gaps, full report, and approval form. It can run against the live FastAPI control plane or in local-report mode when the lab stack is offline.

## Dashboard

The screenshots below are from the working dashboard, loaded with real reports generated by the agent.

![StreamSOC overview dashboard]({{ '/assets/images/ai-agentic-soc/dashboard-overview.png' | relative_url }})

*The overview shows case volume, severity mix, analyst decision state, top MITRE tactics, top detection rules, and correlated-event totals.*

![SOC-20261105-013 case summary]({{ '/assets/images/ai-agentic-soc/dashboard-case-summary.png' | relative_url }})

*Case detail for a High severity, High confidence Responder-style credential capture incident. The report was generated automatically and is explicitly marked as a draft requiring analyst review.*

![Incident timeline in the dashboard]({{ '/assets/images/ai-agentic-soc/dashboard-timeline.png' | relative_url }})

*The timeline is built from correlated Wazuh and Suricata events. It is deterministic output from the correlation layer, not text invented by the model.*

![Deterministic evidence and flags]({{ '/assets/images/ai-agentic-soc/dashboard-evidence.png' | relative_url }})

*The evidence view exposes correlation relations, rule breakdowns, deterministic flags, recommended actions, and evidence gaps.*

![MITRE ATT&CK mapping]({{ '/assets/images/ai-agentic-soc/dashboard-mitre.png' | relative_url }})

*ATT&CK techniques are mapped from the correlated rules, with the supporting evidence visible next to each technique.*

![Human approval decision]({{ '/assets/images/ai-agentic-soc/dashboard-decision-approved.png' | relative_url }})

*The approval gate records the analyst's decision. It does not execute containment or close the source SIEM case.*

![Evaluation results in the dashboard]({{ '/assets/images/ai-agentic-soc/dashboard-evaluation-results.png' | relative_url }})

*The evaluation view renders the measured results from the labeled 50-case dataset, including completed investigations, ATT&CK accuracy, recommendation accuracy, and per-label breakdowns.*

## The design rule: code owns the facts, the LLM owns the prose

The most important design decision was to separate deterministic computation from language generation.

| Output | Produced by |
|---|---|
| Event counts, rule counts, relation counts | Python |
| Timeline ordering, phases, burst splitting | Python |
| MITRE technique and tactic mapping | Python, from rule metadata and correlation |
| Deterministic flags such as `auth_success_observed` | Python |
| Severity and confidence rationale | LLM, constrained to the evidence pack |
| Executive summary and attack narrative | LLM, constrained to the evidence pack |
| Recommended actions | LLM, advisory only |
| Containment execution | Never automated |

This matters because an LLM is useful at turning a structured evidence pack into readable prose, but it is not a reliable counting engine. If a prompt asks a model to count 250 events, split them into bursts, and infer an attack sequence, the output may sound convincing while being wrong.

The engine computes the facts first. The model receives the computed correlation, timeline, flags, and rule evidence. Its job is to explain what the evidence shows, not to produce the numbers. The report includes the evidence-pack hash, prompt hash, model name, token usage, and indexer query count so a reviewer can trace the result.

## Case study: Responder-style credential capture

The strongest example from the local report store is `SOC-20261105-013`.

The trigger was a level-10 Suricata rule for an HTTP 407 NTLM proxy authentication challenge from `192.168.64.50` against the Kali endpoint `192.168.64.3`. On its own, that alert could be a proxy misconfiguration. The investigation turned it into a coherent attack chain:

- LLMNR and NBT-NS poisoning from the attacker;
- WPAD lookups from the victim over both protocols;
- ARP spoofing of the gateway `192.168.64.1` from MAC `02:de:ad:be:ef:50`;
- SMB NTLMSSP authentication attempts to the attacker;
- an HTTP 407 NTLM challenge from the attacker's WPAD service.

The deterministic correlation produced **250 related events**, **three bursts**, and a trigger burst of **1m 44s**. The report mapped the activity to MITRE ATT&CK `T1557.001`, `T1557.002`, and `T1040`, with supporting rules for each technique.

Just as important, the deterministic flags kept the narrative honest:

- `auth_success_observed`: false;
- `privilege_change_observed`: false;
- `file_integrity_change_observed`: false;
- no confirmed credential exfiltration.

That changed the severity decision. The incident was rated **High**, not Critical, because the attack chain was real but successful compromise was not confirmed. The report also listed what was missing: no packet capture to prove NTLM hash capture, no host telemetry from the attacker, and no Windows Security event logs on the Linux endpoint. The mock EDR API was unavailable during that run, and the report said so instead of inventing endpoint evidence.

### Measured result for this case

| Metric | Result |
|---|---|
| MTTD: Wazuh alert to agent detection | 34.6s |
| Settle window before triage | 25.0s |
| Agent triage time: detection to report | 1m 04s |
| Total time to incident report | 1m 38s |
| Manual baseline for the same work | 45m 00s |
| Estimated time saved against that baseline | 43m 21s |
| Events correlated | 250 |

The 45-minute manual baseline is an illustrative comparison, not a controlled time study. The honest claim is narrower: the agent produced a structured first-pass investigation in under two minutes, and the analyst still had to review it, validate the evidence, and decide on a response.

The analyst decision in the dashboard was recorded as **approved**, with the note that no successful authentication was observed and containment should be escalated for analyst action. The system did not isolate the host, reset credentials, or close the Wazuh case. That remains a human action.

## Technologies

| Layer | Technology | What it does |
|---|---|---|
| SIEM and alert source | Wazuh 4.14.7, OpenSearch indexer | Real alerts from `wazuh-alerts-*`; Wazuh API supplies agent inventory |
| Agent orchestration | LangGraph, Python 3.9 | Supervisor, evidence gathering, correlation, report generation |
| LLM | OpenRouter `nvidia/nemotron-3-ultra-550b-a55b:free` with fallback | Narrative and recommendations over deterministic evidence |
| Evidence APIs | FastAPI, Uvicorn, SQLAlchemy, SQLite | Okta-shaped identity mock and Falcon-shaped EDR mock |
| Analyst API | FastAPI, Uvicorn | Queue investigations, expose cases and reports, persist decisions |
| Dashboard | Streamlit, pandas | Case queue, timeline, ATT&CK, evidence, approval, evaluation |
| Data | SQLite, PostgreSQL `eval` schema | Operational state and labeled evaluation ground truth |
| Lab | Docker Desktop, UTM, Kali Linux, Suricata | Wazuh stack, monitored endpoints, network detections |
| Quality | pytest | Engine, API, parser, and end-to-end tests |

## Challenges

### 1. Wazuh 4.x does not expose an alerts API

The original design expected to pull alerts from the Wazuh API. On Wazuh 4.14.7, the old `/security-events` route returns 404. The working alert source is the indexer at `wazuh-alerts-*`, using HTTP Basic authentication and OpenSearch queries.

That changed the integration layer. The Wazuh API is still useful for agent inventory, rules, manager status, and log testing, but it is not the alert store. Separating those responsibilities made the connector easier to reason about and matched how the Wazuh dashboard itself reads alerts.

### 2. Correlation rules fire after the individual events

Triggering on the first level-5 event produced the wrong incident. The agent would report a PAM or SSH event before Wazuh's aggregate rule had fired, then correlate only a fraction of the attack.

The fix was a configurable settle window (25 seconds) plus a trigger floor: every alert at level 4 or above is collected as context, but only level 10 or above can start an investigation. The agent also splits events into bursts, so two attacks from the same source minutes apart are not reported as one long incident.

### 3. Free-tier LLM reliability

Free models routinely returned prose instead of JSON, truncated responses, or spent their whole token budget on hidden reasoning and returned nothing. A stalled generation stream could also hang the agent longer than the HTTP timeout suggested.

The mitigation was a model chain, a repair re-ask that attaches the malformed response and demands raw JSON, a hard wall-clock budget, and a deterministic-only fallback. If the model fails, the report still ships with computed facts and an explicit note that the narrative is unavailable. The system does not block the investigation on the LLM.

### 4. Missing evidence is normal

In the Responder case, the EDR mock was not running and there was no packet capture. A less careful agent could have filled those gaps with plausible-sounding text.

Instead, evidence availability is tracked per source. The report records what was available, what was unavailable, and what that means for confidence. The evidence-gaps section is a first-class part of the output, not an afterthought.

### 5. Safety is an architecture constraint, not a prompt

The agent has no containment node. It cannot isolate a host, disable an account, or close a case. The LLM can recommend those actions, but the only thing the system persists is the analyst's decision.

The dashboard makes that boundary visible: approval records a human decision, and the UI states that it does not execute containment. That constraint made the project easier to defend because the automation boundary is explicit in the graph, the API, and the interface.

### 6. Evaluation includes failure

The labeled dataset contains 50 incident bundles: 10 each of credential stuffing, brute force, phishing, ransomware precursor, and benign activity. Labels are assigned by the generator, never by the model.

The live evaluation completed **45 of 50** investigations. The remaining five hit OpenRouter free-tier rate limits. They were scored as incomplete and incorrect, not silently passed through a deterministic fallback. That is the less flattering choice, but it is the accurate one.

### 7. Operational integrations fail quietly

The Suricata-to-Wazuh feed stopped after the daily log rotation. Suricata was still running and incrementing alert counters, but `eve.json` was empty and Wazuh had no new Suricata alerts. The fix was to reopen the log files with `suricatasc -c reopen-log-files` and restart the Wazuh agent.

This was a useful reminder that detection engineering includes operations. A working rule is not working if the log pipeline has silently lost its file descriptor.

## Results

At the time of the dashboard capture, the local report store held **16 triaged incidents**. Three were High or Critical, and the reports represented **1,837 correlated events** and **12 ATT&CK techniques**. Those totals are a live lab snapshot, not a production benchmark. The more useful results are the per-incident timing and the labeled evaluation.

The engine test suite was passing at **99 tests**, including alert normalization, both mock APIs, the Wazuh clients, the evaluation dataset, the evaluation runner, and the Triage API.

### Labeled evaluation

The evaluation replayed each labeled case through the real agent graph and compared the output with ground truth.

| Metric | Result |
|---|---|
| Investigations completed | 45 / 50 (90.0%) |
| Correct ATT&CK technique (any expected technique) | 43 / 50 (86.0%) |
| Correct ATT&CK technique set (exact) | 13 / 50 (26.0%) |
| Correct recommendation (exact action) | 17 / 50 (34.0%) |
| Correct recommendation (lenient) | 40 / 50 (80.0%) |

The ATT&CK result is the strongest part of the evaluation: the system usually identifies at least one correct technique. Exact technique-set matching and exact action recommendation are much harder. The model often recommended escalation or investigation while also describing host or account containment, which is reasonable analyst behavior but does not match a single exact label.

That gap is the next improvement target. A production system would need a clearer action taxonomy, better calibration, and a feedback loop from analyst decisions. Reporting the 34% exact-match rate is more useful than hiding it behind a lenient metric.

## Lessons learned

**The model is not the hard part.** The difficult work was normalizing alerts, understanding Wazuh's rule timing, correlating evidence, handling missing sources, and making the output reproducible. The LLM is a presentation layer over that work.

**AI should compress analyst effort, not own the decision.** The most valuable output is not "the AI says contain the host." It is a timeline, the evidence behind each claim, and a clear list of what is still unknown.

**Evaluation must include abstention and failure.** A system that cannot say "the LLM was unavailable" or "EDR evidence was missing" is less trustworthy than one that reports its gaps.

**Human-in-the-loop is a product requirement.** A boolean approval flag is not enough. The analyst needs a readable report, a visible evidence trail, a decision form, and persistence. The safety model has to exist in the UI, not just in the design document.

**Scope boundaries build trust.** Saying "this does not execute containment" and "this does not close the Wazuh case" makes the system easier to evaluate honestly. It also makes the next integration step obvious.

## What I would build next

- Wire the persisted analyst decision into TheHive or an explicitly approved action executor.
- Add authentication and role-based access before exposing the API or dashboard beyond loopback.
- Replace the mock identity and EDR services with real integrations, or clearly label them as simulated in every report.
- Use a read-only Wazuh indexer account scoped to `wazuh-alerts-*`.
- Expand the evaluation set and add an analyst-feedback loop so decisions become calibration data.
- Add packet-capture evidence and deeper endpoint telemetry to close the gaps exposed by the Responder case.
- Improve entity resolution and deduplication across repeated alerts from the same source.

## Scope and limitations

This is a lab project, not a production SOC platform.

- Identity and EDR are schema-matched mocks; Wazuh is real.
- The deployment is a single-node lab with a small number of agents.
- The LLM runs on a free-tier route with rate limits and variable latency.
- The agent produces draft reports and recommendations; it does not execute containment.
- The API and dashboard have no authentication and are intended for loopback use.
- The 45-minute manual baseline is illustrative, not a controlled benchmark.
- Five evaluation cases were incomplete because of rate limits and were scored as such.

## Conclusion

The AI-Agentic SOC Triage Engine is not an autonomous SOC. It is a triage accelerator with an auditable evidence trail and a hard human gate.

The project gave me a practical view of how SIEM, identity, endpoint, correlation, LLM orchestration, API design, and interface design fit together. It also made the limits of each layer visible: the model can explain evidence, but it cannot be trusted to produce the evidence; the agent can recommend a response, but it cannot own the response; and a dashboard is only useful if it shows the analyst what is known, what is missing, and what to do next.

That is the part I would carry into a SOC analyst role: automate the repetitive first pass, keep the evidence reproducible, and leave the decision with the person accountable for it.
