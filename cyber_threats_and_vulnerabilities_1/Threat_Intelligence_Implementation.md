# Threat Intelligence Implementation Report

**Author:** Kali Linux / SOC Lab Environment
**Scope:** IoC Analysis (2 indicators) + OpenCTI Threat Intelligence Platform implementation plan (Docker, 2+ connectors)
**Context:** This documentation supports a broader Agentic SOC lab build. Where a step has not yet been executed, it is documented as a **planned implementation** with exact commands, configuration, and the reasoning for why it matters — so the write-up satisfies "explain the methodology and implications" even for the not-yet-run portions.

---

## 1. Indicator of Compromise (IoC) Analysis

Two IoC types are analyzed below: a **network-based IoC** (malicious IP) and a **host-based IoC** (malicious file hash). These are the two most common IoC categories a SOC — agentic or human-run — needs to detect and enrich.

### 1.1 IoC #1 — Malicious IP Address (Network-based)

| Field | Detail |
|---|---|
| **Indicator type** | IPv4 address associated with command-and-control (C2) infrastructure |
| **Example indicator** | e.g. an IP flagged by threat feeds as a Cobalt Strike / botnet C2 endpoint (a real value would be pulled from a feed like AlienVault OTX, Abuse.ch, or your own OpenCTI instance at implementation time) |
| **Detection method** | Network IDS/NSM (e.g., **Suricata** or **Zeek**) matching outbound connection attempts against a threat-intel-fed blocklist; alternatively, **Wazuh** correlating firewall/proxy logs against an ingested IoC list |
| **How it indicates a threat** | A host reaching out to a known C2 IP suggests it is already compromised (beaconing) rather than about to be attacked — this is a *post-compromise* indicator. Frequency, timing regularity ("beacon" intervals), and destination reputation are what elevate a single connection log line into a confirmed IoC hit. |
| **Detection logic (example Suricata rule)** | `alert ip $HOME_NET any -> [<C2_IP>] any (msg:"Possible C2 Beacon - Known Bad IP"; sid:1000001; rev:1;)` |

### 1.2 IoC #2 — Malicious File Hash (Host-based)

| Field | Detail |
|---|---|
| **Indicator type** | SHA-256 hash of a known-malicious binary |
| **Example indicator** | A hash matching a known malware family in **VirusTotal** / **MalwareBazaar** (e.g., a hash tied to a documented ransomware dropper or infostealer) |
| **Detection method** | Endpoint-side hashing via **Wazuh's FIM (File Integrity Monitoring)** or an EDR agent, compared against a hash blocklist ingested from threat intel; alternatively, on-demand lookup: `sha256sum <file>` then check the hash against VirusTotal/MalwareBazaar or an OpenCTI-ingested indicator set |
| **How it indicates a threat** | A file hash match is a **high-confidence, low-false-positive** IoC — unlike an IP (which can be shared/dynamic infrastructure), a specific file hash uniquely fingerprints a known-bad binary. A match confirms the *exact* malicious artifact is present on a host, not just suspicious behavior. |
| **Example command** | `sha256sum suspicious_file.exe`<br>`curl -s "https://www.virustotal.com/api/v3/files/<hash>" -H "x-apikey: <API_KEY>"` |

**Why these two together matter for a SOC:** network IoCs (IPs/domains) catch activity *in motion* (beaconing, exfiltration) while host IoCs (hashes) confirm *what* is running. A mature detection pipeline — and especially an agentic one — correlates both: "this host hit a bad IP AND has a matching bad hash" is a far stronger signal than either alone.

---

## 2. OpenCTI Threat Intelligence Platform — Implementation Plan

### 2.1 Why OpenCTI (in the context of an Agentic SOC lab)

OpenCTI is the piece that turns raw IoCs into **structured, queryable threat intelligence** (STIX2 objects: indicators, threat actors, malware, campaigns, relationships). For an agentic SOC, this matters specifically because:

- An AI agent triaging an alert can't just see "IP: 1.2.3.4" — it needs to **query a knowledge base** to answer "is this bad, and if so, who/what is behind it, and what else should I look for?" OpenCTI is that knowledge base, exposed via a **GraphQL API** an agent can call programmatically.
- Connectors keep that knowledge base **automatically current**, so the agent isn't reasoning over stale/manually-updated data.
- OpenCTI's relationship graph (indicator → malware → threat actor → campaign) lets an agent reason about **context**, not just binary "known bad / not known bad" — this is what enables tiered, explainable automated response rather than blind blocking.

### 2.2 Installation (Docker) — Planned Steps

```bash
# 1. Clone the official OpenCTI docker deployment
git clone https://github.com/OpenCTI-Platform/docker.git
cd docker

# 2. Copy and configure environment variables
cp .env.sample .env
```

Key values to set in `.env`:
```
OPENCTI_ADMIN_EMAIL=admin@soclab.local
OPENCTI_ADMIN_PASSWORD=<strong_password>
OPENCTI_ADMIN_TOKEN=<generate with: cat /proc/sys/kernel/random/uuid>
MINIO_ROOT_PASSWORD=<password>
RABBITMQ_DEFAULT_PASS=<password>
CONNECTOR_EXPORT_FILE_STIX_ID=<uuid>
CONNECTOR_IMPORT_FILE_STIX_ID=<uuid>
```

```bash
# 3. Bring the platform up
sudo docker compose up -d

# 4. Verify all containers are healthy
sudo docker compose ps
sudo docker compose logs -f opencti
```

- Access the web UI at `http://localhost:8080`, log in with the admin credentials set in `.env`.
- OpenCTI's core stack includes: the platform app, Elasticsearch (data store), RabbitMQ (message bus), Redis, and MinIO (file storage) — all defined in the `docker-compose.yml` that ships with the repo.

### 2.3 Connector Configuration (2+ connectors)

Connectors are what feed and enrich OpenCTI automatically. Two well-suited to a SOC lab:

**Connector 1 — MITRE ATT&CK Connector**
- Purpose: imports the full ATT&CK framework (tactics, techniques, threat groups) as structured STIX data.
- Why it matters for the agent: gives the agent a shared vocabulary — when it sees behavior matching a technique (e.g., T1059 command-line execution), it can map that directly to known threat actor TTPs already in the graph.
```yaml
# docker-compose override snippet
connector-mitre:
  image: opencti/connector-mitre-attack:latest
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
    - CONNECTOR_ID=<generate-uuid>
    - CONNECTOR_NAME=MITRE ATT&CK
    - CONNECTOR_SCOPE=identity,attack-pattern,course-of-action,intrusion-set,malware,tool,report
    - CONNECTOR_CONFIDENCE_LEVEL=15
    - CONNECTOR_RUN_AND_TERMINATE=false
```

**Connector 2 — AlienVault OTX Connector**
- Purpose: pulls live IoC pulses (IPs, domains, hashes) from AlienVault's Open Threat Exchange community feed.
- Why it matters for the agent: this is the connector that would actually surface the two IoC types documented in Section 1 automatically, so an agent querying OpenCTI for "have we seen this IP/hash before" gets a real, current answer instead of nothing.
```yaml
connector-otx:
  image: opencti/connector-alienvault:latest
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
    - CONNECTOR_ID=<generate-uuid>
    - CONNECTOR_NAME=AlienVault OTX
    - ALIENVAULT_API_KEY=<your_otx_api_key>
    - ALIENVAULT_TLP=White
    - ALIENVAULT_INTERVAL_SEC=1800
```

```bash
# Apply and start the connectors
sudo docker compose up -d connector-mitre connector-otx

# Confirm registration inside OpenCTI: Data > Connectors in the web UI
# Each connector shows a heartbeat/last-run status once working
```

### 2.4 Basic Usage Demonstration (planned)

1. In the OpenCTI UI, navigate to **Observations → Indicators** and confirm IoCs are flowing in from the OTX connector.
2. Search for one of the IoCs documented in Section 1 (e.g., paste the malicious IP or hash into the global search) — if present, OpenCTI shows its relationships (linked malware, campaigns, confidence score).
3. Manually create one indicator entry (STIX Indicator object) for a locally-observed IoC — this demonstrates both automated ingestion (via connector) and manual analyst input, which is the realistic hybrid workflow of most SOCs.
4. Use the GraphQL Playground (`http://localhost:8080/graphql`) to run a sample query pulling all indicators with a given pattern — this is the exact mechanism an agentic component would use programmatically instead of the UI.

---

## 3. How This Fits an Agentic SOC Lab (General Explanation)

Since the goal is an **agentic SOC**, the point of this whole module isn't "run OpenCTI for its own sake" — it's building the intelligence layer the agent reasons against. Mapped out end-to-end:

| Step | What it does | Why the agent needs it |
|---|---|---|
| **IoC analysis (Section 1)** | Establishes what a network vs. host IoC looks like and how each is detected | The agent's detection layer (Wazuh/Suricata) needs pre-defined logic for *what counts as an IoC hit* before it can hand anything to an intelligence layer |
| **OpenCTI deployment** | Stands up a structured, queryable store of threat data | Gives the agent a place to ask "have I seen this before, and what does it mean" instead of hardcoding threat knowledge into the agent itself |
| **MITRE ATT&CK connector** | Loads a shared framework of adversary behavior | Lets the agent classify *why* something is suspicious in standardized terms (technique IDs), which is also what most SOAR/reporting tooling expects |
| **OTX connector** | Keeps IoC data live and current | Prevents the agent from working off stale intel — a C2 IP from six months ago may be dead; the agent needs freshness to avoid false confidence |
| **API/GraphQL access** | Machine-readable interface into OpenCTI | This is literally the integration point: your agent (via a script, LangChain tool, or custom function-calling setup) queries this API when it needs enrichment mid-investigation |

**The overall pipeline this sets up:**
```
Alert fires (Wazuh/Suricata)
        │
        ▼
Agent extracts IoC (IP / hash / domain)
        │
        ▼
Agent queries OpenCTI GraphQL API for that IoC
        │
        ▼
OpenCTI returns: known? malware family? threat actor? ATT&CK technique?
        │
        ▼
Agent uses that context to decide severity + recommended action
        │
        ▼
Agent logs decision + (optionally) creates/updates the OpenCTI report object
```

This is the standard reason OpenCTI shows up in agentic SOC designs specifically: it's not just a dashboard for humans, it's a **structured memory and reasoning substrate** the agent can call into, which is exactly what a language-model-driven triage step needs instead of relying purely on its own training data (which will always be stale relative to live threat feeds).

---

## 4. Documentation Note on Scope

The IoC analysis in Section 1 is fully demonstrated with realistic detection logic and example commands. The OpenCTI deployment in Section 2 is documented as a **complete, ready-to-execute implementation plan** rather than a live deployment — every command, environment variable, and connector configuration shown is what would be run to stand it up. If/when executed, screenshots of the running containers (`docker compose ps`), the OpenCTI dashboard, and the connector status page (Data → Connectors) would be added here as evidence of functionality.
