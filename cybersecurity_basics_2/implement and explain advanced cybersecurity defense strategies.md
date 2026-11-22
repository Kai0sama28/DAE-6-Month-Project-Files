# Implement and Explain Advanced Cybersecurity Defense Strategies

**Workspace:** `DAE-6-Month-Project-Files` (DAE 6-month cybersecurity program, capstone `ai-agentic-soc`)
**Prepared:** 2026-11-22
**Purpose:** Map existing artifacts to the four rubric areas — Zero Trust, Defense in Depth, supply-chain risk, and an advanced security model — with file paths and line-level evidence. This report deliberately separates *implemented controls* from *adjacent concepts* and *documented gaps*, because the repository contains both strong layered defenses and stale claims that must not be overstated.

---

## Rubric coverage at a glance

| Rubric requirement | Status | Primary evidence |
|---|---|---|
| Zero Trust across ≥2 layers | **Partial** — Zero-Trust-adjacent controls implemented; full ZTA not implemented | `cybersecurity_basics_1/Comprehensive_Security_Policy.md`; `network_security_1/Network_Topology_Implementation_Report.md`; `design_1/Brainstorm Ideas.md` (idea only) |
| Defense in Depth across ≥3 layers | **Met** — explicitly named and implemented across ≥5 layers | `network_security_1/Monitor_and_Respond_Network_Security_Events.md`; `ai-agentic-soc/Firewall_IDS_IPS_Implementation_Report.md` |
| ≥1 supply-chain risk identified / mitigated | **Partial** — source-integrity concern and hygiene documented; formal supply-chain assurance absent | `cyber_threats_and_vulnerabilities_1/CVE_analysis.md`; `.gitignore`; `Vulnerability_Assessment_Report.md` |
| ≥1 advanced security model applied | **Partial** — DAC with ACLs and role separation implemented and explained; no formal advanced model | `network_security_1/Access Control Implementation Report.pdf` |

---

## 1. Zero Trust across two or more layers

### What is explicitly present

The only literal "Zero Trust Architecture" statement is a **future-project idea**, not an implementation:

- `design_1/Brainstorm Ideas.md:6–7` — "### 2. 'Secure by Design' Cloud Landing Zone with Policy-as-Code" proposes to "Build a multi-cloud landing zone using **Infrastructure as Code (Terraform)** that implements **Zero Trust Architecture** and strict **Least Privilege** principles. Integrate automated **policy-as-code** checks (using tools like tfsec or Checkov)…" There are no `.tf` files or tfsec/Checkov implementations anywhere in the repository, so this remains a concept.

### What is actually implemented (Zero-Trust-adjacent controls, across ≥2 layers)

**Identity / access layer — least privilege and unique credentials.**
`cybersecurity_basics_1/Comprehensive_Security_Policy.md:25–36` (Rule 1): "Every user, service, and API account gets **only the rights required to do its job** — no exception accounts on the Wazuh manager, no standing root on shared hosts"; "Admin/API access (e.g., Wazuh API `55000`) requires unique accounts and **strong passwords or keys**; never shared logins"; "Interactive SSH to lab endpoints must use **key-based authentication**; password auth is disabled…" Rule 2 (lines 38–47) adds secret hygiene and rotation, and requires MFA where supported.

**Network layer — default-deny, scoped management plane, encrypted transport.**
`network_security_1/Network_Topology_Implementation_Report.md:121–126`:
- "**Single management plane** | All endpoints talk only to the manager (star hub). There is one place to enforce policy, one choke point to monitor…"
- "**Default-deny edge** | …the firewall can scope every port to `10.11.0.0/22` — agent (1514/1515) and API (55000) traffic is refused from any source outside the LAN (`ufw allow from 10.11.0.0/22 … ; ufw deny 1514,1515,55000/tcp`)"
- "**Encrypted agent channel** | Every spoke→hub flow is TLS (Wazuh agent↔manager). An attacker who taps the LAN still cannot read logs or FIM events in transit"
- "**Host isolation** | Because endpoints are VMs on the UTM host, a compromised host can be disconnected at the virtual NIC level (hypervisor isolation)"

`network_security_1/Network_Protocols_and_Architectures_Report.md:139–151` reinforces: "a single private LAN, default-deny at the edge, encrypted agent channels, and encrypted human access", with SSH key-only, HTTPS/TLS 1.2+ for dashboard and API, and TCP port allow-listing.

`cybersecurity_basics_1/Comprehensive_Security_Policy.md:61–71` (Rule 4) adds: "The lab network is segmented … a **quarantine segment (deny-all default)** exists for compromised hosts" and "**No exposed management surface to the internet:** the Wazuh API (`55000`) and indexer (`9200`) are never published to the WAN."

**Authorization / response layer — separation of authority (human approval gate).**
`ai-agentic-soc/README.md:96–102`: "**The agent never executes containment.** Recommendations are advisory; a human approves. The report is stamped `DRAFT — requires analyst review`." The active graph confirms this: `ai-agentic-soc/agent/graph.py:680–704` ends at `report → notify → END` with no isolation/execution node.

### Honest assessment

A full Zero Trust Architecture requires an identity-centric policy decision/enforcement point, per-request continuous authorization, device posture checks, and microsegmentation. None of those are present. The defensible wording is: **implemented Zero-Trust-adjacent controls — least privilege, default-deny, segmentation, TLS, scoped management ports, and human approval across identity, network and response layers — but did not deploy a named ZTA.** Also note: the project's own Triage API and Streamlit dashboard have **no authentication** (`ai_api_integration_1/implement_open_or_secured_apis.md:57–61`; `ai-agentic-soc/docs/TECHNICAL_DOCUMENTATION.md:765`) and are intended for loopback use only, and Wazuh TLS verification defaults to false (`ai-agentic-soc/.env.example:2–5`) — transport is encrypted but the self-signed certificate is not validated.

## 2. Defense in Depth across three or more layers

This is the strongest supported area. The strategy is explicitly named, explained, and implemented.

**Explicit naming.**
- `network_security_1/Monitor_and_Respond_Network_Security_Events.md:34–39`: "Monitoring is **defense-in-depth across three layers**: a host layer (agent-shipped logs and file-integrity events), a network layer (firewall + IDS/IPS correlation), and an endpoint behaviour layer (process/network/file telemetry). All three funnel into the SIEM, which correlates and alerts." Lines 75–78 explain the value: "each layer watches … from an independent vantage point. A single event … is noise; a *correlated pattern* across layers is a security incident."
- `security_operations_center_1/SOC_Operations.md:68–75`: host file monitoring (Wazuh FIM), network IDS (Suricata), endpoint detection (mock EDR) — "**Operational purpose of monitoring as a category:** defense-in-depth. The SIEM correlates and alerts; monitoring layers keep independent eyes on files, wire, and endpoint behaviour so that a rule gap in one layer is caught by another."
- `cybersecurity_basics_1/Incident_Response_Plan.md:46–53`: "**Secondary detection methods (defense in depth):**" host-based FIM plus behavioural/anomaly process and network telemetry; confirmation by two independent sensors reduces false positives.
- `incident_response_1/Post-Incident Procedures.md:613`: "The defense-in-depth approach with correlation is valuable…"
- PDF evidence (page references from dedicated reports): `network_security_1/Firewall, IDS, and IPS Implementation Report.pdf` p.4 — "The implementation demonstrates a **defense-in-depth security model** using three complementary controls"; `network_security_1/Wireless Network Security Implementation Report.pdf` p.3 — "### 5. WPA2 + WIPS Defense-in-Depth" with "WPA2 protects the legitimate network, while WIPS protects the wireless environment surrounding the network."

**Concrete layers implemented:**

| Layer | Control and evidence |
|---|---|
| **Network / perimeter** | `ai-agentic-soc/Firewall_IDS_IPS_Implementation_Report.md:21–40` — `ufw allow from 10.11.0.0/22 to any port 1514/1515/55000`, `ufw deny 1514,1515,55000/tcp`; default-deny at edge (`Network_Topology_Implementation_Report.md:122`) |
| **Detection (IDS)** | Same report §3 (44–72) — Wazuh SSHD decoder and correlation rule `100010` (level 10, `frequency 6`, `timeframe 120`, MITRE `T1110`) for 6 failed logins in 2 minutes |
| **Prevention (IPS)** | Same report §4 (76–98) — Active Response `firewall-drop` for 600 s on rule match; **but see caveat below** |
| **Host integrity** | Wazuh FIM/syscheck (Comprehensive Policy Rule 3, lines 49–59); `Threat_Detection_Principles.md:327–345` (FIM rules `550`, `510`, Windows `61104`/`60110`/`60132`, vulnerability `23504`) |
| **Endpoint behaviour** | Process/network/file telemetry via mock EDR pillar and Wazuh (`SOC_Operations.md:68–75`); `network_security_1/Monitor_and_Respond_Network_Security_Events.md:80–88` |
| **Wireless** | WPA2 + WIPS layered defense (Wireless PDF, p.3) |
| **Analytic / response** | SIEM correlation and human-approved containment (`Monitor_and_Respond…:209–217`; `Incident Response and Containment.md:440–449`) |

The layered topology report (`Network_Topology_Implementation_Report.md:121–130`) explains how the design mitigates lateral exposure, eavesdropping and segmentation risk, and makes containment addressable from a single hub.

**Caveats to state.** The repository contains time-dependent contradictions:
- Custom rule `100010` is **documented, not deployed** — `security_operations_center_1/Threat_Detection_Principles.md:35–44` states "Custom rule `100010` is not deployed" and the live `local_rules.xml` held only example rule `100001`; the real brute-force chain is stock `5716 → 5760 → 5763`, `5503 → 5551`, `40111`, `40112`.
- Wazuh **Active Response is disabled** in the live lab (`Threat_Detection_Principles.md:45–49`; `incident_response_1/Incident Response and Containment.md:490`), so the IPS layer is documented/desired, not live.
- Suricata evidence is genuine signature detection but **offline pcap replay**, not live Wazuh integration (`Monitoring Implementation.md:345–347`); newer alert documents (`AI_Alerts_Documents/SOC-20261109-015.md:10–26`) show Suricata-style detections, so treat status as time-dependent.
- `ai-agentic-soc/Firewall_IDS_IPS_Implementation_Report.md` is strong technical writing but its Active Response/example event should be presented as documented configuration; the incontrovertible live firewall/containment evidence is in `incident_response_1/Incident Response and Containment.md:583–604` (L1–L3b drill).

## 3. Supply-chain risk — identified and mitigated (partial)

No formal software supply-chain assurance program (SBOM, signed artifacts, provenance, digest-pinned images, locked dependencies) exists. What does exist is source-integrity **awareness** and hygiene:

- **Third-party image source concern and remediation.** `cyber_threats_and_vulnerabilities_1/CVE_analysis.md:12–16`: a persistent `JS/ShellCode.gen` detection was traced to `C:\Users\Kai\Desktop\kali-linux-2026.2-installer-amd64.iso` — "An iso image of kali-linux for a virtual machine, downloaded over 3 month ago"; the host was isolated from Wi-Fi, the ISO manually removed after reboot, and a final clean scan run. The conclusion records: "the user was unsure if the downloaded iso was from a legitamate source or not which raised concern." This is a genuine third-party artifact risk identified and mitigated (quarantine + removal + verification scan), though without hash verification.
- **Vulnerable third-party component exposure.** `cyber_threats_and_vulnerabilities_1/Vulnerability_Assessment_Report.md:91–112`: the Wazuh/OpenSearch stack's service fingerprint disclosure and port 9200 exposure are treated as risks; recommendation line 112: "Recommend restricting 9200 to only the Wazuh server itself via firewall/security group rules, and confirming the underlying OpenSearch version is patched." The Windows endpoint's seven GIMP CVEs are likewise tracked and scored (`incident_response_1/Incident Detection and Analysis.md:329–347`). This identifies third-party-component risk and applies treatment.
- **Secret / source hygiene.** `.gitignore:1–17` — "Secrets & credentials — NEVER commit these" (`.env`, `.env.*`, `*.pem`, `*.p12`, `credentials.json`, `service-account*.json`); `python_1/Security_Evidence_gitignore_and_FastAPI.md:21–40` explains the policy. `cybersecurity_basics_1/Comprehensive_Security_Policy.md:49–59` (Rule 3) requires OS and installed software to be patched within a defined window — "patch discipline closes the known-vector root causes."
- **Hash-based artifact identification.** `cyber_threats_and_vulnerabilities_1/Threat_Intelligence_Implementation.md:23–31` documents a SHA-256 malicious-file hash IoC with FIM/EDR blocklist detection — detection use, not build-time verification.

**Why this is not full supply-chain security.** Dependencies are minimum-version ranges, not pinned (`ai-agentic-soc/requirements.txt:1–16`: `fastapi>=0.128`, `langgraph>=0.6`, `streamlit>=1.50`, etc.; `StreamSOC/requirements.txt:1–4`). Container connectors use mutable `latest` tags (`Threat_Intelligence_Implementation.md:88–92`, `:105–108`). No SBOM, SLSA provenance, signed commits/artifacts, dependency scanning in CI, or vendor-risk register was found. Defensible wording: **identified and mitigated a concrete third-party artifact risk (unverified Kali ISO) plus vulnerable-component exposure, and applied patching/secret hygiene; did not implement formal supply-chain assurance.**

## 4. Advanced security model applied (partial)

**Named model present: Discretionary Access Control (DAC).**
`network_security_1/Access Control Implementation Report.pdf` p.1 states "3. Access Control Model – Discretionary Access Control DAC" and "Model Selected: DAC … The project uses a Discretionary Access Control (DAC) approach for controlling access to system resources." Page 2 gives the implementation: `sudo chown socadmin:socanalysts /opt/soc/reports` and `sudo chmod 750 /opt/soc/reports`, with a permission matrix — `socadmin`: read/write/execute; `socanalysts`: read/execute; "Other users | No access" — and the statement "The DAC model prevents unauthorized users from accessing investigation reports and other SOC resources."

**Role separation reinforces the model.** Same PDF p.2 defines the SOC Analyst role: alerts/investigation data/reports/reasoning logs = READ, containment = APPROVE, containment execute = DENIED, "reflecting the project's human-in-the-loop design." Page 3: "Investigation → Recommendation → Human Approval → Action"; page 4: "The access-control implementation provides multiple layers of protection … The ACL restricts network-level access, DAC controls access to system resources, and the SOC Analyst access level establishes appropriate permissions."

**Why this is partial.** DAC with ACLs is a traditional access-control model, not an advanced/formal one. Searches found no Bell-LaPadula, Biba, Clark-Wilson, Brewer-Nash/Chinese Wall, MAC lattice model, state-machine model, or formal advanced-security-model implementation in the corpus. RBAC exists only as a proposed control — `docs/ai-agentic-soc-case-study.md:277–283` ("Add authentication and role-based access before exposing the API or dashboard beyond loopback") and `security_operations_center_1/Incident_Response_Methodology.md:327` ("Named analyst accounts with role-based access (triage, responder, admin, read-only)"). Defensible wording: **implemented and explained DAC with ACLs and analyst role separation; no named advanced/formal model (e.g., Bell-LaPadula, Biba, Clark-Wilson) was found.**

## 5. Conclusion

Defense in Depth is fully met with explicit layered design and concrete controls. Zero Trust, supply-chain security and an advanced security model are each **partial**: the project implements strong adjacent mechanisms (least privilege, default-deny, segmentation, human approval; ISO-removal remediation and patch hygiene; DAC/ACLs and role separation) but does not deploy a named ZTA, formal supply-chain assurance, or an advanced formal model. The responsible presentation is to claim the implemented controls precisely and label the aspirational or documented-only pieces as such — especially custom rule `100010` and Active Response, which later live verification contradicted.

### Related rubric write-ups

- `implement incident response and handling.md`
- `demonstrate soc fundamentals.md`
- `develop and implement security policies and governance.md`
- `produce effective security documentation.md`
