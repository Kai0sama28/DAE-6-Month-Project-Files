To stand out to **Big Tech** employers in 2026, cybersecurity portfolios must move beyond static certifications and showcase the ability to build, automate, and secure complex, scalable systems. Drawing from the latest industry roadmaps and emerging technological trends, here are five innovative projects that demonstrate high-level engineering and adversarial thinking:

### **1. AI-Agentic Triage and Investigation Engine**
Given the shift toward the **"Agentic SOC,"** employers value candidates who can supervise and build autonomous security workflows. This project involves creating a system that uses **Large Language Models (LLMs)** to independently execute investigative playbooks, such as pulling identity context, querying SIEM history, and checking EDR telemetry before a human analyst even opens a ticket. Your tool should correlate event logs across multiple platforms to construct a unified incident timeline and generate a **natural language summary** for human review.

### **2. "Secure by Design" Cloud Landing Zone with Policy-as-Code**
Cloud security is a critical skill for Big Tech, and moving beyond manual configuration is essential. Build a multi-cloud landing zone using **Infrastructure as Code (Terraform)** that implements **Zero Trust Architecture** and strict **Least Privilege** principles. Integrate automated **policy-as-code** checks (using tools like tfsec or Checkov) that scan the infrastructure before deployment to block risky configurations, such as public storage buckets or overprivileged service accounts.

### **3. IoT Security and Firmware Vulnerability Lab**
As the attack surface expands to billions of connected devices, **IoT security** specialists are in high demand. Set up a home lab to perform **APK decompilation** and firmware analysis on connected hardware to identify vulnerabilities like unencrypted communication protocols or hardcoded credentials. Documenting a full **hardening guide** for a specific hardware target demonstrates the hands-on "builder" mindset that distinguishes security engineers from entry-level analysts.

### **4. Automated Threat Intelligence and IoC Enrichment Pipeline**
Automation is a primary differentiator in 2026, as human teams are often overwhelmed by alert volume. Develop a Python-based pipeline that programmatically discover **Indicators of Compromise (IoCs)** from threat intelligence feeds and automatically enriches them with historical context from your own SIEM logs. Enhance the project by adding **predictive indicators**, using machine learning basics to identify patterns in threat actor behavior before a breach occurs.

### **5. High-Uptime Civic Reporting Platform with No-Auth Ingestion**
This project bridges the gap between **full-stack development** and security, showcasing your ability to build "public interest technology". Create a reporting platform (similar to **Viralkan**) that allows anonymous public participation while implementing **rate-limiting middleware** and strict **Zod schema validation** to prevent denial-of-service (DoS) and SQL injection attacks. Use **PostGIS** for geographic data storage and a serverless architecture to ensure the system remains performant and low-cost under load.

### **Portfolio Presentation Strategy**
Big Tech recruiters look for the **XYZ format** to quantify impact: explain how you "Accomplished **X** through **Y**, resulting in **Z** impact" (e.g., "Automated a manual 4-hour investigation process to take 5 minutes"). Ensure every project includes a **polished README** that explains one critical architecture decision and links to a **live endpoint** or a demo video.

Building an **AI-Agentic Triage and Investigation Engine** is a high-impact project that aligns perfectly with the "Agentic SOC" trend, where autonomous AI agents transition from simple automation (fixed decision trees) to active decision partners.

Given your **emergency response background**, you are uniquely positioned to build a tool that codifies "judgment under pressure" into autonomous investigative playbooks.

### **1. Core Concept: The "Agentic SOC" Analyst**
Traditional SOC automation (SOAR) follows rigid "if-this-then-that" rules. Your engine will instead use **Large Language Models (LLMs)** to independently determine which investigative steps are necessary based on the specific alert received.

*   **Autonomous Querying:** The system should pull identity context (e.g., from Okta or Azure AD), query SIEM history (e.g., Splunk), and check EDR telemetry (e.g., CrowdStrike) before a human ever opens the ticket.
*   **Dynamic Assessment:** The AI must correlate these disjointed logs across multiple platforms to construct a unified incident timeline.
*   **Natural Language Synthesis:** It generates a summary explaining the "why" behind the risk, translating technical telemetry into business impact.

### **2. Technical Implementation Roadmap**
To build this, you will need to bridge **Backend Engineering** with **AI Security**.

*   **Language & Logic:** **Python** is the standard for these automation and machine learning workflows. You will likely use frameworks like **LangChain** or **RAG (Retrieval-Augmented Generation)** to give the LLM access to your specific security logs.
*   **API Integration:** Your engine must interface with security tool APIs:
    *   **Identity:** Pull user roles and login locations.
    *   **SIEM:** Query historical event logs for patterns of **lateral movement** or credential stuffing.
    *   **EDR:** Fetch process dumps or network connection data from the affected endpoint.
*   **Prompt Engineering:** You must design effective prompts that instruct the LLM on how to act as a **Tier 1 Triage Analyst**, separating "noise" from genuine attacks.

### **3. Strategic Project Workflow**
Your engine should follow a structured incident handling flow similar to **NIST 800-61r2**:

1.  **Alert Reception:** Ingest a JSON payload from a simulated SIEM alert.
2.  **Context Gathering:** The Agent "decides" to query the identity provider to see if the user’s login was from an unusual location (e.g., New York vs. Moscow).
3.  **Threat Correlation:** The Agent checks EDR logs to see if that user recently downloaded an unusual file (e.g., an infostealer).
4.  **Timeline Construction:** It maps these events to the **MITRE ATT&CK framework**, identifying tactics like **Initial Access** or **Persistence**.
5.  **Human Handoff:** The Agent compiles its reasoning chain into a summary, highlighting any "**toxic combinations**" of risk (e.g., public resource + overprivileged identity + sensitive data).

### **4. Advanced Features for "Big Tech" Appeal**
To stand out, your project must address the systemic challenges of AI in security:

*   **Model Explainability:** Provide a "reasoning chain" so human analysts can audit why the AI arrived at its conclusions.
*   **Human-in-the-Loop Guardrails:** Implement "Active Mitigation" where the AI proposes a containment action (like isolating a host), but requires manual authorization for high-risk assets.
*   **Cost Optimization:** Use techniques to optimize token costs when querying LLMs for large volumes of logs.

### **5. Portfolio Presentation (The XYZ Impact)**
When presenting this, use the **XYZ format** to quantify the value of your emergency-response-turned-AI-engine:
> "Accomplished **automated triage of 90% of routine alerts** through **an LLM-based investigative engine**, resulting in **shrinking investigation timelines from hours to minutes** and reducing analyst burnout."

**Next Steps:** Start by building a simple Python script that takes a single "Suspicious Login" alert and uses the OpenAI or Anthropic API to query a mock CSV database of "User Identities." This proves the basic logic before you scale to full SIEM/EDR integrations.