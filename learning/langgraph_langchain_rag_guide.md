# LangGraph, LangChain & RAG for the AI-Agentic SOC Triage Engine

A reference for the `ai-agentic-soc` project: what each technology is, and how it maps onto the existing 5-stage triage pipeline (Ingestion → Enrichment → Classification → Dispatcher → Reporting).

---

## 1. Definitions

### LangChain
**LangChain** is an open-source framework for building applications around large language models (LLMs). It provides standard building blocks so you don't hand-roll them:

| Building block | What it does |
|---|---|
| **Models** | A common interface to LLMs (Claude, GPT, local models) and embedding models |
| **Prompts** | Reusable, parameterized prompt templates |
| **Tools** | Python functions an LLM can call, described by a name, a description and an argument schema |
| **Output parsers / structured output** | Force the LLM to return validated JSON or Pydantic objects |
| **Retrievers & vector stores** | Search interfaces over your own documents (the basis of RAG) |
| **Chains** | Fixed sequences of steps: prompt → model → parser |

**Best for:** linear, predictable LLM workflows and integrations.

### LangGraph
**LangGraph** is a library from the LangChain team for building **stateful, multi-step agent workflows as a graph**. It can be used alongside LangChain components or on its own.

- **State**: a shared object (your `TriageState` `TypedDict`) that every step reads and updates.
- **Nodes**: Python functions that take the state and return updates (your `ingestion_node`, `enrichment_node`, etc.).
- **Edges**: the connections between nodes. **Conditional edges** choose the next node at runtime based on state.
- **Checkpointing / persistence**: saves state between steps so a run can pause and resume.
- **Human-in-the-loop**: a graph can pause (`interrupt`) to wait for a person's approval, then continue.
- **Loops and branches**: unlike a simple chain, a graph can retry, branch and cycle.

**Best for:** agentic systems that need branching decisions, shared state, approvals and auditability. Your triage engine is already a LangGraph application.

### Retrieval-Augmented Generation (RAG)
**RAG** is a pattern that improves LLM answers by **retrieving relevant information from an external knowledge source and putting it into the prompt** before the model responds.

1. **Index (offline):** split documents into chunks, convert each to a vector with an embedding model, and store them in a vector database.
2. **Retrieve (at query time):** embed the question or alert, then fetch the top-*k* most similar chunks.
3. **Augment:** insert those chunks into the prompt as context.
4. **Generate:** the LLM answers using that context, ideally citing it.

**Why it matters:** the model doesn't need to have memorized your runbooks, past tickets or environment. It reads them at the moment it needs them, and the knowledge base can be updated without retraining anything. It also reduces hallucination because answers are grounded in retrieved text.

### How they fit together

| Layer | Technology | Role in the triage engine |
|---|---|---|
| Orchestration | **LangGraph** | Controls the flow, state, branching and approvals |
| Components | **LangChain** | LLM calls, tools, retrievers, structured output |
| Knowledge | **RAG** | Supplies runbooks, history and threat knowledge to the LLM |

---

## 2. Where the current project stands

The existing `triage_chain.py` is a **deterministic** LangGraph pipeline: scoring, routing and tool calls are plain Python rules, and the tool handlers are mocks. There is **no LLM and no retrieval yet**. That is a solid foundation, because the graph, state and Pydantic tool schemas are exactly what an LLM-driven version needs. The sections below show where each technology plugs in.

---

## 3. How to use each technology in the triage engine

### 3.1 LangGraph: already in use, extend it

**Conditional routing.** After classification, route to ISOLATE / MONITOR / ESCALATE / FALSE_POSITIVE branches:

```python
builder.add_conditional_edges(
    "classification",
    route_decision,  # returns "ISOLATE", "MONITOR", ...
    {"ISOLATE": "isolate", "MONITOR": "monitor",
     "ESCALATE": "escalate", "FALSE_POSITIVE": "false_positive"},
)
```

**Human approval before containment.** Pause the graph until an analyst approves isolation:

```python
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import interrupt, Command

def approval_node(state: TriageState):
    approved = interrupt({
        "question": "Approve network isolation?",
        "host": state["hostname"],
        "risk_score": state["risk_score"],
    })
    return {"analyst_approved": approved}

graph = builder.compile(checkpointer=MemorySaver())
config = {"configurable": {"thread_id": state["alert_id"]}}
graph.invoke(initial_state, config)            # runs until the interrupt
graph.invoke(Command(resume=True), config)    # analyst approves, run continues
```

**Other uses:** retry loops when a tool fails, parallel enrichment branches, persistent state so incidents survive restarts, and a full audit trail of every step.

### 3.2 LangChain: add the LLM and expose your tools

**Structured classification.** Replace the fixed `ISOLATE` / `85.0` logic with an LLM that returns a validated verdict:

```python
from pydantic import BaseModel
from typing import Literal

class TriageVerdict(BaseModel):
    decision: Literal["ISOLATE", "MONITOR", "FALSE_POSITIVE", "ESCALATE"]
    risk_score: float
    reasoning: str

llm = ...  # any LangChain chat model
classifier = llm.with_structured_output(TriageVerdict)
verdict = classifier.invoke(prompt_with_alert_and_context)
```

Keep guardrails in code: the LLM *recommends*, deterministic rules and the approval gate *authorize* destructive actions.

**Tools from your existing Pydantic schemas.** Your `*Input` models already define argument schemas, so they can be reused as tool schemas. Because your handlers take a single `params` object, wrap them:

```python
from langchain_core.tools import StructuredTool

def _query_logs(**kwargs):
    return query_related_logs(QueryRelatedLogsInput(**kwargs))

query_logs_tool = StructuredTool.from_function(
    func=_query_logs,
    name="query_related_logs",
    description="Search SIEM logs by source IP, user or agent over a time window.",
    args_schema=QueryRelatedLogsInput,
)
```

Give the LLM **read-only tools** (`query_related_logs`, `enrich_indicators`, `inspect_process_tree`, `check_false_positive_history`) to investigate freely. Keep **response tools** (`isolate_host_network`, `terminate_process`, `quarantine_file`, `disable_user_account`) behind the dispatcher and approval gate.

**Report writing.** Use a prompt template plus the LLM in `reporting_node` to turn the timeline, MITRE mapping and actions into an analyst-readable summary.

### 3.3 RAG: ground decisions in your own knowledge

RAG is most useful where the model needs knowledge that isn't in its training data.

| Knowledge source to index | What it improves |
|---|---|
| **Past incident tickets and resolutions** | Replaces the stub `check_false_positive_history` with semantic search: "have we seen this pattern on this host before, and how was it resolved?" |
| **Runbooks / playbooks** | The LLM follows your team's response steps instead of generic advice |
| **MITRE ATT&CK techniques** | Accurate tactic/technique mapping from alert text, replacing the hardcoded list |
| **Wazuh rule descriptions and decoder docs** | Explains what a rule actually detects and how noisy it is |
| **Asset inventory / criticality notes** | Distinguishes a lab VM from a production server when weighing isolation |
| **Threat intel reports** | Context on actors, malware families and IOCs |

**Example: a retrieval step in the graph.**

```python
from langchain_community.vectorstores import Chroma

vectorstore = Chroma(collection_name="soc_knowledge", embedding_function=embeddings)
retriever = vectorstore.as_retriever(search_kwargs={"k": 4})

def retrieval_node(state: TriageState):
    query = f"{state['rule_name']} on {state['hostname']}"
    docs = retriever.invoke(query)
    context = [
        {"source": d.metadata.get("source"), "text": d.page_content}
        for d in docs
    ]
    return {"enriched_context": {**state["enriched_context"], "knowledge": context}}
```

Add `retrieval` between `enrichment` and `classification`, then include the retrieved passages in the classifier prompt and require the LLM to cite which source supported its decision.

**Indexing (run offline or on a schedule):**

```python
from langchain_text_splitters import RecursiveCharacterTextSplitter

splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=100)
chunks = splitter.split_documents(loaded_runbooks_and_tickets)
vectorstore.add_documents(chunks)
```

**Tips:** store metadata (source, date, host, rule ID) so you can filter results; re-index closed tickets automatically so the system learns from analyst decisions; and treat retrieved text as untrusted input, since a poisoned log line or document could contain instructions aimed at the LLM.

---

## 4. Target architecture

```
Alert (Wazuh / OpenSearch)
        │
        ▼
 Ingestion ──► Enrichment (SIEM tools, parallel) ──► Retrieval (RAG)
                                                         │
                                                         ▼
                                           Classification (LLM + rules)
                                                         │
                        ┌──────────────┬─────────────────┼───────────────┐
                        ▼              ▼                 ▼               ▼
                    ISOLATE         MONITOR          ESCALATE     FALSE_POSITIVE
                  (approval gate)       │                 │               │
                        │               │                 │               │
                        └───────────────┴────────┬────────┴───────────────┘
                                                 ▼
                                      Reporting (LLM summary + ticket update)
```

| Stage | Today | With LangChain + RAG |
|---|---|---|
| Ingestion | Rule-based field parsing | Same, optionally LLM-assisted for messy alerts |
| Enrichment | Mock SIEM calls | Real SIEM calls, plus RAG retrieval |
| Classification | Weighted score | LLM verdict with citations, checked by rules |
| Dispatcher | Fixed action sequence | Branches plus human approval |
| Reporting | f-string summary | LLM-written narrative from the timeline |

---

## 5. Safety considerations

- **Never let the LLM directly trigger destructive actions.** Isolation, process kills and account disables should require rule checks and human approval.
- **Validate everything with Pydantic.** Your tool schemas already enforce argument types, so keep using them for LLM-generated arguments.
- **Guard against prompt injection.** Alert fields, log lines and retrieved documents can contain attacker-controlled text. Never treat them as instructions.
- **Protect critical processes and hosts.** Keep the protected-process list and a "do not isolate" asset list in code, not only in prompts.
- **Log everything.** Store the prompt, retrieved sources, verdict and actions for each alert so decisions can be audited.
- **Measure quality.** Build a test set of past alerts with known outcomes and track false-positive and missed-detection rates before enabling automation.

---

## 6. Suggested roadmap

1. Replace mock tool handlers with real Wazuh / OpenSearch API calls.
2. Add the approval gate with `interrupt` and a checkpointer.
3. Stand up a vector store and index runbooks, MITRE ATT&CK and past tickets.
4. Add the `retrieval` node and feed results into classification.
5. Introduce an LLM classifier with structured output, in **shadow mode** (compare against the rule-based decision without acting).
6. Add an LLM-written report, then enable automated actions only for low-risk, well-tested paths.

---

## 7. Quick glossary

- **Embedding:** a numeric vector representing the meaning of a piece of text.
- **Vector store:** a database that finds the vectors most similar to a query (Chroma, FAISS, pgvector, OpenSearch k-NN).
- **Chunking:** splitting documents into smaller passages for indexing.
- **Top-*k*:** the number of most similar chunks retrieved.
- **Tool calling:** letting an LLM request that your code run a function with structured arguments.
- **Checkpointer:** LangGraph's mechanism for saving state between steps.
- **Shadow mode:** running a new decision system alongside the old one without acting on its output.
