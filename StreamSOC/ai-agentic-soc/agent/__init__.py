"""AI-Agentic SOC Triage & Investigation Engine — background agent package.

Modules:
    config       environment-driven runtime configuration
    llm          OpenRouter client (nvidia/nemotron-3.5-lightning:free)
    events       canonical event shape shared by the whole pipeline
    correlation  deterministic log correlation
    report       Markdown incident report rendering
    notifier     macOS desktop notification
    state        persisted watcher state
    graph        LangGraph workflow
    runner       CLI entry point
"""

from __future__ import annotations

__all__ = [
    "config",
    "correlation",
    "events",
    "graph",
    "llm",
    "notifier",
    "report",
    "runner",
    "state",
]
