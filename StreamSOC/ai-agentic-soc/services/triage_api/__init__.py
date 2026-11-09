"""FastAPI control plane for the AI-Agentic SOC triage engine.

The API is intentionally a thin layer over :func:`agent.runner.investigate_now`.
HTTP requests queue work, a single background worker runs the existing
LangGraph investigation, and the Streamlit dashboard polls for the result.
"""

__version__ = "0.1.0"
