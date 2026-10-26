"""HTTP control plane for incident triage.

Run it with::

    venv/bin/python -m services.triage_api

The server binds to loopback by default. Keep it that way unless you put an
authenticated reverse proxy in front of it.
"""

from __future__ import annotations

from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.responses import FileResponse, PlainTextResponse

from agent.config import PROJECT_ROOT, AgentConfig
from services.triage_api import __version__
from services.triage_api.cases import CaseNotFound, CaseRepository
from services.triage_api.decisions import DecisionStore
from services.triage_api.executor import investigate_alert
from services.triage_api.jobs import JobExecutor, JobManager
from services.triage_api.schemas import (
    CaseDetail,
    CaseSummary,
    DecisionRecord,
    DecisionRequest,
    HealthResponse,
    InvestigationRequest,
    JobView,
    MetricsResponse,
)

API_PREFIX = "/api/v1"
DEFAULT_DECISIONS_PATH = PROJECT_ROOT / "data" / "triage_decisions.json"


def _default_reports_dir() -> Path:
    return AgentConfig.from_env().reports_dir


def create_app(
    reports_dir: Optional[Path] = None,
    decisions_path: Optional[Path] = None,
    executor: Optional[JobExecutor] = None,
) -> FastAPI:
    resolved_reports = Path(reports_dir) if reports_dir else _default_reports_dir()
    decisions = DecisionStore(decisions_path or DEFAULT_DECISIONS_PATH)
    cases = CaseRepository(resolved_reports, decisions)
    jobs = JobManager(executor or investigate_alert)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        jobs.start()
        try:
            yield
        finally:
            jobs.stop()

    app = FastAPI(
        title="AI-Agentic SOC Triage API",
        version=__version__,
        description="Queues investigations on the existing LangGraph agent and exposes reports for analyst review.",
        lifespan=lifespan,
    )
    app.state.cases = cases
    app.state.jobs = jobs
    app.state.decisions = decisions

    @app.get("/", include_in_schema=False)
    def root() -> dict:
        return {"service": "triage-api", "version": __version__, "api": API_PREFIX, "docs": "/docs"}

    @app.get(API_PREFIX + "/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        counts = jobs.counts()
        return HealthResponse(
            status="ok" if jobs.alive else "degraded",
            version=__version__,
            reports_dir=str(cases.reports_dir),
            worker_alive=jobs.alive,
            queued_jobs=counts.get("queued", 0),
            running_jobs=counts.get("running", 0),
        )

    @app.post(
        API_PREFIX + "/investigations",
        response_model=JobView,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def start_investigation(payload: InvestigationRequest) -> JobView:
        alert_id = payload.alert_id.strip()
        if not alert_id:
            raise HTTPException(status_code=422, detail="alert_id must not be blank")
        return jobs.submit(alert_id, force=payload.force)

    @app.get(API_PREFIX + "/jobs", response_model=List[JobView])
    def list_jobs(limit: int = Query(50, ge=1, le=500)) -> List[JobView]:
        return jobs.list_recent(limit=limit)

    @app.get(API_PREFIX + "/jobs/{job_id}", response_model=JobView)
    def get_job(job_id: str) -> JobView:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        return job

    @app.get(API_PREFIX + "/cases", response_model=List[CaseSummary])
    def list_cases(
        limit: int = Query(100, ge=1, le=500),
        severity: Optional[str] = None,
    ) -> List[CaseSummary]:
        found = cases.list_cases()
        if severity:
            wanted = severity.strip().lower()
            found = [case for case in found if (case.severity or "").lower() == wanted]
        return found[:limit]

    @app.get(API_PREFIX + "/cases/{incident_id}", response_model=CaseDetail)
    def get_case(incident_id: str) -> CaseDetail:
        try:
            return cases.get_case(incident_id)
        except CaseNotFound:
            raise HTTPException(status_code=404, detail="case not found")

    @app.get(API_PREFIX + "/cases/{incident_id}/report")
    def get_case_report(
        incident_id: str,
        format: str = Query("markdown", pattern="^(markdown|html)$"),
    ):
        try:
            case = cases.get_case(incident_id)
        except CaseNotFound:
            raise HTTPException(status_code=404, detail="case not found")
        if format == "html":
            if not case.report_html_path or not Path(case.report_html_path).is_file():
                raise HTTPException(status_code=404, detail="HTML report not available")
            return FileResponse(case.report_html_path, media_type="text/html")
        return PlainTextResponse(case.markdown, media_type="text/markdown; charset=utf-8")

    @app.post(API_PREFIX + "/cases/{incident_id}/decision", response_model=DecisionRecord)
    def record_decision(incident_id: str, payload: DecisionRequest) -> DecisionRecord:
        try:
            cases.get_case(incident_id)
        except CaseNotFound:
            raise HTTPException(status_code=404, detail="case not found")
        analyst = payload.analyst.strip() or "analyst"
        return decisions.set(incident_id, payload.decision, analyst, payload.note.strip())

    @app.get(API_PREFIX + "/metrics", response_model=MetricsResponse)
    def get_metrics() -> MetricsResponse:
        found = cases.list_cases()
        severities = Counter(case.severity or "Unrated" for case in found)
        decisions_count = Counter(
            case.decision.decision if case.decision else "pending" for case in found
        )
        return MetricsResponse(
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_cases=len(found),
            by_severity=dict(severities),
            by_decision=dict(decisions_count),
            jobs=jobs.counts(),
        )

    return app


app = create_app()
