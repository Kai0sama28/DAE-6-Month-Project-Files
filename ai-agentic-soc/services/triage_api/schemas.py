"""Request and response models for the triage control plane."""

from __future__ import annotations

from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    version: str
    reports_dir: str
    worker_alive: bool
    queued_jobs: int
    running_jobs: int


class InvestigationRequest(BaseModel):
    alert_id: str = Field(..., min_length=1, max_length=256)
    force: bool = False


class JobView(BaseModel):
    job_id: str
    alert_id: str
    status: Literal["queued", "running", "succeeded", "failed"]
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class DecisionRequest(BaseModel):
    decision: Literal["approved", "rejected"]
    analyst: str = Field(default="analyst", max_length=200)
    note: str = Field(default="", max_length=4000)


class DecisionRecord(BaseModel):
    incident_id: str
    decision: Literal["approved", "rejected"]
    analyst: str
    note: str
    decided_at: str


class CaseSummary(BaseModel):
    incident_id: str
    title: str
    severity: Optional[str] = None
    confidence: Optional[str] = None
    affected_host: Optional[str] = None
    source_address: Optional[str] = None
    target_account: Optional[str] = None
    detection_rule: Optional[str] = None
    generated_at: Optional[str] = None
    report_path: str
    report_html_path: Optional[str] = None
    summary: Optional[str] = None
    decision: Optional[DecisionRecord] = None


class CaseDetail(CaseSummary):
    report_status: Optional[str] = None
    model: Optional[str] = None
    correlated_events: Optional[str] = None
    attack_duration: Optional[str] = None
    markdown: str


class MetricsResponse(BaseModel):
    generated_at: str
    total_cases: int
    by_severity: Dict[str, int]
    by_decision: Dict[str, int]
    jobs: Dict[str, int]
