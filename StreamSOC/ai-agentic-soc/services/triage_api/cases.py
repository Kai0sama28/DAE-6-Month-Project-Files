"""Read-only view over the Markdown and HTML incident reports.

The reports are the source of truth. This module parses the stable metadata
tables the report renderer already produces, so the API and dashboard never
need a second database of incidents.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from services.triage_api.decisions import DecisionStore
from services.triage_api.schemas import CaseDetail, CaseSummary

CASE_ID_RE = re.compile(r"^SOC-\d{8}-\d{3}$")
CASE_FILE_RE = re.compile(r"^(SOC-\d{8}-\d{3})\.md$")


class CaseNotFound(LookupError):
    pass


def _clean(value: str) -> str:
    value = value.strip()
    if value.startswith("**") and value.endswith("**"):
        value = value[2:-2]
    return value.replace("`", "").strip()


def _quote_value(markdown: str, label: str) -> Optional[str]:
    pattern = r"^>\s*\*\*" + re.escape(label) + r"\*\*\s*(.+?)\s*$"
    match = re.search(pattern, markdown, re.MULTILINE)
    return _clean(match.group(1)) if match else None


def _table_value(markdown: str, label: str) -> Optional[str]:
    pattern = r"^\|\s*" + re.escape(label) + r"\s*\|\s*(.+?)\s*\|\s*$"
    match = re.search(pattern, markdown, re.MULTILINE)
    return _clean(match.group(1)) if match else None


def _table_prefix_value(markdown: str, label: str) -> Optional[str]:
    pattern = r"^\|\s*\*\*" + re.escape(label) + r"\*\*[^|]*\|\s*(.+?)\s*\|\s*$"
    match = re.search(pattern, markdown, re.MULTILINE)
    return _clean(match.group(1)) if match else None


def _heading(markdown: str) -> Optional[str]:
    match = re.search(r"^#\s+(.+?)\s*$", markdown, re.MULTILINE)
    return _clean(match.group(1)) if match else None


def _executive_summary(markdown: str) -> Optional[str]:
    match = re.search(
        r"^##\s+1\.\s+Executive Summary\s*$\n(.*?)(?=^\|\s*Field\s*\||^##\s)",
        markdown,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        return None
    summary = match.group(1).strip()
    return summary or None


class CaseRepository:
    def __init__(self, reports_dir: Path, decisions: Optional[DecisionStore] = None) -> None:
        self.reports_dir = Path(reports_dir)
        self.decisions = decisions

    def _summary_from(self, detail: CaseDetail) -> CaseSummary:
        return CaseSummary(
            incident_id=detail.incident_id,
            title=detail.title,
            severity=detail.severity,
            confidence=detail.confidence,
            affected_host=detail.affected_host,
            source_address=detail.source_address,
            target_account=detail.target_account,
            detection_rule=detail.detection_rule,
            generated_at=detail.generated_at,
            report_path=detail.report_path,
            report_html_path=detail.report_html_path,
            summary=detail.summary,
            decision=detail.decision,
        )

    def _parse(self, path: Path, markdown: str) -> CaseDetail:
        incident_id = path.stem
        html_path = path.with_suffix(".html")
        decision = self.decisions.get(incident_id) if self.decisions else None
        return CaseDetail(
            incident_id=incident_id,
            title=_heading(markdown) or "Incident Report " + incident_id,
            severity=_table_value(markdown, "Severity"),
            confidence=_table_value(markdown, "Analyst confidence"),
            affected_host=_table_value(markdown, "Affected host"),
            source_address=_table_value(markdown, "Source address"),
            target_account=_table_value(markdown, "Target account"),
            detection_rule=_table_value(markdown, "Detection rule"),
            generated_at=_quote_value(markdown, "Generated at (UTC):"),
            report_path=str(path),
            report_html_path=str(html_path) if html_path.exists() else None,
            summary=_executive_summary(markdown),
            decision=decision,
            report_status=_quote_value(markdown, "Report status:"),
            model=_quote_value(markdown, "Reasoning model:"),
            correlated_events=_table_value(markdown, "Correlated events"),
            attack_duration=_table_prefix_value(markdown, "Attack duration"),
            markdown=markdown,
        )

    def list_cases(self) -> List[CaseSummary]:
        if not self.reports_dir.exists():
            return []
        cases: List[CaseSummary] = []
        for path in self.reports_dir.glob("SOC-*.md"):
            if not CASE_FILE_RE.match(path.name):
                continue
            try:
                markdown = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            cases.append(self._summary_from(self._parse(path, markdown)))
        cases.sort(key=lambda item: (item.generated_at or "", item.incident_id), reverse=True)
        return cases

    def get_case(self, incident_id: str) -> CaseDetail:
        if not CASE_ID_RE.match(incident_id):
            raise CaseNotFound(incident_id)
        path = self.reports_dir / (incident_id + ".md")
        if not path.is_file():
            raise CaseNotFound(incident_id)
        try:
            markdown = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise CaseNotFound(incident_id) from exc
        return self._parse(path, markdown)
