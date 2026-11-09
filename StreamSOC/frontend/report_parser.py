"""Parse the Markdown incident reports produced by the triage agent.

The reports are the source of truth for the dashboard. This module turns the
stable Markdown tables and bullets into plain dictionaries so the Streamlit
views can render timelines, MITRE coverage, evidence and decisions without a
second database.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

CASE_FILE_RE = re.compile(r"^(SOC-\d{8}-\d{3})\.md$")
SECTION_RE = re.compile(r"^##\s+(\d+)\.\s+(.+?)\s*$", re.MULTILINE)
QUOTE_META_RE = re.compile(r"^>\s*\*\*(.+?)\*\*\s*(.+?)\s*$", re.MULTILINE)
HEADING_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
    "unrated": 0,
}


def clean(value: Any) -> str:
    """Remove Markdown emphasis/code ticks from a table cell or bullet."""
    text = str(value if value is not None else "").strip()
    text = text.replace("\\|", "|")
    if text.startswith("**") and text.endswith("**") and len(text) > 4:
        text = text[2:-2].strip()
    text = text.replace("`", "")
    return text.strip()


def _is_separator(line: str) -> bool:
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    return bool(cells) and all(re.fullmatch(r":?-{2,}:?", cell or "") for cell in cells)


def _split_row(line: str) -> List[str]:
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|"):
        text = text[:-1]
    return [clean(cell) for cell in re.split(r"(?<!\\)\|", text)]


def split_sections(markdown: str) -> Dict[int, str]:
    matches = list(SECTION_RE.finditer(markdown))
    sections: Dict[int, str] = {}
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(markdown)
        sections[int(match.group(1))] = markdown[start:end].strip("\n")
    return sections


def parse_tables(text: str) -> List[Dict[str, Any]]:
    """Return every Markdown table in ``text`` as headers + row dictionaries."""
    lines = text.splitlines()
    tables: List[Dict[str, Any]] = []
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        if line.startswith("|") and line.endswith("|"):
            block: List[str] = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                block.append(lines[index].strip())
                index += 1
            if len(block) >= 2:
                headers = _split_row(block[0])
                rows: List[Dict[str, str]] = []
                for raw in block[1:]:
                    if _is_separator(raw):
                        continue
                    cells = _split_row(raw)
                    if len(cells) < len(headers):
                        cells += [""] * (len(headers) - len(cells))
                    rows.append(dict(zip(headers, cells[: len(headers)])))
                tables.append({"headers": headers, "rows": rows})
        else:
            index += 1
    return tables


def _normalise_headers(headers: Iterable[str]) -> List[str]:
    return [header.strip().lower() for header in headers]


def find_table(tables: Iterable[Dict[str, Any]], *wanted: str) -> Optional[Dict[str, Any]]:
    needed = [item.lower() for item in wanted]
    for table in tables:
        headers = _normalise_headers(table["headers"])
        if all(any(item in header for header in headers) for item in needed):
            return table
    return None


def table_rows(tables: Iterable[Dict[str, Any]], *wanted: str) -> List[Dict[str, str]]:
    table = find_table(tables, *wanted)
    return list(table["rows"]) if table else []


def kv_table(tables: Iterable[Dict[str, Any]], *wanted: str) -> Dict[str, str]:
    table = find_table(tables, *wanted)
    if not table:
        return {}
    result: Dict[str, str] = {}
    for row in table["rows"]:
        keys = list(row.keys())
        if len(keys) >= 2:
            result[clean(row[keys[0]])] = clean(row[keys[1]])
    return result


def bullets(text: str) -> List[str]:
    found: List[str] = []
    for line in text.splitlines():
        match = re.match(r"^\s*[-*]\s+(.+?)\s*$", line)
        if match:
            found.append(clean(match.group(1)))
    return found


def parse_quote_meta(markdown: str) -> Dict[str, str]:
    meta: Dict[str, str] = {}
    for match in QUOTE_META_RE.finditer(markdown):
        key = clean(match.group(1)).rstrip(":")
        meta[key] = clean(match.group(2))
    return meta


def _first_paragraph(text: str) -> str:
    head = re.split(r"\n\s*\|", text, maxsplit=1)[0]
    return head.strip()


def _severity_rank(severity: Optional[str]) -> int:
    return SEVERITY_RANK.get((severity or "unrated").strip().lower(), 0)


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def parse_report(path: Path, decision: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    markdown = path.read_text(encoding="utf-8", errors="replace")
    return parse_markdown(markdown, path.stem, path, decision)


def parse_markdown(
    markdown: str,
    incident_id_hint: str = "",
    path: Optional[Path] = None,
    decision: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    sections = split_sections(markdown)
    meta = parse_quote_meta(markdown)
    heading = HEADING_RE.search(markdown)

    sec1 = sections.get(1, "")
    sec1_tables = parse_tables(sec1)
    fields = kv_table(sec1_tables, "field", "value")

    rationale_match = re.search(
        r"\*\*Severity rationale:\*\*\s*(.+?)(?=\n\s*\n|\Z)", sec1, re.DOTALL
    )
    severity_rationale = clean(rationale_match.group(1)) if rationale_match else ""

    sec2_tables = parse_tables(sections.get(2, ""))
    detection_facts = kv_table(sec2_tables, "fact", "value")

    sec4 = sections.get(4, "")
    sec4_tables = parse_tables(sec4)
    relation_table = find_table(sec4_tables, "relation", "events")
    relations = {
        clean(row.get("Relation", "")): clean(row.get("Events", ""))
        for row in (relation_table["rows"] if relation_table else [])
    }
    phase_rows = table_rows(sec4_tables, "phase", "events")
    rule_rows = table_rows(sec4_tables, "rule", "level", "description", "events")
    flags = kv_table(sec4_tables, "flag", "value")

    timeline = table_rows(parse_tables(sections.get(5, "")), "timestamp", "phase")
    mitre = table_rows(parse_tables(sections.get(7, "")), "technique", "tactic")
    risk = bullets(sections.get(8, ""))
    recommendations = table_rows(parse_tables(sections.get(9, "")), "priority", "action")
    containment = bullets(sections.get(9, ""))
    evidence_gaps = bullets(sections.get(10, ""))
    metrics = kv_table(parse_tables(sections.get(11, "")), "metric", "value")
    provenance = bullets(sections.get(12, ""))

    incident_id = clean(fields.get("Incident ID") or incident_id_hint)
    severity = clean(fields.get("Severity") or "")
    confidence = clean(fields.get("Analyst confidence") or "")
    affected_host = clean(fields.get("Affected host") or "")
    source_address = clean(fields.get("Source address") or "")
    target_account = clean(fields.get("Target account") or "")
    detection_rule = clean(fields.get("Detection rule") or "")
    correlated_events = clean(fields.get("Correlated events") or "")
    attack_duration = clean(fields.get("Attack duration (trigger burst)") or "")
    attack_burst = clean(fields.get("Attack burst") or "")
    observation_window = clean(fields.get("Observation window") or "")

    mitre_techniques = []
    tactics = Counter()
    for row in mitre:
        technique = clean(row.get("Technique", ""))
        tactic = clean(row.get("Tactic", ""))
        if technique:
            mitre_techniques.append(technique)
        if tactic:
            tactics[tactic] += 1

    phase_counts = Counter()
    attack_events = 0
    context_events = 0
    max_level = 0
    for row in timeline:
        phase = clean(row.get("Phase", "")) or "OTHER"
        phase_counts[phase] += 1
        burst = clean(row.get("Burst", "")).lower()
        if burst == "attack":
            attack_events += 1
        elif burst == "context":
            context_events += 1
        max_level = max(max_level, _to_int(row.get("Lvl"), 0))

    generated_at = clean(meta.get("Generated at (UTC)") or "")
    html_path = path.with_suffix(".html") if path is not None else None

    return {
        "incident_id": incident_id,
        "title": clean(heading.group(1)) if heading else "Incident Report " + incident_id,
        "severity": severity,
        "severity_rank": _severity_rank(severity),
        "confidence": confidence,
        "affected_host": affected_host,
        "source_address": source_address,
        "target_account": target_account,
        "detection_rule": detection_rule,
        "correlated_events": correlated_events,
        "correlated_events_int": _to_int(correlated_events, len(timeline)),
        "attack_duration": attack_duration,
        "attack_burst": attack_burst,
        "observation_window": observation_window,
        "generated_at": generated_at,
        "report_status": clean(meta.get("Report status") or ""),
        "model": clean(meta.get("Reasoning model") or ""),
        "summary": _first_paragraph(sec1),
        "severity_rationale": severity_rationale,
        "detection_facts": detection_facts,
        "relations": relations,
        "phase_rows": phase_rows,
        "phase_counts": dict(phase_counts),
        "rule_rows": rule_rows,
        "flags": flags,
        "timeline": timeline,
        "timeline_count": len(timeline),
        "attack_events": attack_events,
        "context_events": context_events,
        "max_level": max_level,
        "mitre": mitre,
        "mitre_techniques": mitre_techniques,
        "mitre_tactics": dict(tactics),
        "risk": risk,
        "recommendations": recommendations,
        "containment": containment,
        "evidence_gaps": evidence_gaps,
        "metrics": metrics,
        "provenance": provenance,
        "key_findings": bullets(sections.get(3, "")),
        "report_path": str(path) if path is not None else None,
        "report_html_path": str(html_path) if html_path and html_path.exists() else None,
        "markdown": markdown,
        "decision": decision,
    }


def case_summary(report: Dict[str, Any]) -> Dict[str, Any]:
    keys = (
        "incident_id",
        "title",
        "severity",
        "severity_rank",
        "confidence",
        "affected_host",
        "source_address",
        "target_account",
        "detection_rule",
        "correlated_events",
        "correlated_events_int",
        "attack_duration",
        "generated_at",
        "report_path",
        "report_html_path",
        "summary",
        "decision",
        "timeline_count",
        "max_level",
    )
    return {key: report.get(key) for key in keys}


def case_sort_key(report: Dict[str, Any]) -> tuple:
    generated = report.get("generated_at") or ""
    try:
        parsed = datetime.fromisoformat(generated.replace("Z", "+00:00"))
        stamp = parsed.timestamp()
    except (ValueError, AttributeError):
        stamp = 0.0
    return (stamp, report.get("incident_id") or "")


def load_cases(
    reports_dir: Path,
    decisions: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    directory = Path(reports_dir)
    if not directory.exists():
        return []
    decisions = decisions or {}
    cases: List[Dict[str, Any]] = []
    for path in directory.glob("SOC-*.md"):
        if not CASE_FILE_RE.match(path.name):
            continue
        try:
            report = parse_report(path, decision=decisions.get(path.stem))
        except OSError:
            continue
        cases.append(report)
    cases.sort(key=case_sort_key, reverse=True)
    return cases


def load_case(
    reports_dir: Path,
    incident_id: str,
    decisions: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    if not re.match(r"^SOC-\d{8}-\d{3}$", incident_id or ""):
        return None
    path = Path(reports_dir) / (incident_id + ".md")
    if not path.is_file():
        return None
    decisions = decisions or {}
    return parse_report(path, decision=decisions.get(incident_id))


def aggregate(cases: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    cases = list(cases)
    severities = Counter((case.get("severity") or "Unrated") for case in cases)
    decisions = Counter(
        (case.get("decision") or {}).get("decision", "pending") for case in cases
    )
    tactics = Counter()
    techniques = Counter()
    rules = Counter()
    hosts = Counter()
    for case in cases:
        tactics.update(case.get("mitre_tactics") or {})
        techniques.update(case.get("mitre_techniques") or [])
        rule = case.get("detection_rule") or "Unknown"
        rules[rule] += 1
        host = case.get("affected_host") or "Unknown"
        hosts[host] += 1
    return {
        "total": len(cases),
        "by_severity": dict(severities),
        "by_decision": dict(decisions),
        "by_tactic": dict(tactics),
        "by_technique": dict(techniques),
        "by_rule": dict(rules),
        "by_host": dict(hosts),
        "high_risk": sum(
            1 for case in cases if (case.get("severity_rank") or 0) >= 3
        ),
        "pending": decisions.get("pending", 0),
        "correlated_events": sum(
            case.get("correlated_events_int") or 0 for case in cases
        ),
    }
