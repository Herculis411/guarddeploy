"""
report_generator.py

Turns a ScanResult (from orchestrator.py) into:
  1. A structured JSON evidence report — machine-readable, suitable for
     feeding into a GRC tool or archiving as audit evidence.
  2. A self-contained HTML report — for a human reviewer or auditor,
     with an executive summary, findings grouped by severity, and each
     finding's ISO 27001 Annex A control reference.

This is the module that makes GuardDeploy an audit-evidence generator
rather than "another scanner wrapper": the differentiator is that every
finding leaves this module already mapped to a named ISO 27001 control,
not just a tool-specific rule ID.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from guarddeploy.orchestrator import Finding, ScanResult, SEVERITY_ORDER

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _top_recommendations(failed: list[Finding], limit: int = 3) -> list[str]:
    """Pick the highest-severity, highest-frequency findings as headline recommendations."""
    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    by_check: dict[str, list[Finding]] = {}
    for f in failed:
        by_check.setdefault(f.check_id, []).append(f)

    ranked = sorted(
        by_check.items(),
        key=lambda item: (severity_rank.get(item[1][0].severity, 99), -len(item[1])),
    )
    recs = []
    for check_id, group in ranked[:limit]:
        f = group[0]
        controls = ", ".join(c.ref for c in f.control_mapping.iso_controls)
        recs.append(
            f"[{f.severity}] {f.title} ({check_id}) — {len(group)} occurrence(s). "
            f"Remediate to satisfy ISO 27001 {controls}."
        )
    return recs


def build_report_data(scan: ScanResult, project_name: str = "GuardDeploy Scan") -> dict:
    """Assemble the structured report dict shared by both JSON and HTML output."""
    failed = scan.failed_findings
    total_checks = len(scan.findings)
    total_failed = len(failed)
    pass_rate = round(100 * (1 - total_failed / total_checks), 1) if total_checks else 100.0

    counts = _severity_counts(failed)
    critical_count = counts.get("CRITICAL", 0)

    findings_serialised = []
    for f in scan.findings:
        d = asdict(f)
        d["control_mapping"] = {
            "iso_controls": [{"ref": c.ref, "title": c.title} for c in f.control_mapping.iso_controls],
            "cis_aws_ref": f.control_mapping.cis_aws_ref,
            "rationale": f.control_mapping.rationale,
        }
        findings_serialised.append(d)

    return {
        "project_name": project_name,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {
            "total_checks": total_checks,
            "total_failed": total_failed,
            "pass_rate_pct": pass_rate,
            "critical_count": critical_count,
            "severity_counts": counts,
            "top_recommendations": _top_recommendations(failed),
        },
        "tool_errors": scan.tool_errors,
        "findings": findings_serialised,
    }


def write_json_report(scan: ScanResult, output_path: str, project_name: str = "GuardDeploy Scan") -> dict:
    """Write the structured JSON evidence report and return the report data dict."""
    data = build_report_data(scan, project_name)
    Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def write_html_report(scan: ScanResult, output_path: str, project_name: str = "GuardDeploy Scan") -> dict:
    """Render the self-contained HTML evidence report and return the report data dict."""
    data = build_report_data(scan, project_name)

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")
    html = template.render(**data, severity_order=SEVERITY_ORDER)
    Path(output_path).write_text(html, encoding="utf-8")
    return data
