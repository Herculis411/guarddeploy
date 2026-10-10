"""
orchestrator.py

Runs Checkov against a Terraform directory and Trivy against a container
image or filesystem path, then normalises both tools' output into a
single list of Finding objects the report generator can consume.

Both tools are invoked as subprocesses producing JSON — this module does
not attempt to reimplement scanning logic, only orchestration and
normalisation. If a tool binary is not on PATH, the corresponding scan
is skipped with a warning rather than failing the whole run, so partial
scans (e.g. IaC-only, no container image yet) still produce a report.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from guarddeploy.iso27001_mapping import (
    ControlMapping,
    map_checkov_finding,
    map_trivy_finding,
)

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


@dataclass
class Finding:
    source: str                 # "checkov" | "trivy"
    check_id: str                # e.g. "CKV_AWS_20" or a CVE ID
    title: str
    severity: str                 # normalised to SEVERITY_ORDER values
    resource: str                 # affected resource / file / package
    file_path: str
    passed: bool
    control_mapping: ControlMapping
    guideline: Optional[str] = None


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    tool_errors: list[str] = field(default_factory=list)

    @property
    def failed_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.passed]

    def by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.failed_findings if f.severity == severity]


def _resolve_checkov_severity(raw_severity: Optional[str], mapping: ControlMapping) -> str:
    """
    Decide the severity to report for a Checkov finding.

    Checkov's open-source output leaves `severity` null for almost every
    check — per-rule severity is a Bridgecrew/paid-platform feature, not
    something the free CLI populates. Trusting that field naively would
    collapse every finding (a public S3 bucket and a missing SG
    description alike) to the same default, which defeats a
    severity-based CI gate. So the precedence here is:

      1. Checkov's own severity, if the CLI/output actually supplied one
         (kept in case a future Checkov version or Bridgecrew-connected
         run does populate it).
      2. The curated ISO 27001 mapping's severity, since building that
         mapping already required making a real risk judgement per check.
      3. MEDIUM, as a conservative default for anything genuinely unknown.
    """
    if raw_severity:
        sev = raw_severity.upper()
        if sev in SEVERITY_ORDER:
            return sev
    if mapping.severity:
        return mapping.severity
    return "MEDIUM"


def run_checkov(terraform_dir: str) -> tuple[list[Finding], list[str]]:
    """Run Checkov against a Terraform directory and return normalised findings."""
    errors: list[str] = []
    checkov_bin = shutil.which("checkov")
    if not checkov_bin:
        errors.append("checkov binary not found on PATH — skipping IaC scan")
        return [], errors

    cmd = [checkov_bin, "-d", terraform_dir, "--framework", "terraform", "-o", "json", "--compact"]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    # Checkov exits non-zero when it finds failed checks — that is expected,
    # not a tool failure. Only treat it as an error if stdout has no JSON.
    if not proc.stdout.strip():
        errors.append(f"checkov produced no output (exit {proc.returncode}): {proc.stderr[:500]}")
        return [], errors

    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        errors.append(f"failed to parse checkov JSON output: {exc}")
        return [], errors

    # Checkov emits either a single dict (one framework) or a list of dicts
    # (multiple frameworks). Normalise to a list.
    reports = raw if isinstance(raw, list) else [raw]

    findings: list[Finding] = []
    for report in reports:
        results = report.get("results", {})
        for bucket, passed_flag in (("failed_checks", False), ("passed_checks", True)):
            for check in results.get(bucket, []):
                check_id = check.get("check_id", "UNKNOWN")
                mapping = map_checkov_finding(check_id, title=check.get("check_name"))
                findings.append(
                    Finding(
                        source="checkov",
                        check_id=check_id,
                        title=check.get("check_name", check_id),
                        severity=_resolve_checkov_severity(check.get("severity"), mapping),
                        resource=check.get("resource", "unknown resource"),
                        file_path=check.get("file_path", terraform_dir),
                        passed=passed_flag,
                        control_mapping=mapping,
                        guideline=check.get("guideline"),
                    )
                )
    return findings, errors


def run_trivy(target: str, target_type: str = "image") -> tuple[list[Finding], list[str]]:
    """
    Run Trivy against a container image (target_type='image') or a
    filesystem path (target_type='fs') and return normalised findings.
    """
    errors: list[str] = []
    trivy_bin = shutil.which("trivy")
    if not trivy_bin:
        errors.append("trivy binary not found on PATH — skipping container/dependency scan")
        return [], errors

    cmd = [trivy_bin, target_type, "--format", "json", "--quiet", target]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    if not proc.stdout.strip():
        errors.append(f"trivy produced no output (exit {proc.returncode}): {proc.stderr[:500]}")
        return [], errors

    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        errors.append(f"failed to parse trivy JSON output: {exc}")
        return [], errors

    findings: list[Finding] = []
    for result in raw.get("Results", []):
        target_name = result.get("Target", target)
        for vuln in result.get("Vulnerabilities", []) or []:
            severity = vuln.get("Severity", "UNKNOWN").upper()
            mapping = map_trivy_finding(severity)
            findings.append(
                Finding(
                    source="trivy",
                    check_id=vuln.get("VulnerabilityID", "UNKNOWN"),
                    title=vuln.get("Title") or vuln.get("PkgName", "unknown package"),
                    severity=severity if severity in SEVERITY_ORDER else "UNKNOWN",
                    resource=f"{vuln.get('PkgName', '?')} {vuln.get('InstalledVersion', '')}".strip(),
                    file_path=target_name,
                    passed=False,  # Trivy only reports vulnerabilities present, never "passed" checks
                    control_mapping=mapping,
                    guideline=vuln.get("PrimaryURL"),
                )
            )
    return findings, errors


def run_scan(terraform_dir: Optional[str] = None,
             container_target: Optional[str] = None,
             container_target_type: str = "image") -> ScanResult:
    """Run whichever scans have a target configured and return a combined ScanResult."""
    result = ScanResult()

    if terraform_dir:
        findings, errors = run_checkov(terraform_dir)
        result.findings.extend(findings)
        result.tool_errors.extend(errors)

    if container_target:
        findings, errors = run_trivy(container_target, container_target_type)
        result.findings.extend(findings)
        result.tool_errors.extend(errors)

    return result
