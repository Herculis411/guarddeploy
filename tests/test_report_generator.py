import json

from guarddeploy.iso27001_mapping import map_checkov_finding, map_trivy_finding
from guarddeploy.orchestrator import Finding, ScanResult
from guarddeploy.report_generator import (
    build_report_data,
    write_html_report,
    write_json_report,
)


def _sample_scan() -> ScanResult:
    findings = [
        Finding(
            source="checkov",
            check_id="CKV_AWS_20",
            title="S3 Bucket has public read enabled",
            severity="CRITICAL",
            resource="aws_s3_bucket.reports",
            file_path="fixtures/terraform/main.tf",
            passed=False,
            control_mapping=map_checkov_finding("CKV_AWS_20"),
        ),
        Finding(
            source="checkov",
            check_id="CKV_AWS_24",
            title="Security group allows ingress from 0.0.0.0/0 to port 22",
            severity="HIGH",
            resource="aws_security_group.web",
            file_path="fixtures/terraform/main.tf",
            passed=False,
            control_mapping=map_checkov_finding("CKV_AWS_24"),
        ),
        Finding(
            source="checkov",
            check_id="CKV_AWS_18",
            title="S3 bucket has access logging enabled",
            severity="MEDIUM",
            resource="aws_s3_bucket.reports",
            file_path="fixtures/terraform/main.tf",
            passed=True,
            control_mapping=map_checkov_finding("CKV_AWS_18"),
        ),
        Finding(
            source="trivy",
            check_id="CVE-2023-99999",
            title="Example critical CVE in libfoo",
            severity="CRITICAL",
            resource="libfoo 1.2.3",
            file_path="python:3.9-slim-buster",
            passed=False,
            control_mapping=map_trivy_finding("CRITICAL"),
        ),
    ]
    return ScanResult(findings=findings, tool_errors=["trivy binary not found on PATH — skipping container/dependency scan (example warning)"])


def test_build_report_data_summary_counts():
    data = build_report_data(_sample_scan(), project_name="Test Project")
    summary = data["summary"]

    assert summary["total_checks"] == 4
    assert summary["total_failed"] == 3
    assert summary["critical_count"] == 2  # one checkov, one trivy
    assert 0 < summary["pass_rate_pct"] < 100
    assert len(summary["top_recommendations"]) <= 3
    assert data["project_name"] == "Test Project"


def test_build_report_data_findings_carry_iso_controls():
    data = build_report_data(_sample_scan())
    s3_finding = next(f for f in data["findings"] if f["check_id"] == "CKV_AWS_20")
    refs = [c["ref"] for c in s3_finding["control_mapping"]["iso_controls"]]
    assert "A.8.3" in refs


def test_write_json_report_produces_valid_json(tmp_path):
    out = tmp_path / "report.json"
    write_json_report(_sample_scan(), str(out), project_name="Test Project")
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["project_name"] == "Test Project"
    assert data["summary"]["total_checks"] == 4


def test_write_html_report_is_self_contained_and_includes_iso_refs(tmp_path):
    out = tmp_path / "report.html"
    write_html_report(_sample_scan(), str(out), project_name="Test Project")
    assert out.exists()
    html = out.read_text(encoding="utf-8")

    # Self-contained: no external CDN references
    assert "cdn." not in html
    assert "http://" not in html
    assert "https://" not in html or "PrimaryURL" not in html

    # Content sanity
    assert "Test Project" in html
    assert "A.8.3" in html  # ISO control chip for the S3 finding
    assert "CRITICAL" in html
