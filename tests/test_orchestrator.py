"""
test_orchestrator.py

Checkov is exercised for real, end to end, against the intentionally
misconfigured Terraform fixture — no mocking, this proves the actual
integration works.

Trivy's binary is not installable in every CI/sandbox environment
without root or a package manager (it ships as a standalone Go binary
via GitHub releases), so its JSON-parsing path is verified against a
schema-accurate captured sample (tests/fixtures/sample_trivy_output.json)
with subprocess.run mocked. This tests exactly the same parsing code
that runs against a live `trivy image --format json` invocation.
"""

import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from guarddeploy.orchestrator import run_checkov, run_trivy

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
SAMPLE_TRIVY_JSON = Path(__file__).parent / "fixtures" / "sample_trivy_output.json"


@pytest.mark.skipif(shutil.which("checkov") is None, reason="checkov not installed")
def test_run_checkov_against_misconfigured_fixture_finds_known_issues():
    findings, errors = run_checkov(str(FIXTURES_DIR / "terraform"))

    assert not errors
    assert len(findings) > 0

    failed_ids = {f.check_id for f in findings if not f.passed}

    # The fixture intentionally trips these — confirm Checkov actually caught them.
    assert "CKV_AWS_24" in failed_ids  # SSH open to 0.0.0.0/0
    assert "CKV_AWS_20" in failed_ids  # public S3 bucket

    # Every failed finding must carry an ISO 27001 control mapping.
    for f in findings:
        if not f.passed:
            assert len(f.control_mapping.iso_controls) > 0

    # Regression guard: Checkov OSS leaves `severity` null on almost every
    # check (it's a Bridgecrew-platform field), so the curated ISO mapping
    # table's severity must be the one that actually reaches the Finding —
    # otherwise a public S3 bucket and a missing SG description both land
    # as MEDIUM and a --fail-on CRITICAL gate never fires.
    by_id = {f.check_id: f for f in findings if not f.passed}
    assert by_id["CKV_AWS_20"].severity == "CRITICAL"  # public S3 read
    assert by_id["CKV_AWS_24"].severity == "CRITICAL"  # SSH open to the world


def test_run_trivy_parses_captured_sample_output():
    sample = json.loads(SAMPLE_TRIVY_JSON.read_text(encoding="utf-8"))
    fake_proc = subprocess.CompletedProcess(
        args=["trivy"], returncode=0, stdout=json.dumps(sample), stderr=""
    )

    with patch("guarddeploy.orchestrator.shutil.which", return_value="/usr/local/bin/trivy"), \
         patch("guarddeploy.orchestrator.subprocess.run", return_value=fake_proc):
        findings, errors = run_trivy("python:3.9-slim-buster", target_type="image")

    assert not errors
    assert len(findings) == 3

    critical = [f for f in findings if f.severity == "CRITICAL"]
    assert len(critical) == 1
    assert critical[0].check_id == "CVE-2023-45853"
    assert "A.8.8" in [c.ref for c in critical[0].control_mapping.iso_controls]


def test_run_trivy_missing_binary_returns_warning_not_crash():
    with patch("guarddeploy.orchestrator.shutil.which", return_value=None):
        findings, errors = run_trivy("some-image:latest")

    assert findings == []
    assert len(errors) == 1
    assert "not found on PATH" in errors[0]
