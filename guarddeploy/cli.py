"""
cli.py

Command-line entry point for GuardDeploy. Runs the configured scans,
writes the JSON + HTML evidence reports, and exits non-zero if any
CRITICAL finding is present — the signal a CI security gate blocks on.

Usage:
    python -m guarddeploy.cli --terraform-dir ./infra --output-dir ./report
    python -m guarddeploy.cli --terraform-dir ./infra --image myapp:latest --output-dir ./report
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from guarddeploy.orchestrator import run_scan
from guarddeploy.report_generator import write_html_report, write_json_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="GuardDeploy — Cloud DevSecOps scanning with ISO 27001 evidence mapping."
    )
    parser.add_argument("--terraform-dir", help="Path to Terraform IaC to scan with Checkov")
    parser.add_argument("--image", help="Container image reference to scan with Trivy")
    parser.add_argument("--fs", help="Filesystem path to scan with Trivy (alternative to --image)")
    parser.add_argument("--project-name", default="GuardDeploy Scan", help="Name shown on the report")
    parser.add_argument("--output-dir", default="./guarddeploy-report", help="Directory to write reports into")
    parser.add_argument(
        "--fail-on",
        default="CRITICAL",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEVER"],
        help="Exit non-zero if a finding at or above this severity exists (default: CRITICAL)",
    )
    args = parser.parse_args(argv)

    if not args.terraform_dir and not args.image and not args.fs:
        parser.error("at least one of --terraform-dir, --image, or --fs is required")

    container_target = args.image or args.fs
    container_target_type = "image" if args.image else "fs"

    scan = run_scan(
        terraform_dir=args.terraform_dir,
        container_target=container_target,
        container_target_type=container_target_type,
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "report.json"
    html_path = output_dir / "report.html"

    data = write_json_report(scan, str(json_path), project_name=args.project_name)
    write_html_report(scan, str(html_path), project_name=args.project_name)

    print(f"GuardDeploy scan complete: {data['summary']['total_checks']} checks, "
          f"{data['summary']['total_failed']} failed, "
          f"{data['summary']['pass_rate_pct']}% pass rate.")
    print(f"JSON evidence report: {json_path}")
    print(f"HTML evidence report: {html_path}")

    if scan.tool_errors:
        for err in scan.tool_errors:
            print(f"WARNING: {err}", file=sys.stderr)

    if args.fail_on != "NEVER":
        severity_rank = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        threshold_idx = severity_rank.index(args.fail_on)
        gate_severities = set(severity_rank[: threshold_idx + 1])
        blocking = [f for f in scan.failed_findings if f.severity in gate_severities]
        if blocking:
            print(
                f"\nSECURITY GATE FAILED: {len(blocking)} finding(s) at or above "
                f"{args.fail_on} severity. Deployment blocked.",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
