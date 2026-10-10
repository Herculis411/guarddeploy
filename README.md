# GuardDeploy

**Cloud DevSecOps scanning that outputs audit evidence, not just pass/fail.**

GuardDeploy orchestrates [Checkov](https://www.checkov.io/) (Terraform IaC scanning) and [Trivy](https://trivy.dev/) (container CVE scanning), then maps every finding to a named [ISO/IEC 27001:2022 Annex A](https://www.iso.org/standard/27001) control before generating a report. The scanning itself is not the differentiator — Checkov and Trivy already do that well, and this project doesn't try to replace them. The differentiator is what happens *after* the scan: a security engineer gets a pass/fail list; an auditor gets a document they can file as evidence.

Built by a CISA / ISO 27001 Lead Auditor background engineer as a portfolio project demonstrating the intersection of DevSecOps automation and information security governance.

## Why this exists

Generic IaC/container scanners (Checkov, Snyk, Prisma Cloud) tell you *what* is misconfigured. They don't tell you *which control in your ISMS* that finding relates to, which is the question an ISO 27001 auditor, a compliance lead, or a customer security questionnaire actually asks. GuardDeploy closes that gap for a defined, curated set of high-signal AWS misconfigurations, with a transparent fallback for everything else — see [`guarddeploy/iso27001_mapping.py`](guarddeploy/iso27001_mapping.py) for the full mapping table and its design rationale.

## What it does (MVP scope)

- Runs Checkov against a Terraform directory
- Runs Trivy against a container image or filesystem path
- Maps every failed check to its ISO/IEC 27001:2022 Annex A control(s), with a plain-English rationale
- Generates a structured **JSON evidence report** (for GRC tooling / archiving) and a self-contained **HTML report** (for a human reviewer)
- Exits non-zero when a finding at or above a configurable severity threshold exists — the signal a CI pipeline blocks a deployment on

**Deliberately out of scope for the MVP:** AWS Security Hub aggregation, a persistent dashboard, SAST/DAST, OWASP Top 10 rule coverage. These compete directly with mature tools (Security Hub, Prisma Cloud, Snyk) and add breadth without adding the ISO 27001 differentiator. They're candidates for a v2 once the evidence-mapping core is proven.

## Project structure

```
guarddeploy/
├── guarddeploy/
│   ├── orchestrator.py        # runs Checkov + Trivy, normalises output to Finding objects
│   ├── iso27001_mapping.py    # Checkov/Trivy finding -> ISO 27001 Annex A control mapping
│   ├── report_generator.py    # builds JSON + HTML evidence reports
│   ├── cli.py                 # command-line entry point + CI security gate
│   └── templates/
│       └── report.html.j2     # self-contained HTML report template
├── fixtures/
│   ├── terraform/main.tf      # intentionally misconfigured sample IaC (demo target)
│   └── docker/Dockerfile      # intentionally outdated sample image (demo target)
├── tests/
│   ├── test_iso27001_mapping.py
│   ├── test_orchestrator.py
│   └── test_report_generator.py
├── .github/workflows/security-gate.yml
└── requirements.txt
```

## Installation

```bash
git clone https://github.com/Herculis411/guarddeploy.git
cd guarddeploy
pip install -r requirements.txt
```

Trivy is a standalone Go binary and is not pip-installable — install it separately per the [official instructions](https://trivy.dev/latest/getting-started/installation/). GuardDeploy detects whether `trivy` is on `PATH` at runtime and skips the container scan (with a logged warning, not a crash) if it isn't, so IaC-only scanning works without it.

## Usage

```bash
# Scan Terraform only
python -m guarddeploy.cli --terraform-dir ./fixtures/terraform --output-dir ./report

# Scan Terraform + a container image, fail the build on HIGH or above
python -m guarddeploy.cli \
  --terraform-dir ./fixtures/terraform \
  --image node:14-alpine \
  --fail-on HIGH \
  --output-dir ./report
```

This writes `report/report.json` and `report/report.html`, and exits `1` if a blocking finding exists (see `.github/workflows/security-gate.yml` for the CI integration — the workflow uploads both reports as a build artifact regardless of pass/fail, so there's always an audit trail).

## Running the tests

```bash
pip install -r requirements.txt
pytest -v
```

Checkov's test runs for real against `fixtures/terraform` (no mocking) and asserts it actually catches the fixture's planted misconfigurations. Trivy's binary isn't assumed to be present in every environment (it requires a separate non-pip install), so its JSON-parsing path is tested against a schema-accurate captured sample with `subprocess.run` mocked — the same parsing code that runs against a live `trivy` invocation. See the docstring in `tests/test_orchestrator.py` for the full rationale.

## Example: what a finding looks like end to end

Checkov flags `CKV_AWS_20` (S3 bucket allows public read) on `fixtures/terraform/main.tf`. GuardDeploy's report shows:

| Field | Value |
|---|---|
| Severity | CRITICAL |
| Resource | `aws_s3_bucket.reports` |
| ISO 27001 Annex A | **A.8.3** Information access restriction · **A.8.12** Data leakage prevention · **A.5.23** Information security for use of cloud services |
| CIS AWS Benchmark | 2.1.5 |
| Rationale | S3 bucket allows public read access — direct information disclosure risk. |

That row is what goes in front of an auditor or a customer security review, not just "check failed."

## Mapping coverage (reference scan)

On `fixtures/terraform` plus `node:14-alpine`, GuardDeploy evaluated 166 results: 53 IaC checks (38 failed, 15 passed) and 113 container CVE findings. Of the 38 failed IaC checks, 16 (42%) matched a curated check-specific mapping, 13 (34%) a category mapping inferred from the check title, and 9 (24%) the generic configuration-management default. All 113 container findings use the curated vulnerability mapping.

Automated mapping is partial evidence: it places a finding in the right area of Annex A, and curation makes the placement precise. Moving checks out of the default tier is the main v2 priority.

## Roadmap (v2)

- AWS Security Hub findings aggregation alongside Checkov/Trivy
- Historical scan dashboard (trend of pass rate / findings over time)
- Extend the curated ISO 27001 mapping table beyond the current 25 highest-signal AWS checks
- NIST 800-53 and Cyber Essentials control mappings alongside ISO 27001

## Author

**Stephen Odunze** — Cyber Security & DevSecOps Engineer (CISA, ISO 27001 Lead Auditor, MSc Cyber Security)
[stephenodunze.online](https://stephenodunze.online) · [GitHub](https://github.com/Herculis411) · [LinkedIn](https://linkedin.com/in/stephen-odunze411)
