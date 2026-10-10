"""
iso27001_mapping.py

Maps Checkov (Terraform/IaC) and Trivy (container CVE) findings to
ISO/IEC 27001:2022 Annex A controls, producing auditor-grade evidence
instead of a bare pass/fail list.

Design notes
------------
Checkov alone ships 1000+ AWS check IDs and the set changes release to
release. Rather than pretend to hand-map every one (which would silently
go stale), this module maintains:

1. `CHECKOV_ISO_MAP` — an explicit, curated mapping for the ~30 highest-
   signal AWS checks (public exposure, encryption, IAM, logging, network
   segmentation). These are the findings an ISO 27001 auditor asks about
   first, so they get named ISO control references and a short rationale.
2. `CATEGORY_FALLBACK` — every Checkov check also carries a `category`
   attribute (e.g. "networking", "encryption", "iam", "logging",
   "general_security"). Any check ID *not* in the curated map still gets
   a defensible Annex A reference via its category, so the tool degrades
   gracefully instead of dropping unmapped findings from the evidence
   report.
3. `TRIVY_CVE_ISO_MAP` — container/OS CVEs map by severity to the
   technical vulnerability management and secure engineering controls;
   CVSS severity, not the specific CVE ID, drives which controls apply.

Control text is paraphrased from the public ISO/IEC 27001:2022 Annex A
control titles for reference purposes only — this module does not
reproduce the standard's normative text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class IsoControl:
    ref: str            # e.g. "A.8.20"
    title: str           # short paraphrase of the control title


@dataclass(frozen=True)
class ControlMapping:
    iso_controls: tuple[IsoControl, ...]
    cis_aws_ref: Optional[str] = None
    rationale: str = ""
    # Authoritative severity for this finding type. Checkov's open-source
    # output leaves `severity` null for almost every check (severity by
    # rule is a Bridgecrew/paid-platform feature) — see orchestrator.py
    # for how this field is used to override that empty field rather than
    # let every finding silently collapse to a default MEDIUM.
    severity: Optional[str] = None


# ---------------------------------------------------------------------------
# ISO/IEC 27001:2022 Annex A control reference table (paraphrased titles)
# ---------------------------------------------------------------------------

A_5_23 = IsoControl("A.5.23", "Information security for use of cloud services")
A_5_24 = IsoControl("A.5.24", "Information security incident management planning")
A_5_34 = IsoControl("A.5.34", "Privacy and protection of personal identifiable information")
A_8_2 = IsoControl("A.8.2", "Privileged access rights")
A_8_3 = IsoControl("A.8.3", "Information access restriction")
A_8_5 = IsoControl("A.8.5", "Secure authentication")
A_8_8 = IsoControl("A.8.8", "Management of technical vulnerabilities")
A_8_9 = IsoControl("A.8.9", "Configuration management")
A_8_12 = IsoControl("A.8.12", "Data leakage prevention")
A_8_15 = IsoControl("A.8.15", "Logging")
A_8_16 = IsoControl("A.8.16", "Monitoring activities")
A_8_20 = IsoControl("A.8.20", "Networks security")
A_8_22 = IsoControl("A.8.22", "Segregation of networks")
A_8_24 = IsoControl("A.8.24", "Use of cryptography")
A_8_25 = IsoControl("A.8.25", "Secure development life cycle")
A_8_27 = IsoControl("A.8.27", "Secure system architecture and engineering principles")
A_8_28 = IsoControl("A.8.28", "Secure coding")
A_8_29 = IsoControl("A.8.29", "Security testing in development and acceptance")
A_8_32 = IsoControl("A.8.32", "Change management")


# ---------------------------------------------------------------------------
# Curated Checkov check ID -> ISO 27001 mapping (highest-signal AWS checks)
# ---------------------------------------------------------------------------

CHECKOV_ISO_MAP: dict[str, ControlMapping] = {
    "CKV_AWS_20": ControlMapping(
        (A_8_3, A_8_12, A_5_23),
        cis_aws_ref="CIS AWS 2.1.5",
        rationale="S3 bucket allows public read access — direct information disclosure risk.",
        severity="CRITICAL",
    ),
    "CKV_AWS_57": ControlMapping(
        (A_8_3, A_8_12),
        cis_aws_ref="CIS AWS 2.1.5",
        rationale="S3 bucket allows public write access — data integrity and leakage risk.",
        severity="CRITICAL",
    ),
    "CKV2_AWS_6": ControlMapping(
        (A_8_3, A_8_12),
        rationale="S3 bucket has no public access block configured.",
        severity="HIGH",
    ),
    "CKV_AWS_19": ControlMapping(
        (A_8_24, A_5_34),
        cis_aws_ref="CIS AWS 2.1.1",
        rationale="S3 bucket does not enforce server-side encryption at rest.",
        severity="HIGH",
    ),
    "CKV_AWS_145": ControlMapping(
        (A_8_24,),
        rationale="S3 bucket not encrypted with a customer-managed KMS key.",
        severity="MEDIUM",
    ),
    "CKV_AWS_21": ControlMapping(
        (A_8_9, A_5_24),
        rationale="S3 bucket versioning disabled — hampers incident recovery and change tracking.",
        severity="LOW",
    ),
    "CKV_AWS_18": ControlMapping(
        (A_8_15, A_8_16),
        rationale="S3 bucket access logging not enabled — no audit trail of object access.",
        severity="MEDIUM",
    ),
    "CKV_AWS_16": ControlMapping(
        (A_8_24, A_5_34),
        cis_aws_ref="CIS AWS 2.3.1",
        rationale="RDS instance storage is not encrypted at rest.",
        severity="HIGH",
    ),
    "CKV_AWS_17": ControlMapping(
        (A_8_3, A_8_20),
        rationale="RDS instance is publicly accessible from the internet.",
        severity="CRITICAL",
    ),
    "CKV_AWS_24": ControlMapping(
        (A_8_20, A_8_22),
        cis_aws_ref="CIS AWS 5.2",
        rationale="Security group allows unrestricted ingress on SSH (port 22) from 0.0.0.0/0.",
        severity="CRITICAL",
    ),
    "CKV_AWS_25": ControlMapping(
        (A_8_20, A_8_22),
        cis_aws_ref="CIS AWS 5.3",
        rationale="Security group allows unrestricted ingress on RDP (port 3389) from 0.0.0.0/0.",
        severity="CRITICAL",
    ),
    "CKV_AWS_260": ControlMapping(
        (A_8_20, A_8_22),
        rationale="Security group allows unrestricted ingress on HTTP (port 80) from 0.0.0.0/0.",
        severity="HIGH",
    ),
    "CKV_AWS_382": ControlMapping(
        (A_8_20, A_8_22),
        rationale="Security group allows unrestricted egress on all ports/protocols to 0.0.0.0/0.",
        severity="MEDIUM",
    ),
    "CKV_AWS_23": ControlMapping(
        (A_8_9,),
        rationale="Security group rule has no description — hinders change review and audit.",
        severity="LOW",
    ),
    "CKV_AWS_79": ControlMapping(
        (A_8_2, A_8_5),
        rationale="EC2 instance permits IMDSv1 — vulnerable to SSRF-based credential theft.",
        severity="HIGH",
    ),
    "CKV_AWS_130": ControlMapping(
        (A_8_20,),
        rationale="Subnet auto-assigns public IP addresses to launched instances.",
        severity="MEDIUM",
    ),
    "CKV_AWS_8": ControlMapping(
        (A_8_16,),
        rationale="Detailed monitoring not enabled on the instance/launch configuration.",
        severity="LOW",
    ),
    "CKV_AWS_126": ControlMapping(
        (A_8_16,),
        rationale="Detailed monitoring not enabled on the EC2 instance.",
        severity="LOW",
    ),
    "CKV_AWS_129": ControlMapping(
        (A_8_15, A_8_16),
        rationale="RDS instance logging is not enabled for one or more log types.",
        severity="MEDIUM",
    ),
    "CKV_AWS_40": ControlMapping(
        (A_8_2, A_8_3),
        cis_aws_ref="CIS AWS 1.16",
        rationale="IAM policy grants wildcard (*) actions instead of least-privilege permissions.",
        severity="HIGH",
    ),
    "CKV_AWS_61": ControlMapping(
        (A_8_2,),
        rationale="IAM policy is attached directly to a user rather than a role or group.",
        severity="MEDIUM",
    ),
    "CKV_AWS_63": ControlMapping(
        (A_8_2, A_8_3),
        cis_aws_ref="CIS AWS 1.16",
        rationale="IAM policy grants full administrative privileges ('*' on '*').",
        severity="CRITICAL",
    ),
    "CKV_AWS_41": ControlMapping(
        (A_8_5, A_8_12),
        rationale="Hardcoded AWS access key / secret detected in source — credential leakage risk.",
        severity="CRITICAL",
    ),
    "CKV_AWS_39": ControlMapping(
        (A_8_16, A_5_24),
        rationale="CloudTrail logging is not enabled for the account/region.",
        severity="HIGH",
    ),
    "CKV_AWS_67": ControlMapping(
        (A_8_15, A_8_16),
        rationale="CloudTrail log file validation is not enabled — logs could be tampered with undetected.",
        severity="MEDIUM",
    ),
}

# Checkov category -> fallback ISO controls, used when a specific check ID
# is not in CHECKOV_ISO_MAP above. Categories are inferred heuristically
# from the check ID prefix / Checkov's own "category" metadata where present.
CATEGORY_FALLBACK: dict[str, ControlMapping] = {
    "networking": ControlMapping((A_8_20, A_8_22), rationale="Network exposure or segmentation finding.", severity="MEDIUM"),
    "encryption": ControlMapping((A_8_24,), rationale="Data-at-rest or in-transit encryption finding.", severity="MEDIUM"),
    "iam": ControlMapping((A_8_2, A_8_3), rationale="Identity, access, or privilege finding.", severity="MEDIUM"),
    "logging": ControlMapping((A_8_15, A_8_16), rationale="Logging or monitoring coverage finding.", severity="LOW"),
    "general_security": ControlMapping((A_8_9, A_8_27), rationale="General secure configuration finding.", severity="MEDIUM"),
}

DEFAULT_FALLBACK = ControlMapping(
    (A_8_9,),
    rationale="Unmapped Checkov finding — configuration management control applied by default.",
    severity="MEDIUM",
)


import re as _re

# Checkov's JSON output carries no category field, so the category is inferred
# from the check title. Rules are ordered by specificity: a check about
# "encrypting a CloudWatch log group" is an encryption finding, not a logging one.
_CATEGORY_RULES = [
    ("encryption", _re.compile(
        r"encrypt|\bkms\b|\btls\b|\bssl\b|\bhttps\b|certificate|\bcmk\b|customer.managed key",
        _re.IGNORECASE)),
    ("logging", _re.compile(
        r"\blogs?\b|logging|cloudtrail|cloudwatch|monitor|audit|flow log",
        _re.IGNORECASE)),
    ("iam", _re.compile(
        r"\biam\b|polic(?:y|ies)|\broles?\b|password|\bmfa\b|credential|privilege"
        r"|administrative|access key|permission|principal|assume",
        _re.IGNORECASE)),
    ("networking", _re.compile(
        r"security group|ingress|egress|\bport\b|\bvpc\b|subnet|publicly|public access"
        r"|0\.0\.0\.0|\bcidr\b|network|firewall|\bwaf\b|load balancer|internet",
        _re.IGNORECASE)),
]


def infer_category(title: Optional[str]) -> Optional[str]:
    """Best-effort category for a Checkov check, inferred from its title.

    Returns None when no rule matches, so the caller falls through to the
    generic DEFAULT_FALLBACK rather than guessing.
    """
    if not title:
        return None
    for category, pattern in _CATEGORY_RULES:
        if pattern.search(title):
            return category
    return None


def map_checkov_finding(check_id: str, category: Optional[str] = None,
                        title: Optional[str] = None) -> ControlMapping:
    """Return the ISO 27001 control mapping for a single Checkov check ID.

    Resolution order: curated check ID -> category (given, else inferred from
    the title) -> generic default.
    """
    if check_id in CHECKOV_ISO_MAP:
        return CHECKOV_ISO_MAP[check_id]
    if not category:
        category = infer_category(title)
    if category and category.lower() in CATEGORY_FALLBACK:
        return CATEGORY_FALLBACK[category.lower()]
    return DEFAULT_FALLBACK


# ---------------------------------------------------------------------------
# Trivy CVE severity -> ISO 27001 mapping
# ---------------------------------------------------------------------------
# Trivy findings are open-ended CVE IDs (thousands, updated daily via the
# NVD feed), so — unlike the curated Checkov table above — the defensible
# mapping is by severity band against the technical vulnerability
# management and secure engineering control family, which is what an
# ISO 27001 auditor actually checks: "do you have a working vulnerability
# management process", not "did you specifically catch CVE-2024-XXXXX".

TRIVY_SEVERITY_ISO_MAP: dict[str, ControlMapping] = {
    "CRITICAL": ControlMapping(
        (A_8_8, A_8_25, A_8_29),
        rationale="Critical severity CVE in a deployed container image — active exploit risk.",
    ),
    "HIGH": ControlMapping(
        (A_8_8, A_8_29),
        rationale="High severity CVE in a deployed container image.",
    ),
    "MEDIUM": ControlMapping(
        (A_8_8,),
        rationale="Medium severity CVE — should be remediated within a defined SLA.",
    ),
    "LOW": ControlMapping(
        (A_8_8,),
        rationale="Low severity CVE — track and remediate opportunistically.",
    ),
    "UNKNOWN": ControlMapping(
        (A_8_8,),
        rationale="Severity not classified by the advisory source.",
    ),
}


def map_trivy_finding(severity: str) -> ControlMapping:
    """Return the ISO 27001 control mapping for a Trivy CVE finding by severity."""
    return TRIVY_SEVERITY_ISO_MAP.get(severity.upper(), TRIVY_SEVERITY_ISO_MAP["UNKNOWN"])
