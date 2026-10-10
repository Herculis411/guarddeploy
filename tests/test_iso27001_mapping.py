from guarddeploy.iso27001_mapping import (
    DEFAULT_FALLBACK,
    map_checkov_finding,
    map_trivy_finding,
)


def test_known_checkov_check_maps_to_curated_control():
    mapping = map_checkov_finding("CKV_AWS_20")  # public S3 bucket
    refs = [c.ref for c in mapping.iso_controls]
    assert "A.8.3" in refs
    assert mapping.cis_aws_ref == "CIS AWS 2.1.5"
    assert "public read" in mapping.rationale.lower()


def test_unknown_check_falls_back_to_category():
    mapping = map_checkov_finding("CKV_AWS_9999_MADE_UP", category="networking")
    refs = [c.ref for c in mapping.iso_controls]
    assert "A.8.20" in refs


def test_fully_unknown_check_uses_default_fallback():
    mapping = map_checkov_finding("CKV_AWS_9999_MADE_UP")
    assert mapping == DEFAULT_FALLBACK


def test_trivy_severity_mapping_critical_includes_secure_dev_controls():
    mapping = map_trivy_finding("CRITICAL")
    refs = [c.ref for c in mapping.iso_controls]
    assert "A.8.8" in refs
    assert "A.8.25" in refs


def test_trivy_severity_mapping_is_case_insensitive():
    mapping_lower = map_trivy_finding("high")
    mapping_upper = map_trivy_finding("HIGH")
    assert mapping_lower == mapping_upper


def test_trivy_unrecognised_severity_defaults_to_unknown_bucket():
    mapping = map_trivy_finding("SOMETHING_WEIRD")
    refs = [c.ref for c in mapping.iso_controls]
    assert "A.8.8" in refs
