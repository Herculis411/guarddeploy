from guarddeploy.iso27001_mapping import (
    CATEGORY_FALLBACK, CHECKOV_ISO_MAP, DEFAULT_FALLBACK,
    infer_category, map_checkov_finding,
)


def test_infers_each_category():
    assert infer_category("Ensure no security groups allow ingress from 0.0.0.0:0 to port 22") == "networking"
    assert infer_category("Ensure all data stored in the S3 bucket is securely encrypted at rest") == "encryption"
    assert infer_category("Ensure VPC flow logging is enabled in all VPCs") == "logging"
    assert infer_category("Ensure IAM policies do not allow full '*' administrative privileges") == "iam"


def test_encryption_takes_precedence_over_logging():
    assert infer_category("Ensure CloudWatch log group is encrypted by KMS") == "encryption"


def test_unmatched_title_returns_none():
    assert infer_category("Ensure S3 bucket has versioning enabled") is None
    assert infer_category(None) is None


def test_uncurated_check_uses_inferred_category():
    m = map_checkov_finding("CKV_AWS_NOT_IN_TABLE", title="Ensure VPC flow logging is enabled in all VPCs")
    assert m is CATEGORY_FALLBACK["logging"]


def test_uncurated_check_without_title_uses_default():
    assert map_checkov_finding("CKV_AWS_NOT_IN_TABLE") is DEFAULT_FALLBACK


def test_curated_check_is_never_overridden():
    cid = next(iter(CHECKOV_ISO_MAP))
    assert map_checkov_finding(cid, title="encrypted logging ingress") is CHECKOV_ISO_MAP[cid]
