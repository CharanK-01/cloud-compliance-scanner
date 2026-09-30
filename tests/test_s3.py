"""Unit tests for S3 compliance checks using moto."""

import boto3
import pytest
from moto import mock_aws

from scanner.checks.s3 import (
    check_s3_block_public_access,
    check_s3_no_public_access,
    check_s3_tls_enforced,
    check_s3_versioning,
)
from scanner.session import init_scan_context


@pytest.fixture
def aws_credentials(monkeypatch):
    """Mock AWS credentials for moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@mock_aws
def test_s3_001_block_public_access(aws_credentials):
    """Test S3-001 block public access compliant vs non-compliant bucket."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    ctx = init_scan_context(session=session, regions=["us-east-1"])

    # 1. Bucket without BPA -> FAIL
    s3.create_bucket(Bucket="open-bucket")
    findings = check_s3_block_public_access(ctx)
    open_finding = next(f for f in findings if "open-bucket" in f.resource_id)
    assert open_finding.status == "FAIL"

    # 2. Bucket with all BPA enabled -> PASS
    s3.create_bucket(Bucket="locked-bucket")
    s3.put_public_access_block(
        Bucket="locked-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    # Clear cached buckets
    if hasattr(ctx, "_s3_buckets"):
        delattr(ctx, "_s3_buckets")

    findings = check_s3_block_public_access(ctx)
    locked_finding = next(f for f in findings if "locked-bucket" in f.resource_id)
    assert locked_finding.status == "PASS"


@mock_aws
def test_s3_004_versioning(aws_credentials):
    """Test S3-004 versioning enabled vs disabled."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    ctx = init_scan_context(session=session, regions=["us-east-1"])

    s3.create_bucket(Bucket="versioned-bucket")
    s3.put_bucket_versioning(
        Bucket="versioned-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )
    s3.create_bucket(Bucket="unversioned-bucket")

    findings = check_s3_versioning(ctx)
    v_finding = next(f for f in findings if "versioned-bucket" in f.resource_id)
    uv_finding = next(f for f in findings if "unversioned-bucket" in f.resource_id)

    assert v_finding.status == "PASS"
    assert uv_finding.status == "FAIL"


@mock_aws
def test_s3_006_tls_enforced(aws_credentials):
    """Test S3-006 bucket policy enforcing SecureTransport."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    ctx = init_scan_context(session=session, regions=["us-east-1"])

    s3.create_bucket(Bucket="tls-bucket")
    policy_doc = """{
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowSSLRequestsOnly",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::tls-bucket/*",
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }]
    }"""
    s3.put_bucket_policy(Bucket="tls-bucket", Policy=policy_doc)

    s3.create_bucket(Bucket="notls-bucket")

    findings = check_s3_tls_enforced(ctx)
    tls_f = next(f for f in findings if "tls-bucket" in f.resource_id)
    notls_f = next(f for f in findings if "notls-bucket" in f.resource_id)

    assert tls_f.status == "PASS"
    assert notls_f.status == "FAIL"
