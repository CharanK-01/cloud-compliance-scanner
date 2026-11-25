"""Unit tests for IAM compliance checks using moto."""

import boto3
import pytest
from moto import mock_aws

from scanner.checks.iam import (
    check_no_root_access_keys,
    check_no_wildcard_admin_policies,
    check_password_policy,
    check_root_mfa,
    check_user_policy_attachment,
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
def test_iam_004_password_policy(aws_credentials):
    """Test IAM-004 compliant vs missing password policy."""
    session = boto3.Session(region_name="us-east-1")
    ctx = init_scan_context(session=session, regions=["us-east-1"])

    # 1. No policy set -> FAIL
    findings = check_password_policy(ctx)
    assert len(findings) == 1
    assert findings[0].status == "FAIL"

    # 2. Compliant password policy set -> PASS
    iam = session.client("iam", region_name="us-east-1")
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        PasswordReusePrevention=24,
        MaxPasswordAge=90,
    )
    findings = check_password_policy(ctx)
    assert len(findings) == 1
    assert findings[0].status == "PASS"


@mock_aws
def test_iam_007_wildcard_admin_policies(aws_credentials):
    """Test IAM-007 wildcard admin policy detection."""
    session = boto3.Session(region_name="us-east-1")
    ctx = init_scan_context(session=session, regions=["us-east-1"])
    iam = session.client("iam", region_name="us-east-1")

    # Compliant scoped policy
    scoped_doc = """{
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::mybucket/*"}]
    }"""
    p_good = iam.create_policy(PolicyName="ScopedReadOnly", PolicyDocument=scoped_doc)
    # Attach to a test role so OnlyAttached=True catches it
    role = iam.create_role(
        RoleName="TestRole",
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}',
    )
    iam.attach_role_policy(RoleName="TestRole", PolicyArn=p_good["Policy"]["Arn"])

    findings = check_no_wildcard_admin_policies(ctx)
    assert any(f.resource_id == p_good["Policy"]["Arn"] and f.status == "PASS" for f in findings)

    # Insecure wildcard policy
    wildcard_doc = """{
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }"""
    p_bad = iam.create_policy(PolicyName="InsecureAdmin", PolicyDocument=wildcard_doc)
    iam.attach_role_policy(RoleName="TestRole", PolicyArn=p_bad["Policy"]["Arn"])

    findings = check_no_wildcard_admin_policies(ctx)
    bad_finding = next(f for f in findings if f.resource_id == p_bad["Policy"]["Arn"])
    assert bad_finding.status == "FAIL"


@mock_aws
def test_iam_008_direct_user_policies(aws_credentials):
    """Test IAM-008 detecting directly attached policies on users."""
    session = boto3.Session(region_name="us-east-1")
    ctx = init_scan_context(session=session, regions=["us-east-1"])
    iam = session.client("iam", region_name="us-east-1")

    # User with no direct policies -> PASS
    iam.create_user(UserName="CleanUser")
    findings = check_user_policy_attachment(ctx)
    clean = next(f for f in findings if "CleanUser" in f.resource_id)
    assert clean.status == "PASS"

    # User with direct inline policy -> FAIL
    iam.create_user(UserName="DirtyUser")
    iam.put_user_policy(
        UserName="DirtyUser",
        PolicyName="InlinePriv",
        PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]}',
    )
    findings = check_user_policy_attachment(ctx)
    dirty = next(f for f in findings if "DirtyUser" in f.resource_id)
    assert dirty.status == "FAIL"
