"""Unit tests for EC2 & VPC compliance checks using moto."""

import boto3
import pytest
from moto import mock_aws

from scanner.checks.ec2_vpc import (
    check_ebs_default_encryption,
    check_sg_admin_ports,
    check_sg_all_ports_ingress,
    check_vpc_flow_logs,
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
def test_net_001_sg_admin_ports(aws_credentials):
    """Test NET-001 open SSH port detection."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    ctx = init_scan_context(session=session, regions=["us-east-1"])

    # Create VPC
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    # Insecure SG with 22 open to 0.0.0.0/0
    sg_bad = ec2.create_security_group(GroupName="insecure-ssh-sg", Description="bad", VpcId=vpc_id)
    ec2.authorize_security_group_ingress(
        GroupId=sg_bad["GroupId"],
        IpProtocol="tcp",
        FromPort=22,
        ToPort=22,
        CidrIp="0.0.0.0/0",
    )

    # Secure SG with 443 only
    sg_good = ec2.create_security_group(GroupName="web-https-sg", Description="good", VpcId=vpc_id)
    ec2.authorize_security_group_ingress(
        GroupId=sg_good["GroupId"],
        IpProtocol="tcp",
        FromPort=443,
        ToPort=443,
        CidrIp="0.0.0.0/0",
    )

    findings = check_sg_admin_ports(ctx)
    f_bad = next(f for f in findings if sg_bad["GroupId"] in f.resource_id)
    f_good = next(f for f in findings if sg_good["GroupId"] in f.resource_id)

    assert f_bad.status == "FAIL"
    assert f_good.status == "PASS"


@mock_aws
def test_net_002_sg_all_ports(aws_credentials):
    """Test NET-002 unrestricted all-port ingress."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    ctx = init_scan_context(session=session, regions=["us-east-1"])

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    # Open all ports (-1)
    sg_all = ec2.create_security_group(GroupName="wildcard-sg", Description="all", VpcId=vpc_id)
    ec2.authorize_security_group_ingress(
        GroupId=sg_all["GroupId"],
        IpProtocol="-1",
        CidrIp="0.0.0.0/0",
    )

    findings = check_sg_all_ports_ingress(ctx)
    f_all = next(f for f in findings if sg_all["GroupId"] in f.resource_id)
    assert f_all.status == "FAIL"


@mock_aws
def test_net_003_ebs_default_encryption(aws_credentials):
    """Test NET-003 EBS default encryption."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    ctx = init_scan_context(session=session, regions=["us-east-1"])

    # Default is off -> FAIL
    findings = check_ebs_default_encryption(ctx)
    assert findings[0].status == "FAIL"

    # Enable EBS encryption by default -> PASS
    ec2.enable_ebs_encryption_by_default()
    findings = check_ebs_default_encryption(ctx)
    assert findings[0].status == "PASS"
