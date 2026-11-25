"""EC2 and VPC Security Checks (NET-001 through NET-005)."""

from typing import Any, Dict, List
from botocore.exceptions import ClientError

from scanner.models import Finding, ScanContext
from scanner.registry import check


def _make_finding(
    ctx: ScanContext,
    check_id: str,
    resource_id: str,
    status: str,
    evidence: Dict[str, Any],
    region: str,
) -> Finding:
    meta = ctx.controls.get(check_id)
    title = meta.title if meta else check_id
    service = meta.service if meta else "ec2"
    severity = meta.severity if meta else "Medium"
    risk_score = meta.risk_score if meta else 9
    iso_controls = meta.iso_controls if meta else []
    remediation = meta.remediation if meta else ""
    rationale = meta.rationale if meta else ""

    return Finding(
        check_id=check_id,
        title=title,
        service=service,
        region=region,
        resource_id=resource_id,
        status=status,
        severity=severity,
        risk_score=risk_score,
        iso_controls=iso_controls,
        evidence=evidence,
        remediation=remediation,
        rationale=rationale,
    )


@check("NET-001")
def check_sg_admin_ports(ctx: ScanContext) -> List[Finding]:
    """NET-001: No SG allows 0.0.0.0/0 or ::/0 to SSH (22) or RDP (3389)."""
    findings = []
    for region in ctx.regions:
        ec2 = ctx.get_client("ec2", region_name=region)
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    arn = f"arn:aws:ec2:{region}:{ctx.account_id}:security-group/{sg_id}"
                    open_rules = []

                    for perm in sg.get("IpPermissions", []):
                        proto = perm.get("IpProtocol")
                        from_port = perm.get("FromPort", 0)
                        to_port = perm.get("ToPort", 65535)

                        has_admin_port = False
                        if proto == "-1":
                            has_admin_port = True
                        elif from_port is not None and to_port is not None:
                            if (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port):
                                has_admin_port = True

                        if has_admin_port:
                            for ip_range in perm.get("IpRanges", []):
                                if ip_range.get("CidrIp") == "0.0.0.0/0":
                                    open_rules.append({"cidr": "0.0.0.0/0", "perm": perm})
                            for ip6_range in perm.get("Ipv6Ranges", []):
                                if ip6_range.get("CidrIpv6") == "::/0":
                                    open_rules.append({"cidr": "::/0", "perm": perm})

                    status = "FAIL" if open_rules else "PASS"
                    findings.append(
                        _make_finding(
                            ctx=ctx,
                            check_id="NET-001",
                            resource_id=arn,
                            status=status,
                            evidence={"GroupName": sg.get("GroupName"), "open_rules_count": len(open_rules), "rules": open_rules},
                            region=region,
                        )
                    )
        except ClientError as e:
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="NET-001",
                    resource_id=f"ec2:security-groups:{region}",
                    status="ERROR",
                    evidence={"error": str(e), "code": e.response["Error"]["Code"]},
                    region=region,
                )
            )

    return findings


@check("NET-002")
def check_sg_all_ports_ingress(ctx: ScanContext) -> List[Finding]:
    """NET-002: No SG allows all ports from the internet."""
    findings = []
    for region in ctx.regions:
        ec2 = ctx.get_client("ec2", region_name=region)
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    arn = f"arn:aws:ec2:{region}:{ctx.account_id}:security-group/{sg_id}"
                    all_port_rules = []

                    for perm in sg.get("IpPermissions", []):
                        proto = perm.get("IpProtocol")
                        from_port = perm.get("FromPort")
                        to_port = perm.get("ToPort")

                        is_all_ports = False
                        if proto == "-1":
                            is_all_ports = True
                        elif from_port == 0 and to_port == 65535:
                            is_all_ports = True

                        if is_all_ports:
                            for ip_range in perm.get("IpRanges", []):
                                if ip_range.get("CidrIp") == "0.0.0.0/0":
                                    all_port_rules.append({"cidr": "0.0.0.0/0", "perm": perm})
                            for ip6_range in perm.get("Ipv6Ranges", []):
                                if ip6_range.get("CidrIpv6") == "::/0":
                                    all_port_rules.append({"cidr": "::/0", "perm": perm})

                    status = "FAIL" if all_port_rules else "PASS"
                    findings.append(
                        _make_finding(
                            ctx=ctx,
                            check_id="NET-002",
                            resource_id=arn,
                            status=status,
                            evidence={"GroupName": sg.get("GroupName"), "all_port_rules": all_port_rules},
                            region=region,
                        )
                    )
        except ClientError as e:
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="NET-002",
                    resource_id=f"ec2:security-groups:{region}",
                    status="ERROR",
                    evidence={"error": str(e), "code": e.response["Error"]["Code"]},
                    region=region,
                )
            )

    return findings


@check("NET-003")
def check_ebs_default_encryption(ctx: ScanContext) -> List[Finding]:
    """NET-003: EBS default encryption on per region."""
    findings = []
    for region in ctx.regions:
        ec2 = ctx.get_client("ec2", region_name=region)
        try:
            res = ec2.get_ebs_encryption_by_default()
            is_enabled = res.get("EbsEncryptionByDefault", False)
            status = "PASS" if is_enabled else "FAIL"
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="NET-003",
                    resource_id=f"arn:aws:ec2:{region}:{ctx.account_id}:ebs-encryption",
                    status=status,
                    evidence={"EbsEncryptionByDefault": is_enabled},
                    region=region,
                )
            )
        except ClientError as e:
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="NET-003",
                    resource_id=f"arn:aws:ec2:{region}:{ctx.account_id}:ebs-encryption",
                    status="ERROR",
                    evidence={"error": str(e), "code": e.response["Error"]["Code"]},
                    region=region,
                )
            )

    return findings


@check("NET-004")
def check_ebs_volume_encryption(ctx: ScanContext) -> List[Finding]:
    """NET-004: No unencrypted EBS volumes."""
    findings = []
    for region in ctx.regions:
        ec2 = ctx.get_client("ec2", region_name=region)
        try:
            paginator = ec2.get_paginator("describe_volumes")
            volume_count = 0
            for page in paginator.paginate():
                for vol in page.get("Volumes", []):
                    volume_count += 1
                    vol_id = vol["VolumeId"]
                    arn = f"arn:aws:ec2:{region}:{ctx.account_id}:volume/{vol_id}"
                    is_enc = vol.get("Encrypted", False)
                    status = "PASS" if is_enc else "FAIL"
                    findings.append(
                        _make_finding(
                            ctx=ctx,
                            check_id="NET-004",
                            resource_id=arn,
                            status=status,
                            evidence={"VolumeId": vol_id, "Encrypted": is_enc, "State": vol.get("State")},
                            region=region,
                        )
                    )
            if volume_count == 0:
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="NET-004",
                        resource_id=f"ec2:volumes:{region}",
                        status="PASS",
                        evidence={"message": f"No EBS volumes present in {region}."},
                        region=region,
                    )
                )
        except ClientError as e:
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="NET-004",
                    resource_id=f"ec2:volumes:{region}",
                    status="ERROR",
                    evidence={"error": str(e), "code": e.response["Error"]["Code"]},
                    region=region,
                )
            )

    return findings


@check("NET-005")
def check_vpc_flow_logs(ctx: ScanContext) -> List[Finding]:
    """NET-005: VPC Flow Logs enabled."""
    findings = []
    for region in ctx.regions:
        ec2 = ctx.get_client("ec2", region_name=region)
        try:
            # 1. Describe VPCs
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            if not vpcs:
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="NET-005",
                        resource_id=f"ec2:vpcs:{region}",
                        status="PASS",
                        evidence={"message": f"No VPCs present in {region}."},
                        region=region,
                    )
                )
                continue

            # 2. Describe Flow Logs
            flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
            logged_vpcs = set()
            for fl in flow_logs:
                if fl.get("FlowLogStatus") == "ACTIVE" and fl.get("ResourceId"):
                    logged_vpcs.add(fl["ResourceId"])

            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                arn = f"arn:aws:ec2:{region}:{ctx.account_id}:vpc/{vpc_id}"
                has_logging = vpc_id in logged_vpcs
                status = "PASS" if has_logging else "FAIL"
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="NET-005",
                        resource_id=arn,
                        status=status,
                        evidence={"VpcId": vpc_id, "FlowLogsActive": has_logging, "IsDefault": vpc.get("IsDefault", False)},
                        region=region,
                    )
                )
        except ClientError as e:
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="NET-005",
                    resource_id=f"ec2:vpcs:{region}",
                    status="ERROR",
                    evidence={"error": str(e), "code": e.response["Error"]["Code"]},
                    region=region,
                )
            )

    return findings
