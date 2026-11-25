"""Logging, Monitoring and Configuration Checks (LOG-001 through LOG-004)."""

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
    region: str = "global",
) -> Finding:
    meta = ctx.controls.get(check_id)
    title = meta.title if meta else check_id
    service = meta.service if meta else "logging"
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


@check("LOG-001")
def check_cloudtrail_multi_region_logging(ctx: ScanContext) -> List[Finding]:
    """LOG-001: CloudTrail enabled, multi-region, actively logging."""
    ct = ctx.get_client("cloudtrail", region_name="us-east-1")
    try:
        trails = ct.describe_trails().get("trailList", [])
        if not trails:
            return [
                _make_finding(
                    ctx=ctx,
                    check_id="LOG-001",
                    resource_id="cloudtrail:trails",
                    status="FAIL",
                    evidence={"message": "No CloudTrail trails configured in account."},
                )
            ]

        compliant_trail_found = False
        findings = []
        for t in trails:
            arn = t.get("TrailARN", t.get("Name", "unknown"))
            is_multi = t.get("IsMultiRegionTrail", False)
            home_region = t.get("HomeRegion", "us-east-1")

            trail_ct = ctx.get_client("cloudtrail", region_name=home_region)
            try:
                status_res = trail_ct.get_trail_status(Name=arn)
                is_logging = status_res.get("IsLogging", False)
            except ClientError:
                is_logging = False

            passes = is_multi and is_logging
            if passes:
                compliant_trail_found = True

            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="LOG-001",
                    resource_id=arn,
                    status="PASS" if passes else "FAIL",
                    evidence={
                        "Name": t.get("Name"),
                        "IsMultiRegionTrail": is_multi,
                        "IsLogging": is_logging,
                        "HomeRegion": home_region,
                    },
                    region=home_region,
                )
            )

        return findings
    except ClientError as e:
        return [
            _make_finding(
                ctx=ctx,
                check_id="LOG-001",
                resource_id="cloudtrail:trails",
                status="ERROR",
                evidence={"error": str(e), "code": e.response["Error"]["Code"]},
            )
        ]


@check("LOG-002")
def check_cloudtrail_log_file_validation(ctx: ScanContext) -> List[Finding]:
    """LOG-002: CloudTrail log file validation enabled."""
    ct = ctx.get_client("cloudtrail", region_name="us-east-1")
    try:
        trails = ct.describe_trails().get("trailList", [])
        if not trails:
            return [
                _make_finding(
                    ctx=ctx,
                    check_id="LOG-002",
                    resource_id="cloudtrail:trails",
                    status="FAIL",
                    evidence={"message": "No CloudTrail trails configured."},
                )
            ]

        findings = []
        for t in trails:
            arn = t.get("TrailARN", t.get("Name", "unknown"))
            val_enabled = t.get("LogFileValidationEnabled", False)
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="LOG-002",
                    resource_id=arn,
                    status="PASS" if val_enabled else "FAIL",
                    evidence={"Name": t.get("Name"), "LogFileValidationEnabled": val_enabled},
                    region=t.get("HomeRegion", "us-east-1"),
                )
            )
        return findings
    except ClientError as e:
        return [
            _make_finding(
                ctx=ctx,
                check_id="LOG-002",
                resource_id="cloudtrail:trails",
                status="ERROR",
                evidence={"error": str(e), "code": e.response["Error"]["Code"]},
            )
        ]


@check("LOG-003")
def check_aws_config_recorder(ctx: ScanContext) -> List[Finding]:
    """LOG-003: AWS Config recorder enabled."""
    findings = []
    for region in ctx.regions:
        cfg_client = ctx.get_client("config", region_name=region)
        try:
            status_res = cfg_client.describe_configuration_recorder_status().get(
                "ConfigurationRecordersStatus", []
            )
            if not status_res:
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="LOG-003",
                        resource_id=f"arn:aws:config:{region}:{ctx.account_id}:recorder",
                        status="FAIL",
                        evidence={"message": f"No AWS Config recorder configured in {region}."},
                        region=region,
                    )
                )
                continue

            for rec in status_res:
                name = rec.get("name", "default")
                recording = rec.get("recording", False)
                status = "PASS" if recording else "FAIL"
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="LOG-003",
                        resource_id=f"arn:aws:config:{region}:{ctx.account_id}:recorder/{name}",
                        status=status,
                        evidence=rec,
                        region=region,
                    )
                )
        except ClientError as e:
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="LOG-003",
                    resource_id=f"config:recorder:{region}",
                    status="ERROR",
                    evidence={"error": str(e), "code": e.response["Error"]["Code"]},
                    region=region,
                )
            )

    return findings


@check("LOG-004")
def check_guardduty_enabled(ctx: ScanContext) -> List[Finding]:
    """LOG-004: Amazon GuardDuty detector enabled."""
    findings = []
    for region in ctx.regions:
        gd = ctx.get_client("guardduty", region_name=region)
        try:
            detector_ids = gd.list_detectors().get("DetectorIds", [])
            if not detector_ids:
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="LOG-004",
                        resource_id=f"arn:aws:guardduty:{region}:{ctx.account_id}:detector",
                        status="FAIL",
                        evidence={"message": f"GuardDuty is disabled (no detectors) in {region}."},
                        region=region,
                    )
                )
                continue

            for d_id in detector_ids:
                try:
                    det = gd.get_detector(DetectorId=d_id)
                    enabled = det.get("Status") == "ENABLED"
                    status = "PASS" if enabled else "FAIL"
                    findings.append(
                        _make_finding(
                            ctx=ctx,
                            check_id="LOG-004",
                            resource_id=f"arn:aws:guardduty:{region}:{ctx.account_id}:detector/{d_id}",
                            status=status,
                            evidence=det,
                            region=region,
                        )
                    )
                except ClientError as e:
                    findings.append(
                        _make_finding(
                            ctx=ctx,
                            check_id="LOG-004",
                            resource_id=f"guardduty:{region}:{d_id}",
                            status="ERROR",
                            evidence={"error": str(e)},
                            region=region,
                        )
                    )
        except ClientError as e:
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="LOG-004",
                    resource_id=f"guardduty:{region}",
                    status="ERROR",
                    evidence={"error": str(e), "code": e.response["Error"]["Code"]},
                    region=region,
                )
            )

    return findings
