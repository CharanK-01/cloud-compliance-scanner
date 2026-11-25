"""RDS Security Checks (RDS-001 through RDS-004)."""

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
    service = meta.service if meta else "rds"
    severity = meta.severity if meta else "Medium"
    risk_score = meta.risk_score if meta else 8
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


def _get_all_rds_instances(ctx: ScanContext) -> Dict[str, List[Dict[str, Any]]]:
    """Fetch all DB instances grouped by region."""
    if hasattr(ctx, "_rds_instances_by_region"):
        return getattr(ctx, "_rds_instances_by_region")

    by_region = {}
    for region in ctx.regions:
        rds = ctx.get_client("rds", region_name=region)
        try:
            instances = []
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                instances.extend(page.get("DBInstances", []))
            by_region[region] = instances
        except Exception:
            by_region[region] = []

    setattr(ctx, "_rds_instances_by_region", by_region)
    return by_region


@check("RDS-001")
def check_rds_storage_encrypted(ctx: ScanContext) -> List[Finding]:
    """RDS-001: Storage encrypted."""
    instances_by_region = _get_all_rds_instances(ctx)
    findings = []
    total_instances = 0

    for region, instances in instances_by_region.items():
        total_instances += len(instances)
        for db in instances:
            db_id = db["DBInstanceIdentifier"]
            arn = db.get("DBInstanceArn", f"arn:aws:rds:{region}:{ctx.account_id}:db:{db_id}")
            encrypted = db.get("StorageEncrypted", False)
            status = "PASS" if encrypted else "FAIL"
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="RDS-001",
                    resource_id=arn,
                    status=status,
                    evidence={"DBInstanceIdentifier": db_id, "StorageEncrypted": encrypted, "KmsKeyId": db.get("KmsKeyId")},
                    region=region,
                )
            )

    if total_instances == 0:
        return [
            _make_finding(
                ctx=ctx,
                check_id="RDS-001",
                resource_id="rds:instances",
                status="PASS",
                evidence={"message": "No RDS instances present."},
                region="global",
            )
        ]
    return findings


@check("RDS-002")
def check_rds_not_public(ctx: ScanContext) -> List[Finding]:
    """RDS-002: Not publicly accessible."""
    instances_by_region = _get_all_rds_instances(ctx)
    findings = []
    total_instances = 0

    for region, instances in instances_by_region.items():
        total_instances += len(instances)
        for db in instances:
            db_id = db["DBInstanceIdentifier"]
            arn = db.get("DBInstanceArn", f"arn:aws:rds:{region}:{ctx.account_id}:db:{db_id}")
            public = db.get("PubliclyAccessible", False)
            status = "PASS" if not public else "FAIL"
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="RDS-002",
                    resource_id=arn,
                    status=status,
                    evidence={"DBInstanceIdentifier": db_id, "PubliclyAccessible": public},
                    region=region,
                )
            )

    if total_instances == 0:
        return [
            _make_finding(
                ctx=ctx,
                check_id="RDS-002",
                resource_id="rds:instances",
                status="PASS",
                evidence={"message": "No RDS instances present."},
                region="global",
            )
        ]
    return findings


@check("RDS-003")
def check_rds_backup_retention(ctx: ScanContext) -> List[Finding]:
    """RDS-003: Backup retention >= 7 days."""
    instances_by_region = _get_all_rds_instances(ctx)
    findings = []
    total_instances = 0

    for region, instances in instances_by_region.items():
        total_instances += len(instances)
        for db in instances:
            db_id = db["DBInstanceIdentifier"]
            arn = db.get("DBInstanceArn", f"arn:aws:rds:{region}:{ctx.account_id}:db:{db_id}")
            retention = db.get("BackupRetentionPeriod", 0)
            status = "PASS" if retention >= 7 else "FAIL"
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="RDS-003",
                    resource_id=arn,
                    status=status,
                    evidence={"DBInstanceIdentifier": db_id, "BackupRetentionPeriod": retention},
                    region=region,
                )
            )

    if total_instances == 0:
        return [
            _make_finding(
                ctx=ctx,
                check_id="RDS-003",
                resource_id="rds:instances",
                status="PASS",
                evidence={"message": "No RDS instances present."},
                region="global",
            )
        ]
    return findings


@check("RDS-004")
def check_rds_multi_az(ctx: ScanContext) -> List[Finding]:
    """RDS-004: Multi-AZ configured (for high availability and business continuity)."""
    instances_by_region = _get_all_rds_instances(ctx)
    findings = []
    total_instances = 0

    for region, instances in instances_by_region.items():
        total_instances += len(instances)
        for db in instances:
            db_id = db["DBInstanceIdentifier"]
            arn = db.get("DBInstanceArn", f"arn:aws:rds:{region}:{ctx.account_id}:db:{db_id}")
            multi_az = db.get("MultiAZ", False)
            status = "PASS" if multi_az else "FAIL"
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="RDS-004",
                    resource_id=arn,
                    status=status,
                    evidence={"DBInstanceIdentifier": db_id, "MultiAZ": multi_az},
                    region=region,
                )
            )

    if total_instances == 0:
        return [
            _make_finding(
                ctx=ctx,
                check_id="RDS-004",
                resource_id="rds:instances",
                status="PASS",
                evidence={"message": "No RDS instances present."},
                region="global",
            )
        ]
    return findings
