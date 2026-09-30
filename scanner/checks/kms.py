"""KMS Security Checks (KMS-001)."""

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
    service = meta.service if meta else "kms"
    severity = meta.severity if meta else "Medium"
    risk_score = meta.risk_score if meta else 6
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


@check("KMS-001")
def check_kms_key_rotation(ctx: ScanContext) -> List[Finding]:
    """KMS-001: Customer-managed keys have rotation enabled."""
    findings = []
    total_customer_keys = 0

    for region in ctx.regions:
        kms = ctx.get_client("kms", region_name=region)
        try:
            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for key_entry in page.get("Keys", []):
                    key_id = key_entry["KeyId"]
                    try:
                        desc = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                        # Filter only customer-managed keys (not AWS managed)
                        if desc.get("KeyManager") != "CUSTOMER":
                            continue
                        if desc.get("KeyState") not in ("Enabled",):
                            continue
                        # Asymmetric keys do not support automatic rotation
                        if desc.get("KeySpec") not in ("SYMMETRIC_DEFAULT", None):
                            continue

                        total_customer_keys += 1
                        arn = desc.get("Arn", f"arn:aws:kms:{region}:{ctx.account_id}:key/{key_id}")
                        rot_res = kms.get_key_rotation_status(KeyId=key_id)
                        rot_enabled = rot_res.get("KeyRotationEnabled", False)
                        status = "PASS" if rot_enabled else "FAIL"

                        findings.append(
                            _make_finding(
                                ctx=ctx,
                                check_id="KMS-001",
                                resource_id=arn,
                                status=status,
                                evidence={
                                    "KeyId": key_id,
                                    "Description": desc.get("Description", ""),
                                    "KeyRotationEnabled": rot_enabled,
                                    "CreationDate": str(desc.get("CreationDate")),
                                },
                                region=region,
                            )
                        )
                    except ClientError as e:
                        findings.append(
                            _make_finding(
                                ctx=ctx,
                                check_id="KMS-001",
                                resource_id=f"kms:{region}:{key_id}",
                                status="ERROR",
                                evidence={"error": str(e)},
                                region=region,
                            )
                        )
        except ClientError as e:
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="KMS-001",
                    resource_id=f"kms:{region}",
                    status="ERROR",
                    evidence={"error": str(e), "code": e.response["Error"]["Code"]},
                    region=region,
                )
            )

    if total_customer_keys == 0 and not findings:
        return [
            _make_finding(
                ctx=ctx,
                check_id="KMS-001",
                resource_id="kms:customer-keys",
                status="PASS",
                evidence={"message": "No active customer-managed symmetric KMS keys found."},
                region="global",
            )
        ]

    return findings
