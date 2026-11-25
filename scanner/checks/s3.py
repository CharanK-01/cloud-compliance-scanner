"""S3 Security Checks (S3-001 through S3-006)."""

import json
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
    service = meta.service if meta else "s3"
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


def _get_all_buckets(ctx: ScanContext) -> List[Dict[str, Any]]:
    """List all S3 buckets for the account with cached region."""
    if hasattr(ctx, "_s3_buckets"):
        return getattr(ctx, "_s3_buckets")

    s3 = ctx.get_client("s3")
    try:
        res = s3.list_buckets()
        buckets = res.get("Buckets", [])
        setattr(ctx, "_s3_buckets", buckets)
        return buckets
    except Exception:
        setattr(ctx, "_s3_buckets", [])
        return []


def _get_bucket_region(ctx: ScanContext, bucket_name: str) -> str:
    """Get location constraint for a bucket, mapping None or EU to region names."""
    cache_key = f"_bucket_region_{bucket_name}"
    if hasattr(ctx, cache_key):
        return getattr(ctx, cache_key)

    s3 = ctx.get_client("s3")
    try:
        loc = s3.get_bucket_location(Bucket=bucket_name).get("LocationConstraint")
        if not loc:
            region = "us-east-1"
        elif loc == "EU":
            region = "eu-west-1"
        else:
            region = loc
    except Exception:
        region = "us-east-1"

    setattr(ctx, cache_key, region)
    return region


@check("S3-001")
def check_s3_block_public_access(ctx: ScanContext) -> List[Finding]:
    """S3-001: Block Public Access enabled at bucket and account level."""
    s3 = ctx.get_client("s3")
    buckets = _get_all_buckets(ctx)
    findings = []

    # 1. Account level Block Public Access
    s3control = ctx.get_client("s3control")
    account_bpa_status = "UNKNOWN"
    account_evidence = {}
    try:
        res = s3control.get_public_access_block(AccountId=ctx.account_id)
        cfg = res.get("PublicAccessBlockConfiguration", {})
        all_true = all([
            cfg.get("BlockPublicAcls", False),
            cfg.get("IgnorePublicAcls", False),
            cfg.get("BlockPublicPolicy", False),
            cfg.get("RestrictPublicBuckets", False),
        ])
        account_bpa_status = "PASS" if all_true else "FAIL"
        account_evidence = cfg
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("NoSuchPublicAccessBlockConfiguration", "AccessDeniedException"):
            account_bpa_status = "FAIL" if code == "NoSuchPublicAccessBlockConfiguration" else "ERROR"
            account_evidence = {"error": str(e), "code": code}
        else:
            account_bpa_status = "ERROR"
            account_evidence = {"error": str(e), "code": code}

    findings.append(
        _make_finding(
            ctx=ctx,
            check_id="S3-001",
            resource_id=f"arn:aws:s3:::{ctx.account_id}:account-bpa",
            status=account_bpa_status,
            evidence=account_evidence,
        )
    )

    # 2. Bucket level Block Public Access
    if not buckets:
        return findings

    for b in buckets:
        name = b["Name"]
        arn = f"arn:aws:s3:::{name}"
        b_region = _get_bucket_region(ctx, name)
        b_s3 = ctx.get_client("s3", region_name=b_region)
        try:
            res = b_s3.get_public_access_block(Bucket=name)
            cfg = res.get("PublicAccessBlockConfiguration", {})
            all_true = all([
                cfg.get("BlockPublicAcls", False),
                cfg.get("IgnorePublicAcls", False),
                cfg.get("BlockPublicPolicy", False),
                cfg.get("RestrictPublicBuckets", False),
            ])
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="S3-001",
                    resource_id=arn,
                    status="PASS" if all_true else "FAIL",
                    evidence=cfg,
                    region=b_region,
                )
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="S3-001",
                        resource_id=arn,
                        status="FAIL",
                        evidence={"message": "No Block Public Access configured for bucket."},
                        region=b_region,
                    )
                )
            else:
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="S3-001",
                        resource_id=arn,
                        status="ERROR",
                        evidence={"error": str(e), "code": code},
                        region=b_region,
                    )
                )

    return findings


@check("S3-002")
def check_s3_no_public_access(ctx: ScanContext) -> List[Finding]:
    """S3-002: No public ACL or policy allowing public access."""
    buckets = _get_all_buckets(ctx)
    if not buckets:
        return [
            _make_finding(
                ctx=ctx,
                check_id="S3-002",
                resource_id="s3:buckets",
                status="PASS",
                evidence={"message": "No buckets present."},
            )
        ]

    public_uris = [
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    ]
    findings = []

    for b in buckets:
        name = b["Name"]
        arn = f"arn:aws:s3:::{name}"
        b_region = _get_bucket_region(ctx, name)
        b_s3 = ctx.get_client("s3", region_name=b_region)
        is_public_acl = False
        is_public_policy = False
        evidence = {}

        # 1. Check ACL
        try:
            acl = b_s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in public_uris:
                    is_public_acl = True
                    evidence["public_grant"] = grant
                    break
        except ClientError as e:
            evidence["acl_error"] = str(e)

        # 2. Check Policy Status
        try:
            pol_status = b_s3.get_bucket_policy_status(Bucket=name)
            if pol_status.get("PolicyStatus", {}).get("IsPublic", False):
                is_public_policy = True
                evidence["is_public_policy"] = True
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code != "NoSuchBucketPolicy":
                evidence["policy_error"] = str(e)

        status = "FAIL" if (is_public_acl or is_public_policy) else "PASS"
        evidence["is_public_acl"] = is_public_acl
        evidence["is_public_policy"] = is_public_policy

        findings.append(
            _make_finding(
                ctx=ctx,
                check_id="S3-002",
                resource_id=arn,
                status=status,
                evidence=evidence,
                region=b_region,
            )
        )

    return findings


@check("S3-003")
def check_s3_encryption(ctx: ScanContext) -> List[Finding]:
    """S3-003: Default encryption enabled (prefer SSE-KMS or SSE-S3)."""
    buckets = _get_all_buckets(ctx)
    if not buckets:
        return [
            _make_finding(
                ctx=ctx,
                check_id="S3-003",
                resource_id="s3:buckets",
                status="PASS",
                evidence={"message": "No buckets present."},
            )
        ]

    findings = []
    for b in buckets:
        name = b["Name"]
        arn = f"arn:aws:s3:::{name}"
        b_region = _get_bucket_region(ctx, name)
        b_s3 = ctx.get_client("s3", region_name=b_region)
        try:
            enc = b_s3.get_bucket_encryption(Bucket=name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            # If rules present, it's encrypted
            algorithm = "AES256"
            if rules:
                algorithm = (
                    rules[0]
                    .get("ApplyServerSideEncryptionByDefault", {})
                    .get("SSEAlgorithm", "AES256")
                )
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="S3-003",
                    resource_id=arn,
                    status="PASS",
                    evidence={"algorithm": algorithm, "rules": rules},
                    region=b_region,
                )
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="S3-003",
                        resource_id=arn,
                        status="FAIL",
                        evidence={"message": "Default encryption is not enabled."},
                        region=b_region,
                    )
                )
            else:
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="S3-003",
                        resource_id=arn,
                        status="ERROR",
                        evidence={"error": str(e), "code": code},
                        region=b_region,
                    )
                )

    return findings


@check("S3-004")
def check_s3_versioning(ctx: ScanContext) -> List[Finding]:
    """S3-004: Versioning enabled."""
    buckets = _get_all_buckets(ctx)
    if not buckets:
        return [
            _make_finding(
                ctx=ctx,
                check_id="S3-004",
                resource_id="s3:buckets",
                status="PASS",
                evidence={"message": "No buckets present."},
            )
        ]

    findings = []
    for b in buckets:
        name = b["Name"]
        arn = f"arn:aws:s3:::{name}"
        b_region = _get_bucket_region(ctx, name)
        b_s3 = ctx.get_client("s3", region_name=b_region)
        try:
            ver = b_s3.get_bucket_versioning(Bucket=name)
            status_val = ver.get("Status", "Disabled")
            status = "PASS" if status_val == "Enabled" else "FAIL"
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="S3-004",
                    resource_id=arn,
                    status=status,
                    evidence={"VersioningStatus": status_val},
                    region=b_region,
                )
            )
        except ClientError as e:
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="S3-004",
                    resource_id=arn,
                    status="ERROR",
                    evidence={"error": str(e)},
                    region=b_region,
                )
            )

    return findings


@check("S3-005")
def check_s3_access_logging(ctx: ScanContext) -> List[Finding]:
    """S3-005: Access logging enabled."""
    buckets = _get_all_buckets(ctx)
    if not buckets:
        return [
            _make_finding(
                ctx=ctx,
                check_id="S3-005",
                resource_id="s3:buckets",
                status="PASS",
                evidence={"message": "No buckets present."},
            )
        ]

    findings = []
    for b in buckets:
        name = b["Name"]
        arn = f"arn:aws:s3:::{name}"
        b_region = _get_bucket_region(ctx, name)
        b_s3 = ctx.get_client("s3", region_name=b_region)
        try:
            log_res = b_s3.get_bucket_logging(Bucket=name)
            enabled = "LoggingEnabled" in log_res
            status = "PASS" if enabled else "FAIL"
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="S3-005",
                    resource_id=arn,
                    status=status,
                    evidence=log_res.get("LoggingEnabled", {"message": "Logging disabled"}),
                    region=b_region,
                )
            )
        except ClientError as e:
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="S3-005",
                    resource_id=arn,
                    status="ERROR",
                    evidence={"error": str(e)},
                    region=b_region,
                )
            )

    return findings


@check("S3-006")
def check_s3_tls_enforced(ctx: ScanContext) -> List[Finding]:
    """S3-006: TLS enforced (bucket policy denies aws:SecureTransport=false)."""
    buckets = _get_all_buckets(ctx)
    if not buckets:
        return [
            _make_finding(
                ctx=ctx,
                check_id="S3-006",
                resource_id="s3:buckets",
                status="PASS",
                evidence={"message": "No buckets present."},
            )
        ]

    findings = []
    for b in buckets:
        name = b["Name"]
        arn = f"arn:aws:s3:::{name}"
        b_region = _get_bucket_region(ctx, name)
        b_s3 = ctx.get_client("s3", region_name=b_region)
        try:
            pol_res = b_s3.get_bucket_policy(Bucket=name)
            policy = json.loads(pol_res.get("Policy", "{}"))
            statements = policy.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            tls_denied = False
            for stmt in statements:
                if stmt.get("Effect") == "Deny":
                    cond = stmt.get("Condition", {})
                    # Look for Bool condition with aws:SecureTransport == false
                    bool_cond = cond.get("Bool", {})
                    sec_transport = bool_cond.get("aws:SecureTransport")
                    if sec_transport in ("false", False, ["false"]):
                        tls_denied = True
                        break

            status = "PASS" if tls_denied else "FAIL"
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="S3-006",
                    resource_id=arn,
                    status=status,
                    evidence={"tls_denied_policy_present": tls_denied},
                    region=b_region,
                )
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchBucketPolicy":
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="S3-006",
                        resource_id=arn,
                        status="FAIL",
                        evidence={"message": "No bucket policy attached; TLS not enforced."},
                        region=b_region,
                    )
                )
            else:
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="S3-006",
                        resource_id=arn,
                        status="ERROR",
                        evidence={"error": str(e), "code": code},
                        region=b_region,
                    )
                )

    return findings
