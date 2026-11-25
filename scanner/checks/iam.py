"""IAM Security Checks (IAM-001 through IAM-008)."""

import csv
import io
import time
from datetime import datetime, timezone
from typing import Any, Dict, List
from botocore.exceptions import ClientError

from scanner.models import Finding, ScanContext
from scanner.registry import check


def _get_credential_report(ctx: ScanContext) -> List[Dict[str, str]]:
    """Generate (poll until ready) and parse IAM credential report CSV."""
    if hasattr(ctx, "_credential_report"):
        return getattr(ctx, "_credential_report")

    iam = ctx.get_client("iam")
    # Generate credential report (whitelisted write/generation call)
    try:
        gen = iam.generate_credential_report()
        state = gen.get("State", "")
        max_attempts = 10
        attempts = 0
        while state != "COMPLETE" and attempts < max_attempts:
            time.sleep(1)
            gen = iam.generate_credential_report()
            state = gen.get("State", "")
            attempts += 1
    except ClientError:
        pass

    try:
        report_res = iam.get_credential_report()
        content = report_res["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        rows = list(reader)
        setattr(ctx, "_credential_report", rows)
        return rows
    except Exception:
        setattr(ctx, "_credential_report", [])
        return []


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
    service = meta.service if meta else "iam"
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


@check("IAM-001")
def check_root_mfa(ctx: ScanContext) -> List[Finding]:
    """IAM-001: Root account has MFA enabled."""
    iam = ctx.get_client("iam")
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1
        status = "PASS" if mfa_enabled else "FAIL"
        return [
            _make_finding(
                ctx=ctx,
                check_id="IAM-001",
                resource_id=f"arn:aws:iam::{ctx.account_id}:root",
                status=status,
                evidence={"AccountMFAEnabled": summary.get("AccountMFAEnabled", 0)},
            )
        ]
    except ClientError as e:
        return [
            _make_finding(
                ctx=ctx,
                check_id="IAM-001",
                resource_id=f"arn:aws:iam::{ctx.account_id}:root",
                status="ERROR",
                evidence={"error": str(e), "code": e.response["Error"]["Code"]},
            )
        ]


@check("IAM-002")
def check_no_root_access_keys(ctx: ScanContext) -> List[Finding]:
    """IAM-002: No root account active access keys."""
    iam = ctx.get_client("iam")
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        keys_present = summary.get("AccountAccessKeysPresent", 0)
        status = "PASS" if keys_present == 0 else "FAIL"
        return [
            _make_finding(
                ctx=ctx,
                check_id="IAM-002",
                resource_id=f"arn:aws:iam::{ctx.account_id}:root",
                status=status,
                evidence={"AccountAccessKeysPresent": keys_present},
            )
        ]
    except ClientError as e:
        return [
            _make_finding(
                ctx=ctx,
                check_id="IAM-002",
                resource_id=f"arn:aws:iam::{ctx.account_id}:root",
                status="ERROR",
                evidence={"error": str(e), "code": e.response["Error"]["Code"]},
            )
        ]


@check("IAM-003")
def check_console_users_mfa(ctx: ScanContext) -> List[Finding]:
    """IAM-003: All console users have MFA enabled."""
    rows = _get_credential_report(ctx)
    if not rows:
        # Fallback: inspect users via list_users & list_mfa_devices
        iam = ctx.get_client("iam")
        findings = []
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]
                    try:
                        # Check login profile
                        iam.get_login_profile(UserName=username)
                        mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                        status = "PASS" if len(mfa_devices) > 0 else "FAIL"
                        findings.append(
                            _make_finding(
                                ctx=ctx,
                                check_id="IAM-003",
                                resource_id=user["Arn"],
                                status=status,
                                evidence={"console_access": True, "mfa_devices_count": len(mfa_devices)},
                            )
                        )
                    except ClientError as e:
                        if e.response["Error"]["Code"] == "NoSuchEntity":
                            continue  # No console password
                        findings.append(
                            _make_finding(
                                ctx=ctx,
                                check_id="IAM-003",
                                resource_id=user["Arn"],
                                status="ERROR",
                                evidence={"error": str(e)},
                            )
                        )
            if not findings:
                return [
                    _make_finding(
                        ctx=ctx,
                        check_id="IAM-003",
                        resource_id="iam:users",
                        status="PASS",
                        evidence={"message": "No console users detected."},
                    )
                ]
            return findings
        except ClientError as e:
            return [
                _make_finding(
                    ctx=ctx,
                    check_id="IAM-003",
                    resource_id="iam:users",
                    status="ERROR",
                    evidence={"error": str(e)},
                )
            ]

    findings = []
    console_users_found = False
    for row in rows:
        user = row.get("user")
        if user == "<root_account>":
            continue
        password_enabled = row.get("password_enabled", "false").lower() == "true"
        if password_enabled:
            console_users_found = True
            mfa_active = row.get("mfa_active", "false").lower() == "true"
            status = "PASS" if mfa_active else "FAIL"
            findings.append(
                _make_finding(
                    ctx=ctx,
                    check_id="IAM-003",
                    resource_id=row.get("arn", user),
                    status=status,
                    evidence={"password_enabled": True, "mfa_active": mfa_active},
                )
            )

    if not console_users_found:
        return [
            _make_finding(
                ctx=ctx,
                check_id="IAM-003",
                resource_id="iam:users",
                status="PASS",
                evidence={"message": "No IAM users with console password enabled."},
            )
        ]
    return findings


@check("IAM-004")
def check_password_policy(ctx: ScanContext) -> List[Finding]:
    """IAM-004: Strong account password policy enforced."""
    iam = ctx.get_client("iam")
    resource_id = f"arn:aws:iam::{ctx.account_id}:password-policy"
    try:
        policy = iam.get_account_password_policy().get("PasswordPolicy", {})
        min_len = policy.get("MinimumPasswordLength", 0) >= 14
        req_sym = policy.get("RequireSymbols", False)
        req_num = policy.get("RequireNumbers", False)
        req_upper = policy.get("RequireUppercaseCharacters", False)
        req_lower = policy.get("RequireLowercaseCharacters", False)
        reuse_prev = policy.get("PasswordReusePrevention", 0) >= 24
        max_age = 0 < policy.get("MaxPasswordAge", 0) <= 90

        compliant = all([min_len, req_sym, req_num, req_upper, req_lower, reuse_prev, max_age])
        status = "PASS" if compliant else "FAIL"
        return [
            _make_finding(
                ctx=ctx,
                check_id="IAM-004",
                resource_id=resource_id,
                status=status,
                evidence=policy,
            )
        ]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return [
                _make_finding(
                    ctx=ctx,
                    check_id="IAM-004",
                    resource_id=resource_id,
                    status="FAIL",
                    evidence={"message": "No account password policy is set."},
                )
            ]
        return [
            _make_finding(
                ctx=ctx,
                check_id="IAM-004",
                resource_id=resource_id,
                status="ERROR",
                evidence={"error": str(e), "code": e.response["Error"]["Code"]},
            )
        ]


@check("IAM-005")
def check_access_keys_rotated_90_days(ctx: ScanContext) -> List[Finding]:
    """IAM-005: Access keys rotated within 90 days."""
    rows = _get_credential_report(ctx)
    now = datetime.now(timezone.utc)
    findings = []

    if rows:
        for row in rows:
            user = row.get("user")
            for k in ("1", "2"):
                active = row.get(f"access_key_{k}_active", "false").lower() == "true"
                if active:
                    rot_str = row.get(f"access_key_{k}_last_rotated", "N/A")
                    try:
                        rot_date = datetime.fromisoformat(rot_str.replace("Z", "+00:00"))
                        age_days = (now - rot_date).days
                        status = "PASS" if age_days <= 90 else "FAIL"
                        findings.append(
                            _make_finding(
                                ctx=ctx,
                                check_id="IAM-005",
                                resource_id=f"{row.get('arn', user)}:key-{k}",
                                status=status,
                                evidence={"key_index": k, "age_days": age_days, "last_rotated": rot_str},
                            )
                        )
                    except Exception:
                        pass
    else:
        iam = ctx.get_client("iam")
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]
                    keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                    for k in keys:
                        if k["Status"] == "Active":
                            age_days = (now - k["CreateDate"]).days
                            status = "PASS" if age_days <= 90 else "FAIL"
                            findings.append(
                                _make_finding(
                                    ctx=ctx,
                                    check_id="IAM-005",
                                    resource_id=f"{user['Arn']}:{k['AccessKeyId']}",
                                    status=status,
                                    evidence={"access_key_id": k["AccessKeyId"], "age_days": age_days},
                                )
                            )
        except ClientError as e:
            return [
                _make_finding(
                    ctx=ctx,
                    check_id="IAM-005",
                    resource_id="iam:access-keys",
                    status="ERROR",
                    evidence={"error": str(e)},
                )
            ]

    if not findings:
        return [
            _make_finding(
                ctx=ctx,
                check_id="IAM-005",
                resource_id="iam:access-keys",
                status="PASS",
                evidence={"message": "No active IAM access keys found."},
            )
        ]
    return findings


@check("IAM-006")
def check_unused_credentials_90_days(ctx: ScanContext) -> List[Finding]:
    """IAM-006: Unused credentials (90+ days)."""
    rows = _get_credential_report(ctx)
    now = datetime.now(timezone.utc)
    findings = []

    if rows:
        for row in rows:
            user = row.get("user")
            arn = row.get("arn", user)
            # Check password
            if row.get("password_enabled", "false").lower() == "true":
                last_used = row.get("password_last_used", "N/A")
                if last_used in ("N/A", "no_information"):
                    status = "FAIL"
                    age_days = 999
                else:
                    try:
                        p_date = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                        age_days = (now - p_date).days
                        status = "PASS" if age_days <= 90 else "FAIL"
                    except Exception:
                        age_days = 999
                        status = "FAIL"
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="IAM-006",
                        resource_id=f"{arn}:password",
                        status=status,
                        evidence={"credential_type": "password", "last_used": last_used, "days_unused": age_days},
                    )
                )

            # Check active keys
            for k in ("1", "2"):
                if row.get(f"access_key_{k}_active", "false").lower() == "true":
                    last_used = row.get(f"access_key_{k}_last_used_date", "N/A")
                    if last_used in ("N/A", "N/A "):
                        # Never used -> check rotation / creation date
                        rot_str = row.get(f"access_key_{k}_last_rotated", "N/A")
                        try:
                            r_date = datetime.fromisoformat(rot_str.replace("Z", "+00:00"))
                            age_days = (now - r_date).days
                            status = "PASS" if age_days <= 90 else "FAIL"
                        except Exception:
                            age_days = 999
                            status = "FAIL"
                    else:
                        try:
                            k_date = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                            age_days = (now - k_date).days
                            status = "PASS" if age_days <= 90 else "FAIL"
                        except Exception:
                            age_days = 999
                            status = "FAIL"
                    findings.append(
                        _make_finding(
                            ctx=ctx,
                            check_id="IAM-006",
                            resource_id=f"{arn}:key-{k}",
                            status=status,
                            evidence={"credential_type": f"access_key_{k}", "last_used": last_used, "days_unused": age_days},
                        )
                    )

    if not findings:
        return [
            _make_finding(
                ctx=ctx,
                check_id="IAM-006",
                resource_id="iam:credentials",
                status="PASS",
                evidence={"message": "No active credentials to evaluate."},
            )
        ]
    return findings


@check("IAM-007")
def check_no_wildcard_admin_policies(ctx: ScanContext) -> List[Finding]:
    """IAM-007: No wildcard *:* admin policies attached."""
    iam = ctx.get_client("iam")
    findings = []
    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local", OnlyAttached=True):
            for policy in page.get("Policies", []):
                policy_arn = policy["Arn"]
                default_version = policy.get("DefaultVersionId")
                version_res = iam.get_policy_version(PolicyArn=policy_arn, VersionId=default_version)
                doc = version_res.get("PolicyVersion", {}).get("Document", {})
                statements = doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                has_wildcard = False
                for stmt in statements:
                    if stmt.get("Effect") == "Allow":
                        action = stmt.get("Action", [])
                        resource = stmt.get("Resource", [])
                        if isinstance(action, str):
                            action = [action]
                        if isinstance(resource, str):
                            resource = [resource]
                        if ("*" in action or "*:*" in action) and "*" in resource:
                            # Verify no condition block
                            if not stmt.get("Condition"):
                                has_wildcard = True
                                break

                status = "FAIL" if has_wildcard else "PASS"
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="IAM-007",
                        resource_id=policy_arn,
                        status=status,
                        evidence={"PolicyName": policy.get("PolicyName"), "HasWildcardAdmin": has_wildcard},
                    )
                )

        if not findings:
            return [
                _make_finding(
                    ctx=ctx,
                    check_id="IAM-007",
                    resource_id="iam:customer-managed-policies",
                    status="PASS",
                    evidence={"message": "No attached customer-managed policies found."},
                )
            ]
        return findings
    except ClientError as e:
        return [
            _make_finding(
                ctx=ctx,
                check_id="IAM-007",
                resource_id="iam:policies",
                status="ERROR",
                evidence={"error": str(e), "code": e.response["Error"]["Code"]},
            )
        ]


@check("IAM-008")
def check_user_policy_attachment(ctx: ScanContext) -> List[Finding]:
    """IAM-008: Policies attached to groups/roles, not directly to users."""
    iam = ctx.get_client("iam")
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                arn = user["Arn"]
                attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
                inline = iam.list_user_policies(UserName=username).get("PolicyNames", [])
                total_direct = len(attached) + len(inline)
                status = "PASS" if total_direct == 0 else "FAIL"
                findings.append(
                    _make_finding(
                        ctx=ctx,
                        check_id="IAM-008",
                        resource_id=arn,
                        status=status,
                        evidence={
                            "attached_managed_policies": [p["PolicyName"] for p in attached],
                            "inline_policies": inline,
                        },
                    )
                )

        if not findings:
            return [
                _make_finding(
                    ctx=ctx,
                    check_id="IAM-008",
                    resource_id="iam:users",
                    status="PASS",
                    evidence={"message": "No IAM users found."},
                )
            ]
        return findings
    except ClientError as e:
        return [
            _make_finding(
                ctx=ctx,
                check_id="IAM-008",
                resource_id="iam:users",
                status="ERROR",
                evidence={"error": str(e), "code": e.response["Error"]["Code"]},
            )
        ]
