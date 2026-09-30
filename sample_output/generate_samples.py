import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.models import Finding
from scanner.reports.exporters import export_csv, export_json
from scanner.reports.html_report import generate_html_report
from scanner.scoring import build_scan_summary
from scanner.session import load_controls_mapping

SAMPLE_DIR = Path(__file__).parent
CONTROLS_PATH = Path(__file__).parent.parent / "scanner" / "mappings" / "controls.yaml"


def generate_samples():
    controls = load_controls_mapping(CONTROLS_PATH)

    # 1. BEFORE FINDINGS (Simulated insecure audit)
    before_statuses = {
        "IAM-001": ("FAIL", "arn:aws:iam::123456789012:root", {"AccountMFAEnabled": 0}),
        "IAM-002": ("FAIL", "arn:aws:iam::123456789012:root", {"AccountAccessKeysPresent": 1}),
        "IAM-003": ("FAIL", "arn:aws:iam::123456789012:user/admin-bob", {"mfa_active": False}),
        "IAM-004": ("FAIL", "arn:aws:iam::123456789012:password-policy", {"MinimumPasswordLength": 6}),
        "IAM-005": ("FAIL", "arn:aws:iam::123456789012:user/dev:key-1", {"age_days": 182}),
        "IAM-006": ("FAIL", "arn:aws:iam::123456789012:user/contractor:password", {"days_unused": 140}),
        "IAM-007": ("FAIL", "arn:aws:iam::123456789012:policy/WildcardAdmin", {"Action": "*", "Resource": "*"}),
        "IAM-008": ("FAIL", "arn:aws:iam::123456789012:user/dev", {"attached_managed_policies": ["PowerUserAccess"]}),
        "S3-001": ("FAIL", "arn:aws:s3:::compliance-lab-insecure-123456789012", {"BlockPublicAcls": False}),
        "S3-002": ("FAIL", "arn:aws:s3:::compliance-lab-insecure-123456789012", {"is_public_policy": True}),
        "S3-003": ("FAIL", "arn:aws:s3:::compliance-lab-insecure-123456789012", {"message": "No default encryption"}),
        "S3-004": ("FAIL", "arn:aws:s3:::compliance-lab-insecure-123456789012", {"VersioningStatus": "Disabled"}),
        "S3-005": ("FAIL", "arn:aws:s3:::compliance-lab-insecure-123456789012", {"message": "Logging disabled"}),
        "S3-006": ("FAIL", "arn:aws:s3:::compliance-lab-insecure-123456789012", {"tls_denied_policy_present": False}),
        "NET-001": ("FAIL", "arn:aws:ec2:us-east-1:123456789012:security-group/sg-01a2b3c4d", {"open_rules_count": 1, "port": 22}),
        "NET-002": ("FAIL", "arn:aws:ec2:us-east-1:123456789012:security-group/sg-01a2b3c4d", {"all_ports_open": True}),
        "NET-003": ("FAIL", "arn:aws:ec2:us-east-1:123456789012:ebs-encryption", {"EbsEncryptionByDefault": False}),
        "NET-004": ("PASS", "arn:aws:ec2:us-east-1:123456789012:volume/vol-0987654321", {"Encrypted": True}),
        "NET-005": ("FAIL", "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0a1b2c3d4e5f", {"FlowLogsActive": False}),
        "LOG-001": ("PASS", "arn:aws:cloudtrail:us-east-1:123456789012:trail/MainTrail", {"IsLogging": True, "IsMultiRegionTrail": True}),
        "LOG-002": ("PASS", "arn:aws:cloudtrail:us-east-1:123456789012:trail/MainTrail", {"LogFileValidationEnabled": True}),
        "LOG-003": ("FAIL", "arn:aws:config:us-east-1:123456789012:recorder", {"message": "No Config recorder configured"}),
        "LOG-004": ("PASS", "arn:aws:guardduty:us-east-1:123456789012:detector/det-123", {"Status": "ENABLED"}),
        "KMS-001": ("PASS", "kms:customer-keys", {"message": "All keys have rotation enabled"}),
        "RDS-001": ("PASS", "rds:instances", {"message": "All storage encrypted"}),
        "RDS-002": ("PASS", "rds:instances", {"message": "No public databases"}),
        "RDS-003": ("PASS", "rds:instances", {"message": "Retention >= 7 days"}),
        "RDS-004": ("PASS", "rds:instances", {"message": "Multi-AZ configured"}),
    }

    before_findings = []
    for cid, (status, resid, evid) in before_statuses.items():
        meta = controls[cid]
        before_findings.append(
            Finding(
                check_id=cid,
                title=meta.title,
                service=meta.service,
                region="us-east-1",
                resource_id=resid,
                status=status,
                severity=meta.severity,
                risk_score=meta.risk_score,
                iso_controls=meta.iso_controls,
                evidence=evid,
                remediation=meta.remediation,
                rationale=meta.rationale,
            )
        )

    before_summary = build_scan_summary(
        account_id="123456789012",
        regions=["us-east-1"],
        duration_seconds=4.82,
        findings=before_findings,
        attempted_checks_count=len(before_findings),
    )

    b_json, b_hash = export_json(before_summary, SAMPLE_DIR / "before.json")
    export_csv(before_summary, SAMPLE_DIR / "before.csv")
    generate_html_report(before_summary, SAMPLE_DIR / "before.html", json_sha256=b_hash)
    print(f"[+] Generated Before Report: Posture Score = {before_summary.overall_posture_score}%")

    # 2. AFTER FINDINGS (Remediated posture)
    after_findings = []
    for cid, (status, resid, evid) in before_statuses.items():
        meta = controls[cid]
        # Most failed findings remediated to PASS
        if cid in ("IAM-001", "IAM-002", "IAM-003", "IAM-004", "IAM-007", "IAM-008",
                    "S3-001", "S3-002", "S3-003", "S3-004", "S3-006",
                    "NET-001", "NET-002", "NET-003", "NET-005", "LOG-003"):
            new_status = "PASS"
            new_evid = {"remediated": True, "evidence": "Compliant configuration verified"}
        elif cid in ("IAM-005", "S3-005"):  # Left 2 low/med findings as realistic ongoing backlog
            new_status = "FAIL"
            new_evid = evid
        else:
            new_status = status
            new_evid = evid

        after_findings.append(
            Finding(
                check_id=cid,
                title=meta.title,
                service=meta.service,
                region="us-east-1",
                resource_id=resid,
                status=new_status,
                severity=meta.severity,
                risk_score=meta.risk_score,
                iso_controls=meta.iso_controls,
                evidence=new_evid,
                remediation=meta.remediation,
                rationale=meta.rationale,
            )
        )

    after_summary = build_scan_summary(
        account_id="123456789012",
        regions=["us-east-1"],
        duration_seconds=4.31,
        findings=after_findings,
        attempted_checks_count=len(after_findings),
    )

    a_json, a_hash = export_json(after_summary, SAMPLE_DIR / "after.json")
    export_csv(after_summary, SAMPLE_DIR / "after.csv")
    generate_html_report(after_summary, SAMPLE_DIR / "after.html", json_sha256=a_hash)
    print(f"[+] Generated After Report: Posture Score = {after_summary.overall_posture_score}%")


if __name__ == "__main__":
    generate_samples()
