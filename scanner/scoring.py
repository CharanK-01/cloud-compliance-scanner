"""Risk calculation, compliance scoring, and ISO Annex A aggregation."""

from collections import defaultdict
from typing import Dict, List
from scanner.models import ControlComplianceSummary, Finding, ScanSummary


ISO_27001_TITLES: Dict[str, str] = {
    "A.5.14": "Information transfer",
    "A.5.15": "Access control",
    "A.5.17": "Authentication information",
    "A.5.18": "Access rights",
    "A.5.30": "ICT readiness for business continuity",
    "A.5.33": "Protection of records",
    "A.8.2": "Privileged access rights",
    "A.8.3": "Information access restriction",
    "A.8.5": "Secure authentication",
    "A.8.9": "Configuration management",
    "A.8.13": "Information backup",
    "A.8.14": "Redundancy of information processing facilities",
    "A.8.15": "Logging",
    "A.8.16": "Monitoring activities",
    "A.8.20": "Network controls",
    "A.8.22": "Segregation of networks",
    "A.8.24": "Use of cryptography",
}


def calculate_risk_rating(risk_score: int) -> str:
    """Return severity string from risk score (1-25)."""
    if risk_score >= 20:
        return "Critical"
    if risk_score >= 12:
        return "High"
    if risk_score >= 6:
        return "Medium"
    return "Low"


def calculate_overall_posture_score(findings: List[Finding]) -> float:
    """Compute overall posture score: 100 * (1 - sum(risk FAIL) / sum(risk EVALUATED))."""
    evaluated = [f for f in findings if f.status in ("PASS", "FAIL")]
    if not evaluated:
        return 100.0

    total_evaluated_risk = sum(f.risk_score for f in evaluated)
    if total_evaluated_risk == 0:
        return 100.0

    fail_risk = sum(f.risk_score for f in evaluated if f.status == "FAIL")
    score = 100.0 * (1.0 - (fail_risk / total_evaluated_risk))
    return round(max(0.0, min(100.0, score)), 2)


def calculate_control_compliance(findings: List[Finding]) -> List[ControlComplianceSummary]:
    """Calculate compliance rates per ISO 27001 Annex A control."""
    control_findings = defaultdict(list)
    control_checks = defaultdict(set)

    for f in findings:
        for c in f.iso_controls:
            control_findings[c].append(f)
            control_checks[c].add(f.check_id)

    summaries = []
    # Sort by control identifier
    for control_id in sorted(control_findings.keys()):
        f_list = control_findings[control_id]
        passed = sum(1 for x in f_list if x.status == "PASS")
        failed = sum(1 for x in f_list if x.status == "FAIL")
        errors = sum(1 for x in f_list if x.status == "ERROR")
        evaluated = passed + failed

        compliance_rate = (passed / evaluated * 100.0) if evaluated > 0 else 0.0

        title = ISO_27001_TITLES.get(control_id, "Information Security Control")
        summaries.append(
            ControlComplianceSummary(
                control_id=control_id,
                title=title,
                mapped_checks=sorted(list(control_checks[control_id])),
                total_evaluated=evaluated,
                passed=passed,
                failed=failed,
                errors=errors,
                compliance_rate=round(compliance_rate, 2),
            )
        )

    return summaries


def build_scan_summary(
    account_id: str,
    regions: List[str],
    duration_seconds: float,
    findings: List[Finding],
    attempted_checks_count: int,
) -> ScanSummary:
    """Build comprehensive scan metrics and executive summary."""
    from datetime import datetime, timezone

    passed_count = sum(1 for f in findings if f.status == "PASS")
    failed_count = sum(1 for f in findings if f.status == "FAIL")
    error_count = sum(1 for f in findings if f.status == "ERROR")
    na_count = sum(1 for f in findings if f.status == "NOT_APPLICABLE")

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        if f.status == "FAIL" and f.severity in severity_counts:
            severity_counts[f.severity] += 1

    overall_score = calculate_overall_posture_score(findings)
    control_summaries = calculate_control_compliance(findings)

    # Coverage: checks that completed successfully (not ERROR) / checks attempted
    successful_evaluations = attempted_checks_count - error_count
    coverage_rate = (
        round((successful_evaluations / attempted_checks_count * 100.0), 2)
        if attempted_checks_count > 0
        else 100.0
    )
    coverage_rate = max(0.0, min(100.0, coverage_rate))

    # Top 5 risks: failed findings sorted by risk score descending
    failed_findings = [f for f in findings if f.status == "FAIL"]
    top_risks = sorted(failed_findings, key=lambda x: x.risk_score, reverse=True)[:5]

    return ScanSummary(
        account_id=account_id,
        scan_timestamp=datetime.now(timezone.utc),
        duration_seconds=round(duration_seconds, 2),
        regions=regions,
        overall_posture_score=overall_score,
        coverage_rate=coverage_rate,
        total_findings=len(findings),
        passed_count=passed_count,
        failed_count=failed_count,
        error_count=error_count,
        na_count=na_count,
        severity_counts=severity_counts,
        control_summaries=control_summaries,
        top_risks=top_risks,
        findings=findings,
    )
