"""Unit tests for risk calculation and posture scoring."""

from scanner.models import Finding
from scanner.scoring import (
    calculate_control_compliance,
    calculate_overall_posture_score,
    calculate_risk_rating,
)


def _dummy_finding(check_id: str, status: str, risk_score: int, iso_controls: list) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"Test {check_id}",
        service="s3",
        region="us-east-1",
        resource_id=f"test:{check_id}",
        status=status,
        severity=calculate_risk_rating(risk_score),
        risk_score=risk_score,
        iso_controls=iso_controls,
        evidence={},
        remediation="",
    )


def test_calculate_risk_rating():
    assert calculate_risk_rating(25) == "Critical"
    assert calculate_risk_rating(20) == "Critical"
    assert calculate_risk_rating(16) == "High"
    assert calculate_risk_rating(12) == "High"
    assert calculate_risk_rating(9) == "Medium"
    assert calculate_risk_rating(6) == "Medium"
    assert calculate_risk_rating(4) == "Low"
    assert calculate_risk_rating(1) == "Low"


def test_calculate_overall_posture_score():
    # All pass -> 100%
    f1 = _dummy_finding("IAM-001", "PASS", 20, ["A.8.5"])
    f2 = _dummy_finding("S3-001", "PASS", 15, ["A.8.3"])
    assert calculate_overall_posture_score([f1, f2]) == 100.0

    # 1 fail (20 risk) + 1 pass (20 risk) -> 50%
    f3 = _dummy_finding("IAM-002", "FAIL", 20, ["A.8.2"])
    score = calculate_overall_posture_score([f1, f3])
    assert score == 50.0

    # Empty findings -> 100%
    assert calculate_overall_posture_score([]) == 100.0


def test_calculate_control_compliance():
    f1 = _dummy_finding("IAM-001", "PASS", 20, ["A.8.5"])
    f2 = _dummy_finding("IAM-003", "FAIL", 12, ["A.8.5"])
    f3 = _dummy_finding("S3-001", "PASS", 15, ["A.8.3"])

    summaries = calculate_control_compliance([f1, f2, f3])
    s_a85 = next(s for s in summaries if s.control_id == "A.8.5")
    s_a83 = next(s for s in summaries if s.control_id == "A.8.3")

    assert s_a85.total_evaluated == 2
    assert s_a85.passed == 1
    assert s_a85.failed == 1
    assert s_a85.compliance_rate == 50.0

    assert s_a83.total_evaluated == 1
    assert s_a83.passed == 1
    assert s_a83.compliance_rate == 100.0
