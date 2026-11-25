"""Data models for Cloud Security Compliance Scanner."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import boto3


@dataclass
class Finding:
    """Represents an evaluation result for a single resource under a check."""
    check_id: str                   # e.g., "IAM-001"
    title: str                      # Human-readable check title
    service: str                    # iam, s3, ec2, etc.
    region: str                     # "global" or specific AWS region (e.g., "us-east-1")
    resource_id: str                # ARN, Name, or ID of evaluated resource
    status: str                     # PASS | FAIL | ERROR | NOT_APPLICABLE
    severity: str                   # Critical | High | Medium | Low | Info
    risk_score: int                 # Likelihood x Impact (1 - 25)
    iso_controls: List[str]         # e.g., ["A.8.5", "A.8.2"]
    evidence: Dict[str, Any]        # Raw API response / telemetry justifying status
    remediation: str                # Step-by-step remediation advice
    rationale: str = ""             # Security and risk rationale


@dataclass
class CheckDefinition:
    """Check configuration and ISO mapping loaded from controls.yaml."""
    check_id: str
    title: str
    service: str
    iso_controls: List[str]
    likelihood: int                 # 1 to 5
    impact: int                     # 1 to 5
    remediation: str
    rationale: str = ""

    @property
    def risk_score(self) -> int:
        return self.likelihood * self.impact

    @property
    def severity(self) -> str:
        score = self.risk_score
        if score >= 20:
            return "Critical"
        if score >= 12:
            return "High"
        if score >= 6:
            return "Medium"
        return "Low"


@dataclass
class ScanContext:
    """Context passed to all check functions."""
    session: boto3.Session
    account_id: str
    regions: List[str]
    controls: Dict[str, CheckDefinition] = field(default_factory=dict)
    _clients: Dict[str, Any] = field(default_factory=dict)

    def get_client(self, service_name: str, region_name: Optional[str] = None):
        """Get or create a cached boto3 client with standard adaptive retry config."""
        from botocore.config import Config
        retry_config = Config(
            retries={"max_attempts": 10, "mode": "adaptive"}
        )
        cache_key = f"{service_name}:{region_name}"
        if cache_key not in self._clients:
            kwargs = {"config": retry_config}
            if region_name:
                kwargs["region_name"] = region_name
            self._clients[cache_key] = self.session.client(service_name, **kwargs)
        return self._clients[cache_key]


@dataclass
class ControlComplianceSummary:
    """Per-ISO 27001 Annex A control audit summary."""
    control_id: str
    title: str
    mapped_checks: List[str]
    total_evaluated: int
    passed: int
    failed: int
    errors: int
    compliance_rate: float          # 0.0 to 100.0


@dataclass
class ScanSummary:
    """Overall executive metrics computed across all findings."""
    account_id: str
    scan_timestamp: datetime
    duration_seconds: float
    regions: List[str]
    overall_posture_score: float    # 0.0 to 100.0
    coverage_rate: float            # 0.0 to 100.0 (successful checks / attempted)
    total_findings: int
    passed_count: int
    failed_count: int
    error_count: int
    na_count: int
    severity_counts: Dict[str, int] # Critical, High, Medium, Low
    control_summaries: List[ControlComplianceSummary]
    top_risks: List[Finding]
    findings: List[Finding]
