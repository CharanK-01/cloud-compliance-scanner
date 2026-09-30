"""AWS Session and Environment initialization."""

import os
from pathlib import Path
from typing import Dict, List, Optional
import boto3
import yaml
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError

from scanner.models import CheckDefinition, ScanContext

DEFAULT_CONTROLS_PATH = Path(__file__).parent / "mappings" / "controls.yaml"


def load_controls_mapping(filepath: Optional[Path] = None) -> Dict[str, CheckDefinition]:
    """Load check definitions and ISO mappings from controls.yaml."""
    path = filepath or DEFAULT_CONTROLS_PATH
    if not path.exists():
        raise FileNotFoundError(f"Controls mapping file not found at {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    definitions = {}
    for check_id, meta in data.items():
        definitions[check_id] = CheckDefinition(
            check_id=check_id,
            title=meta.get("title", ""),
            service=meta.get("service", "unknown"),
            iso_controls=meta.get("iso_controls", []),
            likelihood=int(meta.get("likelihood", 3)),
            impact=int(meta.get("impact", 3)),
            remediation=meta.get("remediation", "").strip(),
            rationale=meta.get("rationale", "").strip(),
        )
    return definitions


def create_session(profile_name: Optional[str] = None, region_name: Optional[str] = None) -> boto3.Session:
    """Create a boto3 session with optional AWS profile and region."""
    kwargs = {}
    if profile_name:
        kwargs["profile_name"] = profile_name
    if region_name:
        kwargs["region_name"] = region_name
    return boto3.Session(**kwargs)


def get_account_id(session: boto3.Session) -> str:
    """Retrieve AWS Account ID using STS caller identity."""
    try:
        sts = session.client("sts", config=Config(retries={"max_attempts": 5, "mode": "adaptive"}))
        identity = sts.get_caller_identity()
        return identity.get("Account", "unknown-account")
    except (ClientError, NoCredentialsError):
        return "unknown-account"


def discover_regions(session: boto3.Session, requested_regions: Optional[List[str]] = None) -> List[str]:
    """Discover enabled AWS regions or filter by user requested regions."""
    if requested_regions:
        return [r.strip() for r in requested_regions if r.strip()]

    try:
        ec2 = session.client("ec2", region_name="us-east-1", config=Config(retries={"max_attempts": 5, "mode": "adaptive"}))
        response = ec2.describe_regions(AllRegions=False)
        regions = [r["RegionName"] for r in response.get("Regions", [])]
        return sorted(regions) if regions else ["us-east-1"]
    except Exception:
        # Default fallback if region discovery fails or restricted
        return ["us-east-1"]


def init_scan_context(
    session: boto3.Session,
    regions: Optional[List[str]] = None,
    controls_path: Optional[Path] = None,
) -> ScanContext:
    """Initialize ScanContext with session, discovered regions, and control mappings."""
    account_id = get_account_id(session)
    active_regions = discover_regions(session, regions)
    controls = load_controls_mapping(controls_path)

    return ScanContext(
        session=session,
        account_id=account_id,
        regions=active_regions,
        controls=controls,
    )
