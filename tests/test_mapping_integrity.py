"""Test mapping integrity between check registry and controls.yaml."""

from pathlib import Path
import pytest

from scanner.registry import CHECKS, load_all_checks
from scanner.session import load_controls_mapping

CONTROLS_PATH = Path(__file__).parent.parent / "scanner" / "mappings" / "controls.yaml"


def test_mapping_integrity():
    """Verify all registered checks exist in controls.yaml with valid metadata."""
    load_all_checks()
    controls = load_controls_mapping(CONTROLS_PATH)

    assert len(CHECKS) > 0, "No checks registered in CHECKS registry"
    assert len(controls) > 0, "No controls loaded from controls.yaml"

    for check_id in CHECKS:
        assert check_id in controls, f"Registered check '{check_id}' is missing from controls.yaml!"
        meta = controls[check_id]

        assert meta.title, f"Check {check_id} must have a non-empty title"
        assert meta.service, f"Check {check_id} must have a service assigned"
        assert len(meta.iso_controls) > 0, f"Check {check_id} must map to at least one ISO control"
        for iso in meta.iso_controls:
            assert iso.startswith("A."), f"ISO control '{iso}' in {check_id} should follow 'A.x.x' convention"

        assert 1 <= meta.likelihood <= 5, f"Check {check_id} likelihood must be between 1 and 5 (got {meta.likelihood})"
        assert 1 <= meta.impact <= 5, f"Check {check_id} impact must be between 1 and 5 (got {meta.impact})"
        assert 1 <= meta.risk_score <= 25, f"Check {check_id} risk_score must be between 1 and 25"
        assert meta.severity in ("Critical", "High", "Medium", "Low"), f"Invalid severity: {meta.severity}"
        assert meta.remediation, f"Check {check_id} must have remediation instructions"
