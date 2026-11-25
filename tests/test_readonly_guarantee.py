"""Test ensuring scanner checks are strictly read-only."""

import ast
from pathlib import Path
import pytest

CHECKS_DIR = Path(__file__).parent.parent / "scanner" / "checks"

DISALLOWED_PREFIXES = (
    "create_",
    "put_",
    "delete_",
    "update_",
    "modify_",
    "attach_",
    "detach_",
)

WHITELISTED_CALLS = {
    "generate_credential_report",
    "_make_finding",
    "mkdir",  # Path.mkdir if any
}


def test_strictly_readonly_guarantee():
    """Verify that no mutating API calls are invoked in any check file."""
    assert CHECKS_DIR.exists(), f"Checks directory not found at {CHECKS_DIR}"

    violations = []
    py_files = list(CHECKS_DIR.glob("*.py"))
    assert len(py_files) > 0, "No check files found to audit!"

    for py_file in py_files:
        if py_file.name == "__init__.py":
            continue

        with open(py_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in WHITELISTED_CALLS:
                    continue

                for prefix in DISALLOWED_PREFIXES:
                    if func_name.startswith(prefix):
                        violations.append(
                            f"{py_file.name}:{getattr(node, 'lineno', '?')} calls prohibited mutating method '{func_name}'"
                        )

    assert not violations, "Read-only guarantee violated:\n" + "\n".join(violations)
