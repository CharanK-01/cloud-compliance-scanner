"""Check registry and decorator for scanner plugins."""

import importlib
import pkgutil
from typing import Callable, Dict, List
import scanner.checks

CHECKS: Dict[str, Callable] = {}


def check(check_id: str):
    """Decorator to register a check function under a unique check_id."""
    def decorator(fn: Callable):
        CHECKS[check_id] = fn
        return fn
    return decorator


def get_check(check_id: str) -> Callable:
    """Retrieve a registered check callable by ID."""
    return CHECKS.get(check_id)


def list_checks() -> List[str]:
    """Return sorted list of all registered check IDs."""
    return sorted(CHECKS.keys())


def load_all_checks():
    """Dynamically import all check modules in scanner.checks package."""
    package = scanner.checks
    for _, module_name, _ in pkgutil.iter_modules(package.__path__):
        importlib.import_module(f"scanner.checks.{module_name}")
