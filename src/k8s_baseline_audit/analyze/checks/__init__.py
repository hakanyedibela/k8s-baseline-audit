"""Built-in checks. Importing this package registers every check."""

from .base import REGISTRY, Check  # noqa: I001

from . import workload  # noqa: E402,F401
from . import identity  # noqa: E402,F401,I001


def all_checks() -> list[Check]:
    return [REGISTRY[k] for k in sorted(REGISTRY)]


__all__ = ["REGISTRY", "Check", "all_checks"]
