"""Heuristic check modules — one per catalog category.

Importing this package imports every category module, which registers
their decorated heuristic functions with the central registry. Keep
new check modules listed here so the registry knows about them.
"""

from __future__ import annotations

# Side-effect imports — each module's @register decorators populate the
# registry at import time. The aliases stay around so static analysis
# can't accidentally drop them as unused.
from intel2sigma.core.heuristics.checks import (
    condition_integrity,
    ioc_vs_behavior,
    lab_artifacts,
    metadata_completeness,
    path_specificity,
)

__all__ = [
    "condition_integrity",
    "ioc_vs_behavior",
    "lab_artifacts",
    "metadata_completeness",
    "path_specificity",
]
