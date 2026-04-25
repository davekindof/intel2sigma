"""Heuristic engine — pure-function quality checks over :class:`SigmaRule`.

Public surface:

* :class:`HeuristicResult`, :class:`HeuristicConfig`, :data:`Severity` — model
* :func:`register` — decorator used by ``checks/*.py`` modules
* :func:`run_all` — apply every enabled heuristic to a rule
* :func:`load_config` — read ``intel2sigma/data/heuristics.yml``

Importing this module also imports the ``checks`` subpackage so the
registry is fully populated by the time a caller uses :func:`run_all`.
"""

from __future__ import annotations

# Importing ``checks`` registers every heuristic via ``@register`` at
# import time. The empty ``import`` is deliberate — we only need the
# side effect.
from intel2sigma.core.heuristics import checks as _checks  # noqa: F401
from intel2sigma.core.heuristics.base import (
    HeuristicConfig,
    HeuristicFn,
    HeuristicResult,
    Severity,
    register,
    registered_ids,
    run_all,
)
from intel2sigma.core.heuristics.config import cached_config, load_config

__all__ = [
    "HeuristicConfig",
    "HeuristicFn",
    "HeuristicResult",
    "Severity",
    "cached_config",
    "load_config",
    "register",
    "registered_ids",
    "run_all",
]
