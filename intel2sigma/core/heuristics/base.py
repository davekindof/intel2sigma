"""Heuristic registry and result model.

Heuristics are pure functions of a :class:`SigmaRule` that return either
``None`` (no issue) or a :class:`HeuristicResult` describing the
finding. They are advisory — never blocking — and their severity comes
from data, not code (CLAUDE.md I-5).

Registration is decorator-driven::

    @register("h-001", category="ioc_vs_behavior")
    def ioc_only_rule(rule: SigmaRule) -> HeuristicResult | None:
        ...

The registry is a module-level dict keyed by heuristic id, populated at
import time when each ``checks/<category>.py`` module imports. The
``run_all`` function iterates the registry, applies the configured
severity from ``data/heuristics.yml``, and returns a list of fired
results.

Per CLAUDE.md I-1 (deterministic composer): heuristic functions must
not call out to LLMs, the network, the filesystem, or the clock. They
take a rule, return a finding-or-None. Tested against fixed fixtures.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from intel2sigma.core.model import SigmaRule

Severity = Literal["info", "warn", "critical"]
"""Heuristic severity. Matches docs/heuristics.md §Severity levels.

* ``info``     — educational nudge; not blocking, low visual prominence.
* ``warn``     — should be addressed; user can acknowledge and proceed.
* ``critical`` — almost always wrong; user must explicitly override.
"""


@dataclass(frozen=True, slots=True)
class HeuristicResult:
    """One heuristic finding.

    Severity is set by :func:`run_all` from the configuration data, not
    by the heuristic function itself — so re-tuning the catalog is a
    data-only PR per CLAUDE.md I-5.
    """

    heuristic_id: str
    message: str
    suggestion: str = ""
    severity: Severity = "info"
    location: str | None = None


# Function signature: takes a rule, returns Result-or-None.
HeuristicFn = Callable[[SigmaRule], HeuristicResult | None]


@dataclass(frozen=True, slots=True)
class _RegisteredHeuristic:
    """Internal record of a registered heuristic."""

    heuristic_id: str
    category: str
    fn: HeuristicFn


# Module-level registry. Populated by ``@register`` at import time.
# Iterated by :func:`run_all` in registration order, which matches the
# import order of ``checks/*.py`` modules — deterministic per CLAUDE.md
# I-1 and I-8.
_REGISTRY: dict[str, _RegisteredHeuristic] = {}


def register(
    heuristic_id: str,
    *,
    category: str,
) -> Callable[[HeuristicFn], HeuristicFn]:
    """Decorator that adds a heuristic function to the registry.

    Re-registering an existing id raises — accidental id collisions are
    a real risk as the catalog grows, and silent overwrites would be a
    nightmare to debug.
    """

    def _decorate(fn: HeuristicFn) -> HeuristicFn:
        if heuristic_id in _REGISTRY:
            raise ValueError(
                f"Heuristic id {heuristic_id!r} already registered "
                f"(by {_REGISTRY[heuristic_id].fn.__name__}); ids must be unique."
            )
        _REGISTRY[heuristic_id] = _RegisteredHeuristic(
            heuristic_id=heuristic_id,
            category=category,
            fn=fn,
        )
        return fn

    return _decorate


def registered_ids() -> list[str]:
    """Return the registered ids in registration order. Test/diagnostic API."""
    return list(_REGISTRY.keys())


def get_registered(heuristic_id: str) -> _RegisteredHeuristic | None:
    """Look up a registered heuristic by id. Returns None if absent."""
    return _REGISTRY.get(heuristic_id)


@dataclass(frozen=True, slots=True)
class HeuristicConfig:
    """Per-heuristic configuration from ``data/heuristics.yml``.

    ``severity`` is the runtime severity applied to fired results. It can
    differ from the heuristic's catalog default — that's the whole point
    of having configuration: re-tuning is a data-only edit.
    """

    severity: Severity
    enabled: bool = True


def run_all(
    rule: SigmaRule,
    config: dict[str, HeuristicConfig],
) -> list[HeuristicResult]:
    """Apply every enabled, configured heuristic to ``rule``.

    Iteration order is the registration order (deterministic). A heuristic
    that isn't configured is skipped — the catalog can outgrow the data
    file (or vice versa) without exceptions; this is friendlier for
    in-flight PRs that add a heuristic but haven't yet updated the YAML.

    Results carry the severity from ``config``, not from the heuristic
    function — keeps the function pure.
    """
    fired: list[HeuristicResult] = []
    for entry in _REGISTRY.values():
        cfg = config.get(entry.heuristic_id)
        if cfg is None or not cfg.enabled:
            continue
        result = entry.fn(rule)
        if result is None:
            continue
        # Re-stamp severity from config (the function itself may have left
        # the default ``info`` on the result; config wins).
        fired.append(
            HeuristicResult(
                heuristic_id=result.heuristic_id,
                message=result.message,
                suggestion=result.suggestion,
                severity=cfg.severity,
                location=result.location,
            )
        )
    return fired


__all__ = [
    "HeuristicConfig",
    "HeuristicFn",
    "HeuristicResult",
    "Severity",
    "get_registered",
    "register",
    "registered_ids",
    "run_all",
]
