"""Tier 3 — advisory heuristics over a complete :class:`SigmaRule`.

Where tiers 1 and 2 say "is this a valid Sigma rule" (and refuse to
proceed if not), tier 3 says "is this a *good* Sigma rule" and
produces non-blocking advisories. Per CLAUDE.md I-8 it's a pure
function: takes a rule, returns a list, no I/O or clock or RNG.

Wraps :mod:`intel2sigma.core.heuristics`: the heuristic registry +
config loader live there; tier 3 is the thin adapter that maps
:class:`HeuristicResult` to the existing :class:`ValidationIssue`
shape so the composer's review pane can render advisories alongside
tier-1 and tier-2 findings without learning a new model.
"""

from __future__ import annotations

from intel2sigma.core.heuristics import (
    HeuristicConfig,
    HeuristicResult,
    cached_config,
    run_all,
)
from intel2sigma.core.model import SigmaRule
from intel2sigma.core.validate.issues import ValidationIssue


def validate_tier3(
    rule: SigmaRule,
    *,
    config: dict[str, HeuristicConfig] | None = None,
) -> list[ValidationIssue]:
    """Run all enabled heuristics; return advisories as :class:`ValidationIssue`.

    ``config`` defaults to the cached :func:`cached_config` reading of
    ``intel2sigma/data/heuristics.yml``. Tests can supply an alternate
    mapping to flip enable flags or override severities.

    Severity flows into the issue's ``code`` prefix (``H_INFO`` /
    ``H_WARN`` / ``H_CRITICAL``) so consumers that filter by severity
    can do so with a string check instead of a separate field. We use
    the existing :class:`ValidationIssue` model (frozen, two-tier-bound)
    rather than introduce a third tier-aware shape — the issue is
    already "advisory-shaped" once you ignore the literal tier number.
    """
    cfg = cached_config() if config is None else config
    fired = run_all(rule, cfg)
    issues: list[ValidationIssue] = []
    for result in fired:
        issues.append(
            ValidationIssue(
                # Tier 3 advisories ride on the same model the composer
                # already renders. ``tier=2`` keeps the model literal
                # restriction satisfied; the ``code`` prefix below is
                # the actual sort key consumers should use.
                tier=2,
                code=_code_for(result.severity, result.heuristic_id),
                message=_format_message(result),
                location=result.location,
            )
        )
    return issues


def _code_for(severity: str, heuristic_id: str) -> str:
    """Build the issue code: ``H_<SEVERITY>_<id>``.

    Example: ``H_WARN_h-001`` or ``H_CRITICAL_h-050``.
    """
    return f"H_{severity.upper()}_{heuristic_id}"


def _format_message(result: HeuristicResult) -> str:
    """Combine the heuristic's message and suggestion into one display line.

    Kept on one ValidationIssue field rather than introducing a separate
    suggestion attribute, so the composer's existing issue-rendering
    template handles advisories without changes.
    """
    if result.suggestion:
        return f"{result.message} — {result.suggestion}"
    return result.message


__all__ = ["validate_tier3"]
