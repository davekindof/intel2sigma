"""Heuristics that check the rule's condition tree for shape bugs.

The composer assembles conditions programmatically, so undefined-
selection references and orphaned blocks are mostly composer bugs
rather than user errors. They still make excellent advisories: they
catch upstream regressions early, and rules loaded via the v1.5 paste-
existing-rule path can carry these defects in from arbitrary YAML.
"""

from __future__ import annotations

from intel2sigma.core.heuristics.base import HeuristicResult, register
from intel2sigma.core.model import ConditionExpression, ConditionOp, SigmaRule


def _referenced_selections(condition: ConditionExpression) -> set[str]:
    """Walk the condition tree and collect every ``selection`` leaf name.

    ``ALL_OF``/``ONE_OF`` operators carry a glob (e.g. ``"match_*"``);
    glob-targets aren't pinned to one block, so they don't go in the
    direct-reference set — h-051 is conservative about flagging blocks
    that *could* be matched by an outstanding glob.
    """
    refs: set[str] = set()
    _walk_refs(condition, refs)
    return refs


def _walk_refs(node: ConditionExpression, acc: set[str]) -> None:
    if node.selection is not None:
        acc.add(node.selection)
    for child in node.children:
        _walk_refs(child, acc)


_GLOB_OPS: frozenset[ConditionOp] = frozenset({ConditionOp.ALL_OF, ConditionOp.ONE_OF})


def _has_glob_selector(condition: ConditionExpression) -> bool:
    """True if the condition uses ``ALL_OF`` / ``ONE_OF`` glob form anywhere.

    When a glob is in play we cannot tell statically whether a given block
    is referenced, so h-051 stops short of flagging anything in those
    rules to avoid false positives.
    """
    if condition.op in _GLOB_OPS:
        return True
    return any(_has_glob_selector(c) for c in condition.children)


@register("h-050", category="condition_integrity")
def condition_references_undefined(rule: SigmaRule) -> HeuristicResult | None:
    """Condition refers to a selection name that has no DetectionBlock.

    This is almost always a real bug — the rule cannot fire as written,
    or fires only by accident if the missing name happens to be a Sigma
    keyword. Severity ``critical`` per the catalog default.
    """
    block_names = {b.name for b in rule.detections}
    referenced = _referenced_selections(rule.condition)
    missing = referenced - block_names
    if not missing:
        return None
    # Sort to keep the message deterministic — heuristic functions are
    # pure (CLAUDE.md I-8) so no ``random`` / no insertion-order leaks.
    first = sorted(missing)[0]
    extra = "" if len(missing) == 1 else f" (and {len(missing) - 1} more)"
    return HeuristicResult(
        heuristic_id="h-050",
        message=(
            f"Condition references selection {first!r}{extra} which is not "
            f"defined anywhere in the rule. The rule will not fire."
        ),
        suggestion=(
            f"Add a detection block named {first!r}, or remove the reference from the condition."
        ),
        location="condition",
    )


@register("h-051", category="condition_integrity")
def selection_defined_but_unused(rule: SigmaRule) -> HeuristicResult | None:
    """A DetectionBlock is defined but never referenced by the condition.

    Skipped when the condition uses ``ALL_OF``/``ONE_OF`` glob form —
    the glob may legitimately cover the block, and a static walk can't
    prove otherwise without re-implementing pySigma's glob matcher.
    """
    if _has_glob_selector(rule.condition):
        return None
    referenced = _referenced_selections(rule.condition)
    orphans = [b.name for b in rule.detections if b.name not in referenced]
    if not orphans:
        return None
    first = orphans[0]
    extra = "" if len(orphans) == 1 else f" (and {len(orphans) - 1} more)"
    return HeuristicResult(
        heuristic_id="h-051",
        message=(
            f"Detection block {first!r}{extra} is defined but the "
            f"condition never references it. It contributes nothing to "
            f"the rule firing."
        ),
        suggestion=(f"Either reference {first!r} in the condition, or delete the block."),
        location=f"detections.{first}",
    )


__all__ = [
    "condition_references_undefined",
    "selection_defined_but_unused",
]
