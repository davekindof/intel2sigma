"""Tests for the condition-integrity category (h-050, h-051)."""

from __future__ import annotations

from intel2sigma.core.heuristics.checks.condition_integrity import (
    condition_references_undefined,
    selection_defined_but_unused,
)
from intel2sigma.core.model import (
    ConditionExpression,
    ConditionOp,
    DetectionBlock,
    DetectionItem,
    SigmaRule,
)

# ---------------------------------------------------------------------------
# h-050 — undefined selection in condition
# ---------------------------------------------------------------------------


def test_h050_fires_when_condition_references_unknown_selection(
    benign_rule: SigmaRule,
) -> None:
    """Pointing the condition at a non-existent block fires h-050."""
    broken = benign_rule.model_copy(
        update={"condition": ConditionExpression(selection="ghost_block")},
    )
    result = condition_references_undefined(broken)
    assert result is not None
    assert result.heuristic_id == "h-050"
    assert "ghost_block" in result.message


def test_h050_does_not_fire_on_valid_condition(benign_rule: SigmaRule) -> None:
    """The benign baseline's condition resolves cleanly — no advisory."""
    assert condition_references_undefined(benign_rule) is None


# ---------------------------------------------------------------------------
# h-051 — orphaned selection block
# ---------------------------------------------------------------------------


def test_h051_fires_on_orphaned_block(benign_rule: SigmaRule) -> None:
    """A defined block the condition never references fires h-051."""
    with_orphan = benign_rule.model_copy(
        update={
            "detections": [
                *benign_rule.detections,
                DetectionBlock(
                    name="orphan_block",
                    is_filter=False,
                    items=[
                        DetectionItem(field="Image", values=["nope.exe"]),
                    ],
                ),
            ],
        }
    )
    result = selection_defined_but_unused(with_orphan)
    assert result is not None
    assert result.heuristic_id == "h-051"
    assert "orphan_block" in result.message


def test_h051_skips_when_condition_uses_glob_selector(benign_rule: SigmaRule) -> None:
    """``ALL_OF match_*`` could legitimately cover any block — don't fire."""
    glob_condition = ConditionExpression(
        op=ConditionOp.ALL_OF,
        children=[ConditionExpression(selection="match_*")],
    )
    globbed = benign_rule.model_copy(update={"condition": glob_condition})
    # We could legitimately glob-match all the existing blocks; a static
    # walk can't tell, so the heuristic stays silent rather than risk a
    # false positive.
    assert selection_defined_but_unused(globbed) is None
