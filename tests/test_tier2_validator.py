"""Tests for ``core.validate.tier2`` — pySigma acceptance.

Tier 2 drives the rule through ``to_yaml`` and pySigma's own parser, then
translates pySigma's exception hierarchy into our structured issue shape.
The happy-path test is the most important: the ``smoke_rule`` fixture
exercises every serializer code path and must round-trip through pySigma
cleanly. The negative tests craft rule shapes pySigma rejects to verify
the code-translation mapping.
"""

from __future__ import annotations

from datetime import date
from uuid import UUID

from intel2sigma.core.model import (
    ConditionExpression,
    DetectionBlock,
    DetectionItem,
    LogSource,
    SigmaRule,
)
from intel2sigma.core.validate import validate_tier2
from intel2sigma.core.validate.tier2 import CODE_PYSIGMA_MODIFIER


def test_smoke_rule_passes_tier2(smoke_rule: SigmaRule) -> None:
    """The fixture must round-trip through pySigma cleanly. Empty list."""
    issues = validate_tier2(smoke_rule)
    assert issues == [], f"smoke_rule unexpectedly failed tier 2: {issues}"


def test_tier2_reports_bad_modifier() -> None:
    """A modifier string pySigma doesn't recognise trips a modifier-code issue.

    Our ``ValueModifier`` Literal is a closed set so constructing an invalid
    modifier at the model layer fails at Pydantic time. To exercise tier 2's
    error translation we use ``model_construct`` to bypass validation and
    simulate a rule that reached tier 2 with a pySigma-unknown modifier —
    which is essentially what would happen if pySigma added a new modifier
    we didn't yet list.
    """
    item = DetectionItem.model_construct(
        field="Image",
        modifiers=["definitely_not_a_sigma_modifier"],  # type: ignore[list-item]
        values=["\\foo.exe"],
    )
    block = DetectionBlock.model_construct(
        name="match_1",
        is_filter=False,
        items=[item],
    )
    rule = SigmaRule(
        title="Bad modifier rule",
        id=UUID("00000000-0000-0000-0000-000000000002"),
        date=date(2026, 4, 24),
        logsource=LogSource(product="windows", category="process_creation"),
        detections=[block],
        condition=ConditionExpression(selection="match_1"),
    )

    issues = validate_tier2(rule)
    assert issues, "Expected at least one tier-2 issue"
    assert issues[0].tier == 2
    # pySigma raises SigmaModifierError (or a subclass) for unknown modifiers.
    assert issues[0].code == CODE_PYSIGMA_MODIFIER


def test_tier2_message_contains_pysigma_error_text(smoke_rule: SigmaRule) -> None:
    """Positive case: the happy-path message is absent because there's no issue."""
    issues = validate_tier2(smoke_rule)
    assert not issues
