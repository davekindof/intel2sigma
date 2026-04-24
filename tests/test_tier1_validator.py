"""Tests for ``core.validate.tier1`` — blocking cross-field checks.

Each failing case has a dedicated test so the mapping from error shape to
error code is explicit. The positive case reuses the existing
``smoke_rule`` fixture from ``conftest.py``.
"""

from __future__ import annotations

from datetime import date
from uuid import UUID

from intel2sigma.core.model import (
    ConditionExpression,
    ConditionOp,
    DetectionBlock,
    DetectionItem,
    LogSource,
    SigmaRule,
)
from intel2sigma.core.taxonomy import load_taxonomy
from intel2sigma.core.validate import validate_tier1
from intel2sigma.core.validate.tier1 import (
    CODE_CONDITION_UNKNOWN_SELECTION,
    CODE_ENUM_VALUE_INVALID,
    CODE_FIELD_NOT_IN_TAXONOMY,
    CODE_MODIFIER_NOT_ALLOWED,
)

# Share one loaded registry across the module — loading is pure but not
# free, and all taxonomy-dependent tests target the bundled catalog.
_TAXONOMY = load_taxonomy()


# ---------------------------------------------------------------------------
# Positive case
# ---------------------------------------------------------------------------


def test_smoke_rule_passes_tier1(smoke_rule: SigmaRule) -> None:
    """The fixture rule has a known-good structure; tier-1 must return []."""
    issues = validate_tier1(smoke_rule, taxonomy=_TAXONOMY)
    assert issues == [], f"smoke_rule unexpectedly failed tier 1: {issues}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _simple_rule(
    detections: list[DetectionBlock],
    condition: ConditionExpression,
    *,
    category: str = "process_creation",
    product: str = "windows",
) -> SigmaRule:
    return SigmaRule(
        title="Test rule",
        id=UUID("00000000-0000-0000-0000-000000000001"),
        date=date(2026, 4, 24),
        logsource=LogSource(product=product, category=category),
        detections=detections,
        condition=condition,
    )


# ---------------------------------------------------------------------------
# Condition integrity
# ---------------------------------------------------------------------------


def test_condition_references_unknown_selection() -> None:
    rule = _simple_rule(
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(field="Image", modifiers=["endswith"], values=["\\evil.exe"]),
                ],
            ),
        ],
        condition=ConditionExpression(selection="does_not_exist"),
    )
    issues = validate_tier1(rule, taxonomy=_TAXONOMY)
    codes = [i.code for i in issues]
    assert CODE_CONDITION_UNKNOWN_SELECTION in codes


def test_condition_glob_with_no_matching_blocks() -> None:
    rule = _simple_rule(
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(field="Image", modifiers=["endswith"], values=["\\foo.exe"]),
                ],
            ),
        ],
        condition=ConditionExpression(
            op=ConditionOp.ALL_OF,
            children=[ConditionExpression(selection="filter_*")],
        ),
    )
    issues = validate_tier1(rule, taxonomy=_TAXONOMY)
    codes = [i.code for i in issues]
    assert CODE_CONDITION_UNKNOWN_SELECTION in codes


def test_condition_glob_with_matching_block_passes() -> None:
    rule = _simple_rule(
        detections=[
            DetectionBlock(
                name="selection_parent_a",
                items=[
                    DetectionItem(field="Image", modifiers=["endswith"], values=["\\foo.exe"]),
                ],
            ),
        ],
        condition=ConditionExpression(
            op=ConditionOp.ALL_OF,
            children=[ConditionExpression(selection="selection_*")],
        ),
    )
    issues = validate_tier1(rule, taxonomy=_TAXONOMY)
    assert not issues


def test_condition_nested_and_recursively_validated() -> None:
    rule = _simple_rule(
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(field="Image", modifiers=["endswith"], values=["\\foo.exe"]),
                ],
            ),
        ],
        condition=ConditionExpression(
            op=ConditionOp.AND,
            children=[
                ConditionExpression(selection="match_1"),
                ConditionExpression(selection="phantom_block"),
            ],
        ),
    )
    issues = validate_tier1(rule, taxonomy=_TAXONOMY)
    codes = [i.code for i in issues]
    assert CODE_CONDITION_UNKNOWN_SELECTION in codes


# ---------------------------------------------------------------------------
# Taxonomy-dependent checks
# ---------------------------------------------------------------------------


def test_field_not_in_taxonomy_for_known_observation() -> None:
    rule = _simple_rule(
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(
                        field="NotARealSigmaField",
                        modifiers=["contains"],
                        values=["whatever"],
                    ),
                ],
            ),
        ],
        condition=ConditionExpression(selection="match_1"),
    )
    issues = validate_tier1(rule, taxonomy=_TAXONOMY)
    codes = [i.code for i in issues]
    assert CODE_FIELD_NOT_IN_TAXONOMY in codes


def test_modifier_not_in_allowed_set() -> None:
    # Image allows [endswith, contains, startswith, re, exact] — 'cidr' is not listed.
    rule = _simple_rule(
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(field="Image", modifiers=["cidr"], values=["\\foo.exe"]),
                ],
            ),
        ],
        condition=ConditionExpression(selection="match_1"),
    )
    issues = validate_tier1(rule, taxonomy=_TAXONOMY)
    codes = [i.code for i in issues]
    assert CODE_MODIFIER_NOT_ALLOWED in codes


def test_enum_value_invalid() -> None:
    # IntegrityLevel is an enum with values [Low, Medium, High, System].
    rule = _simple_rule(
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(
                        field="IntegrityLevel",
                        modifiers=["exact"],
                        values=["Extreme"],
                    ),
                ],
            ),
        ],
        condition=ConditionExpression(selection="match_1"),
    )
    issues = validate_tier1(rule, taxonomy=_TAXONOMY)
    codes = [i.code for i in issues]
    assert CODE_ENUM_VALUE_INVALID in codes


def test_enum_value_valid_passes() -> None:
    rule = _simple_rule(
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(
                        field="IntegrityLevel",
                        modifiers=["exact"],
                        values=["System"],
                    ),
                ],
            ),
        ],
        condition=ConditionExpression(selection="match_1"),
    )
    issues = validate_tier1(rule, taxonomy=_TAXONOMY)
    assert not issues


def test_uncatalogued_logsource_skips_taxonomy_checks() -> None:
    """Rules targeting an unknown category pass tier-1 if condition is sane.

    The catalog is deliberately incomplete — rules for cloud sources or
    niche categories should not be rejected; we just can't introspect them.
    """
    rule = _simple_rule(
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(
                        field="ThisFieldWouldBeRejectedIfCategoryWereKnown",
                        modifiers=["contains"],
                        values=["x"],
                    ),
                ],
            ),
        ],
        condition=ConditionExpression(selection="match_1"),
        category="aws_cloudtrail",  # not in our catalog
        product="aws",
    )
    issues = validate_tier1(rule, taxonomy=_TAXONOMY)
    assert not issues


def test_multiple_issues_collected() -> None:
    """The validator returns every issue it finds, not just the first."""
    rule = _simple_rule(
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(field="NotReal", modifiers=["contains"], values=["a"]),
                    DetectionItem(field="Image", modifiers=["cidr"], values=["\\foo.exe"]),
                ],
            ),
        ],
        condition=ConditionExpression(selection="ghost_block"),
    )
    issues = validate_tier1(rule, taxonomy=_TAXONOMY)
    codes = {i.code for i in issues}
    assert CODE_FIELD_NOT_IN_TAXONOMY in codes
    assert CODE_MODIFIER_NOT_ALLOWED in codes
    assert CODE_CONDITION_UNKNOWN_SELECTION in codes
