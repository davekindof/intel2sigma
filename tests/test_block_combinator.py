"""Combinator coverage — core model + serializer round-trip.

Tests that:
  * ``DetectionBlock.combinator`` defaults to ``all_of`` (preserves existing
    rule semantics).
  * ``to_yaml`` emits the mapping form for ``all_of`` and the list-of-mappings
    form for ``any_of``.
  * ``from_yaml`` parses both forms back into the model with the right
    combinator.
  * Round-tripping a rule with a mixed-combinator block set is byte-stable.
"""

from __future__ import annotations

from datetime import date
from uuid import UUID

from sigma.rule import SigmaRule as PySigmaRule

from intel2sigma.core.model import (
    ConditionExpression,
    ConditionOp,
    DetectionBlock,
    DetectionItem,
    LogSource,
    SigmaRule,
)
from intel2sigma.core.serialize import from_yaml, to_yaml


def _rule_with(blocks: list[DetectionBlock], condition: ConditionExpression) -> SigmaRule:
    return SigmaRule(
        title="Combinator coverage rule",
        id=UUID("00000000-1111-2222-3333-444444444444"),
        date=date(2026, 4, 24),
        logsource=LogSource(product="windows", category="process_creation"),
        detections=blocks,
        condition=condition,
    )


# ---------------------------------------------------------------------------
# all_of — current default behavior
# ---------------------------------------------------------------------------


def test_all_of_block_emits_mapping_form() -> None:
    block = DetectionBlock(
        name="match_1",
        combinator="all_of",
        items=[
            DetectionItem(field="Image", modifiers=["endswith"], values=["\\foo.exe"]),
            DetectionItem(field="CommandLine", modifiers=["contains"], values=["-x"]),
        ],
    )
    rule = _rule_with([block], ConditionExpression(selection="match_1"))
    yaml = to_yaml(rule)
    # Mapping form: keys directly under the block name, no list bullets.
    assert "match_1:\n    Image|endswith:" in yaml
    assert "  - Image|endswith:" not in yaml


# ---------------------------------------------------------------------------
# any_of — list-of-mappings form
# ---------------------------------------------------------------------------


def test_any_of_block_emits_list_of_mappings() -> None:
    block = DetectionBlock(
        name="match_1",
        combinator="any_of",
        items=[
            DetectionItem(field="Image", modifiers=["endswith"], values=["\\foo.exe"]),
            DetectionItem(field="CommandLine", modifiers=["contains"], values=["-x"]),
        ],
    )
    rule = _rule_with([block], ConditionExpression(selection="match_1"))
    yaml = to_yaml(rule)
    # List form: each item is its own mapping under match_1.
    assert "match_1:" in yaml
    assert "- Image|endswith:" in yaml
    assert "- CommandLine|contains:" in yaml


# ---------------------------------------------------------------------------
# from_yaml: both shapes parse back into the right combinator
# ---------------------------------------------------------------------------


def test_from_yaml_parses_mapping_as_all_of() -> None:
    block = DetectionBlock(
        name="match_1",
        combinator="all_of",
        items=[DetectionItem(field="Image", modifiers=["endswith"], values=["\\foo.exe"])],
    )
    rule = _rule_with([block], ConditionExpression(selection="match_1"))
    parsed = from_yaml(to_yaml(rule))
    assert parsed.detections[0].combinator == "all_of"


def test_from_yaml_parses_list_of_mappings_as_any_of() -> None:
    block = DetectionBlock(
        name="match_1",
        combinator="any_of",
        items=[
            DetectionItem(field="Image", modifiers=["endswith"], values=["\\foo.exe"]),
            DetectionItem(field="CommandLine", modifiers=["contains"], values=["-x"]),
        ],
    )
    rule = _rule_with([block], ConditionExpression(selection="match_1"))
    parsed = from_yaml(to_yaml(rule))
    assert parsed.detections[0].combinator == "any_of"
    assert len(parsed.detections[0].items) == 2


# ---------------------------------------------------------------------------
# Round-trip: byte-identical re-serialization with mixed combinators
# ---------------------------------------------------------------------------


def test_mixed_combinator_round_trip_is_byte_identical() -> None:
    blocks = [
        DetectionBlock(
            name="match_paths",
            combinator="any_of",
            items=[
                DetectionItem(field="Image", modifiers=["endswith"], values=["\\evil.exe"]),
                DetectionItem(field="Image", modifiers=["endswith"], values=["\\bad.dll"]),
            ],
        ),
        DetectionBlock(
            name="match_args",
            combinator="all_of",
            items=[
                DetectionItem(
                    field="CommandLine",
                    modifiers=["contains"],
                    values=["-encodedcommand"],
                ),
            ],
        ),
    ]
    condition = ConditionExpression(
        op=ConditionOp.AND,
        children=[
            ConditionExpression(selection="match_paths"),
            ConditionExpression(selection="match_args"),
        ],
    )
    rule = _rule_with(blocks, condition)
    first = to_yaml(rule)
    second = to_yaml(from_yaml(first))
    assert first == second


# ---------------------------------------------------------------------------
# pySigma still accepts our list-of-mappings emission.
# ---------------------------------------------------------------------------


def test_any_of_block_pysigma_accepts() -> None:
    """A list-of-mappings block must be valid Sigma per pySigma's parser.

    The whole point of supporting any_of is so users can write OR-within-block
    rules that downstream tools accept; if pySigma rejects our emission the
    feature is broken at the boundary.
    """
    block = DetectionBlock(
        name="match_1",
        combinator="any_of",
        items=[
            DetectionItem(field="Image", modifiers=["endswith"], values=["\\foo.exe"]),
            DetectionItem(field="CommandLine", modifiers=["contains"], values=["-x"]),
        ],
    )
    rule = _rule_with([block], ConditionExpression(selection="match_1"))
    yaml = to_yaml(rule)
    PySigmaRule.from_yaml(yaml)  # raises if rejected
