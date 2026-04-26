"""Tests for the overbroad-selection category (h-010, h-011, h-012)."""

from __future__ import annotations

from intel2sigma.core.heuristics.checks.overbroad_selection import (
    short_image_endswith,
    single_common_keyword,
    single_high_cardinality_match,
)
from intel2sigma.core.model import (
    ConditionExpression,
    DetectionBlock,
    DetectionItem,
    SigmaRule,
)

# --- h-010: single high-cardinality field ------------------------------------


def test_h010_fires_on_lone_commandline_contains(benign_rule: SigmaRule) -> None:
    """A rule with one match block, one item, CommandLine|contains fires h-010."""
    overbroad = benign_rule.model_copy(
        update={
            "detections": [
                DetectionBlock(
                    name="match_1",
                    is_filter=False,
                    items=[
                        DetectionItem(
                            field="CommandLine",
                            modifiers=["contains"],
                            values=["-encodedcommand"],
                        ),
                    ],
                ),
            ],
            "condition": ConditionExpression(selection="match_1"),
        }
    )
    result = single_high_cardinality_match(overbroad)
    assert result is not None
    assert result.heuristic_id == "h-010"
    assert result.location == "detections.match_1"


def test_h010_does_not_fire_with_two_items_in_block(benign_rule: SigmaRule) -> None:
    """The benign baseline (Image + CommandLine in one block) is well-grounded."""
    assert single_high_cardinality_match(benign_rule) is None


# --- h-011: single common keyword --------------------------------------------


def test_h011_fires_on_lone_powershell_keyword(benign_rule: SigmaRule) -> None:
    """A rule whose only match value is `powershell` fires h-011."""
    overbroad = benign_rule.model_copy(
        update={
            "detections": [
                DetectionBlock(
                    name="match_1",
                    is_filter=False,
                    items=[
                        DetectionItem(
                            field="CommandLine",
                            modifiers=["contains"],
                            values=["powershell"],
                        ),
                    ],
                ),
            ],
            "condition": ConditionExpression(selection="match_1"),
        }
    )
    result = single_common_keyword(overbroad)
    assert result is not None
    assert result.heuristic_id == "h-011"
    assert "powershell" in result.message.lower()


def test_h011_does_not_fire_when_value_is_specific(benign_rule: SigmaRule) -> None:
    """A specific argument like `-encodedcommand` is not in the keyword list."""
    specific = benign_rule.model_copy(
        update={
            "detections": [
                DetectionBlock(
                    name="match_1",
                    is_filter=False,
                    items=[
                        DetectionItem(
                            field="CommandLine",
                            modifiers=["contains"],
                            values=["-encodedcommand"],
                        ),
                    ],
                ),
            ],
            "condition": ConditionExpression(selection="match_1"),
        }
    )
    assert single_common_keyword(specific) is None


# --- h-012: short Image|endswith ---------------------------------------------


def test_h012_fires_on_three_char_endswith(benign_rule: SigmaRule) -> None:
    r"""Image|endswith of `\py` (2 chars after backslash) fires h-012."""
    short = benign_rule.model_copy(
        update={
            "detections": [
                DetectionBlock(
                    name="match_1",
                    is_filter=False,
                    items=[
                        DetectionItem(
                            field="Image",
                            modifiers=["endswith"],
                            values=["\\py"],
                        ),
                    ],
                ),
            ],
            "condition": ConditionExpression(selection="match_1"),
        }
    )
    result = short_image_endswith(short)
    assert result is not None
    assert result.heuristic_id == "h-012"
    assert "too short" in result.message.lower()


def test_h012_does_not_fire_on_full_filename(benign_rule: SigmaRule) -> None:
    r"""The benign baseline uses `\powershell.exe` — well over the 5-char floor."""
    assert short_image_endswith(benign_rule) is None
