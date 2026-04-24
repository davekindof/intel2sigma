"""Focused tests for the condition-string parser in ``core.serialize``.

These cover shapes that ``to_yaml`` emits, plus real-corpus shapes the parser
must handle without mis-binding the quantifier prefix. The parser's scope is
intentionally narrow (see SPEC.md) — hand-written condition grammar goes
through pySigma, not this loader.
"""

from __future__ import annotations

from intel2sigma.core.model import ConditionOp

# Intentionally exercising the module-private parser so we can test parsing
# semantics without a full YAML round-trip.
from intel2sigma.core.serialize import _parse_condition_string


def test_bare_selection() -> None:
    expr = _parse_condition_string("match_1", {"match_1"})
    assert expr.op is None
    assert expr.selection == "match_1"


def test_not_prefix() -> None:
    expr = _parse_condition_string("not filter_1", {"filter_1"})
    assert expr.op is ConditionOp.NOT
    assert expr.children[0].selection == "filter_1"


def test_flat_and() -> None:
    expr = _parse_condition_string("match_1 and match_2", {"match_1", "match_2"})
    assert expr.op is ConditionOp.AND
    assert [c.selection for c in expr.children] == ["match_1", "match_2"]


def test_flat_or() -> None:
    expr = _parse_condition_string("a or b or c", {"a", "b", "c"})
    assert expr.op is ConditionOp.OR
    assert [c.selection for c in expr.children] == ["a", "b", "c"]


def test_all_of_glob() -> None:
    expr = _parse_condition_string("all of selection_*", {"selection_1"})
    assert expr.op is ConditionOp.ALL_OF
    assert expr.children[0].selection == "selection_*"


def test_one_of_glob() -> None:
    expr = _parse_condition_string("1 of selection_*", {"selection_1"})
    assert expr.op is ConditionOp.ONE_OF
    assert expr.children[0].selection == "selection_*"


def test_quantifier_joined_with_selection_via_and() -> None:
    """Regression test for the ordering bug.

    Real-corpus shape from rules-emerging-threats CVE-2025-59287:
        ``1 of selection_parent_* and selection_child``
    Must parse as AND(ONE_OF(selection_parent_*), selection_child), NOT as
    ONE_OF("selection_parent_* and selection_child").
    """
    expr = _parse_condition_string(
        "1 of selection_parent_* and selection_child",
        {"selection_parent_wsusservice", "selection_parent_w3wp", "selection_child"},
    )
    assert expr.op is ConditionOp.AND
    assert len(expr.children) == 2

    quantified, direct = expr.children
    assert quantified.op is ConditionOp.ONE_OF
    assert quantified.children[0].selection == "selection_parent_*"

    assert direct.op is None
    assert direct.selection == "selection_child"


def test_selection_and_not_filter() -> None:
    """Canonical composer-emitted shape: match_1 and not filter_1."""
    expr = _parse_condition_string("match_1 and not filter_1", {"match_1", "filter_1"})
    assert expr.op is ConditionOp.AND
    assert expr.children[0].selection == "match_1"
    assert expr.children[1].op is ConditionOp.NOT
    assert expr.children[1].children[0].selection == "filter_1"


def test_parenthesized_selection() -> None:
    expr = _parse_condition_string("(match_1)", {"match_1"})
    assert expr.selection == "match_1"
