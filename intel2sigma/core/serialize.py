"""Canonical Sigma YAML serializer.

Uses ``ruamel.yaml`` (not ``PyYAML``) so we control emission order, quoting, and
flow style explicitly. The round-trip guarantee from SPEC.md — parsing a
canonical rule and re-serializing produces byte-identical output — is what this
module exists to uphold.

Canonical key order (SPEC.md):
    title, id, status, description, references, author, date, modified, tags,
    logsource, detection, condition, falsepositives, level
"""

from __future__ import annotations

import io
from typing import Any, cast

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

from intel2sigma.core.model import (
    ConditionExpression,
    ConditionOp,
    DetectionBlock,
    DetectionItem,
    LogSource,
    SigmaRule,
)

# Exact emission order for top-level rule keys.
_CANONICAL_ORDER: tuple[str, ...] = (
    "title",
    "id",
    "status",
    "description",
    "references",
    "author",
    "date",
    "modified",
    "tags",
    "logsource",
    "detection",
    "condition",
    "falsepositives",
    "level",
)

# Keys that are omitted from emission when empty, so round-trip remains stable
# for minimal rules.
_OMIT_WHEN_EMPTY: frozenset[str] = frozenset(
    {
        "references",
        "tags",
        "falsepositives",
        "modified",
        "description",
        "author",
    }
)


def _yaml() -> YAML:
    """Fresh ``YAML`` instance configured for canonical emission."""
    y = YAML(typ="rt")  # round-trip preserves comments and ordering
    y.default_flow_style = False
    y.allow_unicode = True
    y.indent(mapping=2, sequence=4, offset=2)
    y.width = 120
    return y


# ---------------------------------------------------------------------------
# Condition rendering
# ---------------------------------------------------------------------------


def _render_condition(expr: ConditionExpression) -> str:
    """Render a ``ConditionExpression`` to its Sigma string form.

    The composer assembles the tree; pySigma parses the string form. We render
    in a single deterministic way so that the byte-identical round-trip
    guarantee holds.
    """
    if expr.op is None:
        if expr.selection is None:
            raise ValueError("Leaf ConditionExpression must have a selection")
        return expr.selection

    if expr.op is ConditionOp.NOT:
        if len(expr.children) != 1:
            raise ValueError("NOT condition must have exactly one child")
        return f"not {_render_condition(expr.children[0])}"

    if expr.op in (ConditionOp.AND, ConditionOp.OR):
        if not expr.children:
            raise ValueError(f"{expr.op.value} condition must have children")
        joiner = f" {expr.op.value} "
        rendered = [_render_condition(c) for c in expr.children]
        parts = [
            r if _is_atomic(c) else f"({r})" for c, r in zip(expr.children, rendered, strict=True)
        ]
        return joiner.join(parts)

    if expr.op in (ConditionOp.ALL_OF, ConditionOp.ONE_OF):
        # Shape: a single leaf child whose selection carries the glob.
        if len(expr.children) != 1 or expr.children[0].selection is None:
            raise ValueError(f"{expr.op.value} condition must have one leaf child")
        verb = "all of" if expr.op is ConditionOp.ALL_OF else "1 of"
        return f"{verb} {expr.children[0].selection}"

    raise ValueError(f"Unhandled ConditionOp: {expr.op}")


def _is_atomic(expr: ConditionExpression) -> bool:
    """Whether ``expr`` renders without needing outer parentheses."""
    if expr.op is None:
        return True
    return expr.op in (ConditionOp.ALL_OF, ConditionOp.ONE_OF, ConditionOp.NOT)


# ---------------------------------------------------------------------------
# Model → YAML structure
# ---------------------------------------------------------------------------


def _logsource_to_map(ls: LogSource) -> CommentedMap:
    out = CommentedMap()
    for key in ("category", "product", "service", "definition"):
        value = getattr(ls, key)
        if value is not None:
            out[key] = value
    return out


def _detection_item_key(item: DetectionItem) -> str:
    """Build the Sigma detection-item key including its modifier chain."""
    if not item.modifiers:
        return item.field
    return item.field + "|" + "|".join(item.modifiers)


def _values_to_yaml(values: list[str | int | bool]) -> Any:
    """Collapse single-value lists to scalars; keep multi-value lists."""
    if len(values) == 1:
        return values[0]
    return list(values)


def _detections_to_map(blocks: list[DetectionBlock]) -> CommentedMap:
    """Build the `detection` block body.

    Mapping form for ``combinator == "all_of"`` (fields AND'd), list-of-mappings
    form for ``any_of`` (fields OR'd). See :class:`DetectionBlock` for the
    semantics and a YAML example.
    """
    out = CommentedMap()
    for block in blocks:
        if block.combinator == "any_of":
            out[block.name] = [
                {_detection_item_key(item): _values_to_yaml(item.values)} for item in block.items
            ]
        else:
            block_map = CommentedMap()
            for item in block.items:
                block_map[_detection_item_key(item)] = _values_to_yaml(item.values)
            out[block.name] = block_map
    return out


def to_yaml(rule: SigmaRule) -> str:
    """Serialize ``rule`` to canonical Sigma YAML.

    Emission order is fixed by ``_CANONICAL_ORDER``. Empty optional fields are
    omitted (see ``_OMIT_WHEN_EMPTY``) so that round-tripping a minimal rule
    does not sprout empty keys.
    """
    data = CommentedMap()
    for key in _CANONICAL_ORDER:
        value = _field_value(rule, key)
        if _should_omit(key, value):
            continue
        data[key] = value

    buf = io.StringIO()
    _yaml().dump(data, buf)
    return buf.getvalue()


def _field_value(rule: SigmaRule, key: str) -> Any:
    match key:
        case "id":
            return str(rule.id)
        case "date" | "modified":
            value = getattr(rule, key)
            return value.isoformat() if value is not None else None
        case "logsource":
            return _logsource_to_map(rule.logsource)
        case "detection":
            # Canonical detection block: named selections + condition string.
            det = _detections_to_map(rule.detections)
            det["condition"] = _render_condition(rule.condition)
            return det
        case "condition":
            # The condition string is embedded inside the detection block per
            # Sigma spec, so the top-level ``condition`` key is a model-only
            # concept and never emitted directly.
            return _OMITTED
        case _:
            return getattr(rule, key)


class _Sentinel:
    __slots__ = ()


_OMITTED = _Sentinel()


def _should_omit(key: str, value: Any) -> bool:
    if value is _OMITTED:
        return True
    if value is None:
        return True
    return bool(key in _OMIT_WHEN_EMPTY and not value)


# ---------------------------------------------------------------------------
# YAML → model
# ---------------------------------------------------------------------------


def from_yaml(text: str) -> SigmaRule:
    """Parse canonical Sigma YAML back into a :class:`SigmaRule`.

    The inverse of :func:`to_yaml`. Condition-string parsing is intentionally
    limited to shapes the composer itself emits — hand-written Sigma rules with
    complex conditions should enter through pySigma, not through this round-
    trip path.
    """
    loaded = _yaml().load(text)
    if not isinstance(loaded, dict):
        raise TypeError("Top-level YAML document must be a mapping")
    data = cast(dict[str, Any], loaded)

    detection_raw = data.get("detection")
    if not isinstance(detection_raw, dict):
        raise TypeError("'detection' block must be a mapping")

    condition_str = detection_raw.get("condition")
    if not isinstance(condition_str, str):
        raise TypeError("'detection.condition' must be a string")

    blocks = [
        _parse_detection_block(name, body)
        for name, body in detection_raw.items()
        if name != "condition"
    ]
    condition = _parse_condition_string(condition_str, {b.name for b in blocks})

    logsource_raw = data.get("logsource") or {}
    if not isinstance(logsource_raw, dict):
        raise TypeError("'logsource' must be a mapping")

    return SigmaRule(
        title=str(data["title"]),
        id=data["id"],
        status=data.get("status", "experimental"),
        description=data.get("description", ""),
        references=list(data.get("references", []) or []),
        author=data.get("author", ""),
        date=data["date"],
        modified=data.get("modified"),
        tags=list(data.get("tags", []) or []),
        logsource=LogSource(**logsource_raw),
        detections=blocks,
        condition=condition,
        falsepositives=list(data.get("falsepositives", []) or []),
        level=data.get("level", "medium"),
    )


def _detection_item_from_yaml(key: Any, raw_value: Any) -> DetectionItem:
    """Build a :class:`DetectionItem` from a single YAML key/value pair.

    Handles both the scalar and list value shapes, and splits the ``|``-
    delimited modifier chain out of the key.
    """
    field, *modifiers = str(key).split("|")
    values = raw_value if isinstance(raw_value, list) else [raw_value]
    return DetectionItem(
        field=field,
        # Pydantic validates modifier strings against the ValueModifier
        # Literal at construction time; mypy can't see that narrowing.
        modifiers=list(modifiers),  # type: ignore[arg-type]
        values=list(values),
    )


def _parse_detection_block(name: str, body: Any) -> DetectionBlock:
    """Parse either the mapping or list-of-mappings form.

    Mapping form → ``combinator="all_of"``. List-of-mappings form →
    ``combinator="any_of"``. Multi-field entries in the list form (which
    would represent an AND-subgroup inside an OR) flatten into individual
    items — see the class docstring on :class:`DetectionBlock` for why
    this is an accepted fidelity loss in v1.
    """
    is_filter = name.startswith("filter")
    items: list[DetectionItem] = []

    if isinstance(body, list):
        for entry in body:
            if not isinstance(entry, dict):
                raise TypeError(f"Detection block '{name}': list entries must be mappings")
            for key, raw_value in entry.items():
                items.append(_detection_item_from_yaml(key, raw_value))
        return DetectionBlock(name=name, is_filter=is_filter, combinator="any_of", items=items)

    if not isinstance(body, dict):
        raise TypeError(f"Detection block '{name}' must be a mapping or a list of mappings")

    for key, raw_value in body.items():
        items.append(_detection_item_from_yaml(key, raw_value))
    return DetectionBlock(name=name, is_filter=is_filter, items=items)


def _parse_condition_string(text: str, block_names: set[str]) -> ConditionExpression:
    """Parse the subset of condition strings the composer emits.

    Recognised shapes:
      - ``<selection>``
      - ``not <selection>``
      - ``<a> and <b> [and ...]``
      - ``<a> or <b> [or ...]``
      - ``all of <glob>`` / ``1 of <glob>``
      - ``(<expr>) and not (<expr>)`` and similar one-level combinations
      - mixed forms where a quantifier clause joins a direct selection via
        ``and``/``or``, e.g. ``1 of selection_parent_* and selection_child``

    Precedence (lowest first): ``and``/``or`` → ``not`` → quantifier prefix →
    selection name. Top-level boolean splits are evaluated before prefix
    matching so a quantifier clause can appear as one conjunct/disjunct without
    greedily consuming the rest of the expression.

    Hand-written rules with arbitrary precedence are not round-trippable
    through this loader by design.
    """
    stripped = text.strip()
    if not stripped:
        raise ValueError("Empty condition string")

    # Top-level AND / OR split (lowest precedence) respecting paren depth.
    # Must run before prefix matching so inputs like
    # "1 of selection_* and other" are not greedily consumed by the
    # quantifier branch.
    for op_token, op in (("and", ConditionOp.AND), ("or", ConditionOp.OR)):
        parts = _split_top_level(stripped, op_token)
        if len(parts) > 1:
            return ConditionExpression(
                op=op,
                children=[_parse_condition_string(p, block_names) for p in parts],
            )

    # NOT prefix binds to whatever follows.
    if stripped.startswith("not "):
        inner = stripped.removeprefix("not ").strip()
        return ConditionExpression(
            op=ConditionOp.NOT,
            children=[_parse_condition_string(inner, block_names)],
        )

    # Selection-glob quantifiers.
    if stripped.startswith("all of "):
        glob = stripped.removeprefix("all of ").strip()
        return ConditionExpression(
            op=ConditionOp.ALL_OF,
            children=[ConditionExpression(selection=glob)],
        )
    if stripped.startswith("1 of "):
        glob = stripped.removeprefix("1 of ").strip()
        return ConditionExpression(
            op=ConditionOp.ONE_OF,
            children=[ConditionExpression(selection=glob)],
        )

    # Stripped parens around a bare selection: ``(selection_a)``.
    if stripped.startswith("(") and stripped.endswith(")"):
        return _parse_condition_string(stripped[1:-1], block_names)

    if stripped not in block_names:
        raise ValueError(f"Condition references unknown selection: {stripped!r}")
    return ConditionExpression(selection=stripped)


def _split_top_level(text: str, token: str) -> list[str]:
    """Split ``text`` on ``token`` at paren-depth zero.

    Matches ``token`` only at word boundaries to avoid splitting ``pandoc``
    on ``and``.
    """
    depth = 0
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    token_pad = f" {token} "
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch == ")":
            depth -= 1
            buf.append(ch)
            i += 1
            continue
        if depth == 0 and text.startswith(token_pad, i - 1):
            # The previous char is the leading space; collapse it from buf.
            if buf and buf[-1] == " ":
                buf.pop()
            parts.append("".join(buf).strip())
            buf = []
            i += len(token_pad) - 1
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf).strip())
    return [p for p in parts if p]
