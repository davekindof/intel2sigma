"""Tier-1 validation — blocking cross-field checks.

Pydantic enforces field-level invariants at construction time; this module
handles the cross-field rules Pydantic cannot see:

* Every selection name referenced by the condition tree exists as a
  DetectionBlock.
* If the rule's logsource matches a catalogued observation type, every
  DetectionItem uses a declared field with modifiers the taxonomy allows.
* Enum-typed field values match the declared value set.

An unrecognised logsource is **not** an error. The catalog is deliberately
incomplete (cloud sources, niche categories), and rules targeting an
uncatalogued source are still valid Sigma — we simply cannot introspect
their fields. The taxonomy-dependent checks are skipped in that case.

All issues are tier=1 and considered blocking per SPEC.md's validation
tiers.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import cache

from intel2sigma.core.model import (
    ConditionExpression,
    DetectionItem,
    SigmaRule,
)
from intel2sigma.core.taxonomy import (
    ObservationTypeSpec,
    TaxonomyField,
    TaxonomyRegistry,
    load_taxonomy,
)
from intel2sigma.core.taxonomy.schema import FieldType
from intel2sigma.core.validate.issues import ValidationIssue

# Error codes surfaced by this tier. Stable strings so consumers can branch.
CODE_CONDITION_UNKNOWN_SELECTION = "T1_CONDITION_UNKNOWN_SELECTION"
CODE_FIELD_NOT_IN_TAXONOMY = "T1_FIELD_NOT_IN_TAXONOMY"
CODE_MODIFIER_NOT_ALLOWED = "T1_MODIFIER_NOT_ALLOWED"
CODE_ENUM_VALUE_INVALID = "T1_ENUM_VALUE_INVALID"


@cache
def _default_taxonomy() -> TaxonomyRegistry:
    """Lazy-load + cache the bundled taxonomy for default validator calls."""
    return load_taxonomy()


def validate_tier1(
    rule: SigmaRule,
    taxonomy: TaxonomyRegistry | None = None,
) -> list[ValidationIssue]:
    """Run every tier-1 check against ``rule`` and return all issues found.

    Args:
        rule: The in-memory Sigma rule.
        taxonomy: Optional registry injected for tests. Defaults to the
            bundled catalog loaded once and cached.

    Returns:
        A list of :class:`ValidationIssue`. Empty list = the rule passes
        tier 1. Ordered stably so consumers can diff two runs.
    """
    registry = taxonomy if taxonomy is not None else _default_taxonomy()
    issues: list[ValidationIssue] = []

    block_names = {b.name for b in rule.detections}
    issues.extend(_check_condition_integrity(rule.condition, block_names))

    spec = _lookup_observation(rule, registry)
    if spec is not None:
        issues.extend(_check_fields_against_taxonomy(rule, spec))

    return issues


# ---------------------------------------------------------------------------
# Condition integrity
# ---------------------------------------------------------------------------


def _check_condition_integrity(
    expr: ConditionExpression,
    block_names: set[str],
    *,
    location: str = "condition",
) -> Iterable[ValidationIssue]:
    """Every leaf selection in the condition tree must exist as a block.

    Globs (``selection_*``) are accepted if at least one existing block name
    matches the glob pattern.
    """
    if expr.op is None:
        # Leaf: a bare selection reference.
        if expr.selection is None:
            return
        if expr.selection not in block_names:
            yield ValidationIssue(
                tier=1,
                code=CODE_CONDITION_UNKNOWN_SELECTION,
                message=(
                    f"Condition references selection {expr.selection!r} "
                    f"but no detection block by that name exists."
                ),
                location=location,
            )
        return

    # Quantifier nodes carry a glob in their single child's selection.
    if expr.op.value in ("all_of", "one_of"):
        glob = expr.children[0].selection if expr.children else None
        if glob is None:
            return
        if not _glob_matches_any(glob, block_names):
            yield ValidationIssue(
                tier=1,
                code=CODE_CONDITION_UNKNOWN_SELECTION,
                message=(
                    f"Condition quantifier {expr.op.value!r} references "
                    f"glob {glob!r} but no detection block name matches."
                ),
                location=location,
            )
        return

    # Compound nodes — recurse into each child.
    for idx, child in enumerate(expr.children):
        yield from _check_condition_integrity(child, block_names, location=f"{location}[{idx}]")


def _glob_matches_any(glob: str, names: set[str]) -> bool:
    """Sigma selection globs use ``*`` as a suffix wildcard (plus prefix).

    This mirrors pySigma's own implementation: the glob becomes a regex that
    treats ``*`` as ``.*``. Any block name matching it is enough.
    """
    pattern = re.compile("^" + re.escape(glob).replace(r"\*", ".*") + "$")
    return any(pattern.match(n) for n in names)


# ---------------------------------------------------------------------------
# Taxonomy-dependent checks
# ---------------------------------------------------------------------------


def _lookup_observation(
    rule: SigmaRule,
    registry: TaxonomyRegistry,
) -> ObservationTypeSpec | None:
    """Find the catalog entry matching ``rule.logsource.category``.

    Returns ``None`` if the rule's category is not catalogued — callers skip
    the taxonomy-dependent checks in that case.
    """
    category = rule.logsource.category
    if not category:
        return None
    for obs_id in registry.all_ids():
        spec = registry.get(obs_id)
        if spec.logsource.category == category:
            # Platform product match (if both sides declare product).
            if rule.logsource.product and spec.platforms:
                platform_products = {p.product for p in spec.platforms}
                if rule.logsource.product not in platform_products:
                    continue
            return spec
    return None


def _check_fields_against_taxonomy(
    rule: SigmaRule,
    spec: ObservationTypeSpec,
) -> Iterable[ValidationIssue]:
    fields_by_name = {f.name: f for f in spec.fields}
    for block_idx, block in enumerate(rule.detections):
        for item_idx, item in enumerate(block.items):
            loc = f"detections[{block_idx}].items[{item_idx}]"
            yield from _check_item(item, fields_by_name, spec.id, loc)


def _check_item(
    item: DetectionItem,
    fields_by_name: dict[str, TaxonomyField],
    observation_id: str,
    location: str,
) -> Iterable[ValidationIssue]:
    field_spec = fields_by_name.get(item.field)
    if field_spec is None:
        yield ValidationIssue(
            tier=1,
            code=CODE_FIELD_NOT_IN_TAXONOMY,
            message=(
                f"Field {item.field!r} is not declared for observation "
                f"{observation_id!r}. Known fields: "
                f"{sorted(fields_by_name)!r}."
            ),
            location=location,
        )
        return

    allowed = set(field_spec.allowed_modifiers)
    for modifier in item.modifiers:
        if modifier not in allowed:
            yield ValidationIssue(
                tier=1,
                code=CODE_MODIFIER_NOT_ALLOWED,
                message=(
                    f"Modifier {modifier!r} is not allowed on field "
                    f"{item.field!r} (allowed: "
                    f"{sorted(allowed)!r})."
                ),
                location=location,
            )

    if field_spec.type is FieldType.ENUM and field_spec.values is not None:
        enum_values = set(field_spec.values)
        for value in item.values:
            if isinstance(value, str) and value not in enum_values:
                yield ValidationIssue(
                    tier=1,
                    code=CODE_ENUM_VALUE_INVALID,
                    message=(
                        f"Value {value!r} is not a valid choice for enum "
                        f"field {item.field!r} (choices: "
                        f"{sorted(enum_values)!r})."
                    ),
                    location=location,
                )


__all__ = [
    "CODE_CONDITION_UNKNOWN_SELECTION",
    "CODE_ENUM_VALUE_INVALID",
    "CODE_FIELD_NOT_IN_TAXONOMY",
    "CODE_MODIFIER_NOT_ALLOWED",
    "validate_tier1",
]
