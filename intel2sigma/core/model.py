"""In-memory Pydantic v2 representation of a Sigma rule.

The model is the source of truth inside the process. It round-trips to canonical
Sigma YAML via :mod:`intel2sigma.core.serialize` and is validated by the tiered
validators in :mod:`intel2sigma.core.validate`.

Per SPEC.md the model must be extensible for correlation rules (v2) without
breaking v1 consumers. Keep field additions additive and optional where
possible.
"""

from __future__ import annotations

from datetime import date as _date
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

RuleStatus = Literal[
    "stable",
    "test",
    "experimental",
    "deprecated",
    "unsupported",
]

RuleLevel = Literal[
    "informational",
    "low",
    "medium",
    "high",
    "critical",
]

# Sigma value modifiers most composers need. This is the list we surface in
# dropdowns; pySigma accepts additional less-common ones that may be added
# later without model changes.
ValueModifier = Literal[
    "contains",
    "startswith",
    "endswith",
    "all",
    "exact",
    "re",
    "cased",
    "base64",
    "base64offset",
    "utf16",
    "utf16le",
    "utf16be",
    "wide",
    "windash",
    "cidr",
    "gt",
    "gte",
    "lt",
    "lte",
]


class ConditionOp(StrEnum):
    """Logical operators recognised by the deterministic composer."""

    AND = "and"
    OR = "or"
    NOT = "not"
    ALL_OF = "all_of"
    ONE_OF = "one_of"


# ---------------------------------------------------------------------------
# Base model with shared config
# ---------------------------------------------------------------------------


class _Model(BaseModel):
    """Project-wide Pydantic base.

    ``extra='forbid'`` — unknown keys are a serialization bug, not a courtesy
    to forward-compat. Mis-spelled field names fail loudly in tests.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=False,
        str_strip_whitespace=True,
        validate_assignment=True,
    )


# ---------------------------------------------------------------------------
# Logsource
# ---------------------------------------------------------------------------


class LogSource(_Model):
    """Sigma logsource block.

    At least one of ``category``, ``product``, or ``service`` must be set for a
    rule to be convertible by pySigma. The model allows all-None only so that
    an in-progress rule during stage 0 is still representable.
    """

    category: str | None = None
    product: str | None = None
    service: str | None = None
    definition: str | None = None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class DetectionItem(_Model):
    """A single field-modifier-value triple inside a detection block.

    Two shapes:

    * **Field-match item** — ``field`` is set; the rule matches
      against the named event field. The common case.
    * **Keyword-search item** — ``field`` is empty; the rule matches
      *any* event field against the value list. Sigma's idiom for
      "fire if any of these strings appears anywhere in the event"
      — common in auditd / Zeek / network-traffic rules. SigmaHQ
      examples include ``filter_keywords: [samr, lsarpc, winreg]``.
      The L1 corpus audit (``e9a040b``) counted 100+ corpus rules
      using this shape.

    ``values`` is always a list so the (single value vs. list)
    distinction in YAML is a pure serialization concern rather than
    a model concern. The serializer collapses single-element lists
    to scalars where that is the canonical shape.

    *Whitespace handling.* Overrides the project-wide
    ``str_strip_whitespace=True`` to ``False`` because detection
    values can legitimately be (or end with) literal whitespace —
    ``CommandLine|endswith: ' '`` is a real Sigma idiom (the macOS
    "space after filename" masquerading pattern at SigmaHQ rule
    ``b6e2a2e3-…``). The L1 corpus audit found 55+ rules losing
    values to over-eager whitespace stripping. The
    ``_field_well_formed`` validator below strip-checks the field
    name *only when it's set*, which is the only place we *do* want
    the trim semantic.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=False,
        str_strip_whitespace=False,
        validate_assignment=True,
    )

    # ``field`` is empty for keyword-search items, populated for
    # field-match items. Pre-L2-P1b this had ``min_length=1`` and
    # rejected empty strings outright; that broke 106+ corpus rules
    # using the keyword-search idiom.
    field: str = ""
    modifiers: list[ValueModifier] = Field(default_factory=list)
    # ``None`` is the YAML-null sentinel. Sigma treats ``Field: null``
    # as "match when the field is absent / null" — common in macOS /
    # process-creation rules that skip events with no command line
    # (e.g. ``filter_optional_null: { CommandLine: null }``). The L2-
    # P1d corpus audit found 27+ rules using this idiom alongside the
    # explicit-empty-string ``Field: ''`` form. Both are now first-
    # class values; the serializer renders ``None`` back to YAML null
    # and the empty string to a quoted ``''``.
    values: list[str | int | bool | None] = Field(default_factory=list, min_length=1)

    @field_validator("field")
    @classmethod
    def _field_well_formed(cls, value: str) -> str:
        # Empty string ``""`` is the keyword-search marker; allow it.
        # Whitespace-only ``"   "`` is always a typo — never legitimate.
        if value and not value.strip():
            raise ValueError("DetectionItem.field cannot be whitespace-only")
        return value

    @property
    def is_keyword(self) -> bool:
        """True when this item is a keyword-search shape (no field set)."""
        return not self.field


BlockCombinator = Literal["all_of", "any_of"]


class DetectionBlock(_Model):
    """A named Sigma selection.

    Marked as either a *match* block (contributes positively to the rule firing)
    or a *filter* block (an except-when clause). This marking lets the composer
    auto-assemble the condition.

    The ``combinator`` field controls the emission shape:

      * ``all_of`` (default) → mapping form, fields AND'd together:

        .. code-block:: yaml

            match_1:
              Image|endswith: \\foo.exe
              CommandLine|contains: -bar

      * ``any_of`` → list-of-mappings form, fields OR'd:

        .. code-block:: yaml

            match_1:
              - Image|endswith: \\foo.exe
              - CommandLine|contains: -bar

    For arbitrarily nested shapes ((A AND B) OR (C AND D) within one block),
    users are expected to split into multiple blocks and combine across them
    via the rule-level match combinator. Multi-field sub-groups within a
    single list entry are not modeled here; the narrow-scope ``from_yaml``
    loader flattens them, which may lose fidelity on hand-written rules that
    use that shape. The composer itself never emits multi-field sub-groups.
    """

    name: str = Field(min_length=1)
    is_filter: bool = False
    combinator: BlockCombinator = "all_of"
    items: list[DetectionItem] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _name_is_identifier_like(cls, value: str) -> str:
        # Sigma selection keys are freeform but restricting to identifier-ish
        # names prevents users from breaking YAML by naming a block with ``:``.
        if not value or any(c.isspace() for c in value) or ":" in value:
            raise ValueError(
                "DetectionBlock.name must be non-empty and contain no whitespace or ':'"
            )
        return value


class ConditionExpression(_Model):
    """A composer-built condition tree.

    The composer never parses a user-entered condition string; it assembles one
    of these from the block list and the user's chosen combinators, then
    renders it to the Sigma string form at serialization time.

    Leaf nodes carry a ``selection`` name (a DetectionBlock.name). Interior
    nodes carry an ``op`` and ``children``. ``NOT`` has exactly one child;
    ``ALL_OF``/``ONE_OF`` carry a selection glob (e.g. ``"match_*"``) as their
    single leaf child instead of an explicit children list.
    """

    op: ConditionOp | None = None
    selection: str | None = None
    children: list[ConditionExpression] = Field(default_factory=list)

    @field_validator("children")
    @classmethod
    def _non_leaf_has_children(
        cls,
        value: list[ConditionExpression],
    ) -> list[ConditionExpression]:
        return value


# Pydantic v2 requires rebuild for the self-referential list.
ConditionExpression.model_rebuild()


# ---------------------------------------------------------------------------
# Top-level rule
# ---------------------------------------------------------------------------

# Tag format: loose validation at this tier. Tier 3 (SigmaHQ conventions)
# applies the stricter ATT&CK-technique-id pattern advisory checks.
_Tag = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]*$")]


class SigmaRule(_Model):
    """Canonical in-memory Sigma rule.

    Field ordering matches the canonical YAML emission order defined in
    SPEC.md. Serializers rely on this class's declaration order — keep
    additions at the logical location, not at the bottom.
    """

    # Metadata
    title: str = Field(min_length=1, max_length=256)
    id: UUID
    status: RuleStatus = "experimental"
    description: str = ""
    references: list[str] = Field(default_factory=list)
    author: str = ""
    date: _date
    modified: _date | None = None
    tags: list[_Tag] = Field(default_factory=list)

    # Logsource
    logsource: LogSource

    # Detection
    detections: list[DetectionBlock] = Field(default_factory=list)
    condition: ConditionExpression

    # Trailing metadata (canonical emission places these after detection)
    falsepositives: list[str] = Field(default_factory=list)
    level: RuleLevel = "medium"

    @field_validator("title")
    @classmethod
    def _title_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("SigmaRule.title must not be blank")
        return value
