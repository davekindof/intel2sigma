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

    ``values`` is always a list so the (single value vs. list) distinction in
    YAML is a pure serialization concern rather than a model concern. The
    serializer collapses single-element lists to scalars where that is the
    canonical shape.
    """

    field: str = Field(min_length=1)
    modifiers: list[ValueModifier] = Field(default_factory=list)
    values: list[str | int | bool] = Field(default_factory=list, min_length=1)

    @field_validator("field")
    @classmethod
    def _field_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("DetectionItem.field must not be blank")
        return value


class DetectionBlock(_Model):
    """A named Sigma selection.

    Marked as either a *match* block (contributes positively to the rule firing)
    or a *filter* block (an except-when clause). This marking lets the composer
    auto-assemble the condition.
    """

    name: str = Field(min_length=1)
    is_filter: bool = False
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
