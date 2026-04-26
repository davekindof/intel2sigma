"""Pydantic v2 schema for observation-type catalog files under ``data/taxonomy/``.

These models define the shape of a single observation-type YAML. The loader in
:mod:`intel2sigma.core.taxonomy.loader` validates every bundled file against
them at startup and fails fast on any violation.

Per CLAUDE.md I-5, catalog content lives in data; this module defines *what
shape the data must take*, not the data itself.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from intel2sigma.core.model import LogSource, ValueModifier

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class FieldType(StrEnum):
    """Input-type classification used by the composer for validation and
    default-modifier selection.

    Drives Stage 1 UX: ``path`` fields get path normalization hints,
    ``hash`` fields validate MD5/SHA1/SHA256 lengths, ``ip`` fields validate
    addresses and enable the ``cidr`` modifier, and so on. See
    ``docs/taxonomy.md`` for the authoritative definitions.
    """

    PATH = "path"
    STRING = "string"
    HASH = "hash"
    IP = "ip"
    INT = "int"
    ENUM = "enum"
    REGEX = "regex"


class PlatformTier(StrEnum):
    """Relative prominence of a platform variant in the Stage 0 card.

    Primary platforms are promoted in the UI; secondary platforms are
    available but visually de-emphasized.
    """

    PRIMARY = "primary"
    SECONDARY = "secondary"


# UI groups used by Stage 0 ("Observation selection"). Fixed by the
# wireframe in ``docs/ui.md``. Adding a new group is a code + UI change, not
# a pure data change. Two cloud/audit groups added as part of the Phase B1
# observable expansion (corpus-frequency analysis surfaced 23 ≥15-rule
# logsources outside the original five buckets — AWS CloudTrail, Windows
# Security channel, Okta, etc.).
CategoryGroup = Literal[
    "process_and_execution",
    "file_and_registry",
    "network",
    "scheduled_and_system",
    "powershell_and_scripting",
    "os_event_log",  # Windows Security/System/Application/Defender, Linux auditd
    "audit_and_identity",  # AWS CloudTrail, Azure logs, GCP audit, Okta, GitHub audit
]


# ---------------------------------------------------------------------------
# Base with shared config
# ---------------------------------------------------------------------------


class _Model(BaseModel):
    """Project-wide taxonomy Pydantic base.

    ``extra='forbid'`` makes a typo in a data file fail loudly, consistent
    with the fail-fast loader policy (see :mod:`.loader`).
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )


# ---------------------------------------------------------------------------
# Entity models
# ---------------------------------------------------------------------------


class PlatformVariant(_Model):
    """One platform an observation type supports.

    ``id`` is an intel2sigma-internal identifier (``windows``, ``linux``,
    ``macos``). ``product`` is the Sigma ``logsource.product`` value used when
    the rule is serialized, which usually matches ``id`` but need not (some
    variants target a specific product subfamily).
    """

    id: str = Field(min_length=1)
    product: str = Field(min_length=1)
    tier: PlatformTier


class TaxonomyField(_Model):
    """One catalog entry describing a Sigma detection field.

    Fields within an :class:`ObservationTypeSpec` are intentionally ordered:
    the declaration order is the real-world-frequency ranking for that
    observation type. The composer UI consumes that ordering to decide which
    fields to surface prominently (e.g. top-N in the default dropdown) and
    which to leave in a secondary list, so the catalog doesn't have to commit
    to a binary core/advanced split at data-authoring time.

    Invariants enforced on construction:
      * ``default_modifier`` must appear in ``allowed_modifiers``
      * ``type == ENUM`` requires a non-empty ``values`` list
      * ``type != ENUM`` forbids ``values``
    """

    name: str = Field(min_length=1)
    label: str = Field(min_length=1)
    type: FieldType
    default_modifier: ValueModifier
    allowed_modifiers: list[ValueModifier] = Field(min_length=1)
    example: str | None = None
    note: str | None = None
    values: list[str] | None = None

    @model_validator(mode="after")
    def _default_modifier_is_allowed(self) -> TaxonomyField:
        if self.default_modifier not in self.allowed_modifiers:
            raise ValueError(
                f"field {self.name!r}: default_modifier {self.default_modifier!r} "
                f"is not in allowed_modifiers {self.allowed_modifiers!r}"
            )
        return self

    @model_validator(mode="after")
    def _enum_invariants(self) -> TaxonomyField:
        if self.type is FieldType.ENUM:
            if not self.values:
                raise ValueError(
                    f"field {self.name!r}: type=enum requires a non-empty 'values' list"
                )
        elif self.values is not None:
            raise ValueError(f"field {self.name!r}: 'values' is only valid on type=enum fields")
        return self


_IdPattern = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$", min_length=1)]


class ObservationTypeSpec(_Model):
    """One observation-type catalog file.

    The file's ``id`` must match the stem of its filename — the loader
    enforces this. ``logsource`` is the template carried into every rule
    built against this observation type; the composer may override per-rule
    but usually doesn't.
    """

    id: _IdPattern
    label: str = Field(min_length=1)
    description: str = Field(min_length=1)
    category_group: CategoryGroup
    logsource: LogSource
    platforms: list[PlatformVariant] = Field(min_length=1)
    synonyms: list[str] = Field(default_factory=list)
    fields: list[TaxonomyField] = Field(min_length=1)

    @model_validator(mode="after")
    def _platform_ids_unique(self) -> ObservationTypeSpec:
        ids = [p.id for p in self.platforms]
        if len(set(ids)) != len(ids):
            raise ValueError(f"observation {self.id!r}: duplicate platform id(s) in {ids!r}")
        return self

    @model_validator(mode="after")
    def _field_names_unique(self) -> ObservationTypeSpec:
        names = [f.name for f in self.fields]
        if len(set(names)) != len(names):
            raise ValueError(f"observation {self.id!r}: duplicate field name(s) in {names!r}")
        return self
