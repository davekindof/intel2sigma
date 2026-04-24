"""Permissive rule draft carried between htmx requests.

Shape and rationale: see docs/web-state-model.md.

A :class:`RuleDraft` is what the composer mutates. Unlike
:class:`~intel2sigma.core.model.SigmaRule`, every field is optional or has a
sensible default so a stage-0 user with no title or detection blocks is
still representable. Conversion to a strict ``SigmaRule`` happens at
preview-render time or at stage transitions via :meth:`RuleDraft.to_sigma_rule`.

The draft round-trips through JSON in a hidden ``<textarea>`` in the shell.
``RuleDraft.from_json`` / ``.model_dump_json()`` are the wire format;
``.to_sigma_rule()`` is the validation/materialization gate.
"""

from __future__ import annotations

from datetime import date as _date  # aliased: RuleDraft.date is a str field
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from intel2sigma.core.model import (
    BlockCombinator,
    ConditionExpression,
    ConditionOp,
    DetectionBlock,
    DetectionItem,
    LogSource,
    RuleLevel,
    RuleStatus,
    SigmaRule,
    ValueModifier,
)
from intel2sigma.core.validate.issues import ValidationIssue


class _Model(BaseModel):
    """All drafts forbid extra keys so typos in JSON round-trips fail loudly."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LogSourceDraft(_Model):
    category: str | None = None
    product: str | None = None
    service: str | None = None


class DetectionItemDraft(_Model):
    """One field|modifier|value row in the composer.

    ``values`` is always list[str] for draft purposes — coercion to int/bool
    happens at to_sigma_rule() time, since the composer widgets are text
    inputs regardless of the underlying field type.
    """

    field: str = ""
    modifiers: list[ValueModifier] = Field(default_factory=list)
    values: list[str] = Field(default_factory=list)


class DetectionBlockDraft(_Model):
    name: str = ""
    is_filter: bool = False
    # Mirror of ``DetectionBlock.combinator`` — see the core-model docstring
    # for the semantics and YAML emission shapes.
    combinator: BlockCombinator = "all_of"
    items: list[DetectionItemDraft] = Field(default_factory=list)


# Composer-owned condition representation. Nested dicts rather than a
# recursive Pydantic model — the latter would require model_rebuild() and
# fiddly serialization to survive JSON round-trips. Shape:
#
#   {"selection": "match_1"}
#   {"op": "and", "children": [{"selection": "match_1"},
#                              {"op": "not", "children": [{"selection": "filter_1"}]}]}
#   {"op": "all_of", "children": [{"selection": "selection_*"}]}
ConditionTreeDraft = dict[str, Any]


class RuleDraft(_Model):
    """Top-level composer state. Round-trips through the hidden JSON blob."""

    # Metadata — strings so empty-state is representable.
    title: str = ""
    id: UUID | None = None
    status: RuleStatus = "experimental"
    description: str = ""
    references: list[str] = Field(default_factory=list)
    author: str = ""
    date: str = ""  # ISO string; coerced to date in to_sigma_rule()
    modified: str = ""
    tags: list[str] = Field(default_factory=list)
    level: RuleLevel = "medium"
    falsepositives: list[str] = Field(default_factory=list)

    # Observation selection (drives Stage 1's field dropdown)
    observation_id: str = ""
    platform_id: str = ""
    logsource: LogSourceDraft = Field(default_factory=LogSourceDraft)

    # Detection
    detections: list[DetectionBlockDraft] = Field(default_factory=list)
    condition_tree: ConditionTreeDraft | None = None
    # Across-match-blocks combinator used by the auto-composer:
    #   all_of  → condition: all of match_* (blocks AND'd, current default)
    #   any_of  → condition: 1 of match_*   (blocks OR'd)
    # Filter blocks are always NOT'd regardless of this field.
    match_combinator: BlockCombinator = "all_of"

    # Composer-local state — not exported to the rule
    stage: int = 0

    # -------------------------------------------------------------------
    # Serialization
    # -------------------------------------------------------------------

    @classmethod
    def from_json(cls, text: str | None) -> RuleDraft:
        """Deserialize from the hidden textarea value.

        Missing or empty input produces a fresh, empty draft — callers
        typically get this on the initial GET before any state exists.
        """
        if not text or not text.strip():
            return cls()
        try:
            return cls.model_validate_json(text)
        except ValidationError:
            # A corrupted blob in the client shouldn't wedge the composer.
            # Start fresh; the user's in-progress data is already lost on
            # the wire so there's nothing to preserve.
            return cls()

    def to_json(self) -> str:
        """Emit the JSON used in the hidden textarea."""
        return self.model_dump_json()

    # -------------------------------------------------------------------
    # Materialization to core.model.SigmaRule
    # -------------------------------------------------------------------

    def to_sigma_rule(self) -> SigmaRule | list[ValidationIssue]:
        """Attempt conversion to a strict ``core.model.SigmaRule``.

        Returns the validated rule on success, or a list of
        :class:`ValidationIssue` describing every reason it can't be built.
        Issues use ``tier=1`` since they're structural (required-field
        absence, parse failures) — tier-2 concerns like pySigma
        compatibility are checked separately after a successful build.
        """
        issues: list[ValidationIssue] = []

        # UUID
        rule_id = self.id if self.id is not None else uuid4()

        # Date
        parsed_date = self._parse_date(self.date, "date", issues)
        parsed_modified = (
            self._parse_date(self.modified, "modified", issues) if self.modified else None
        )

        # Logsource
        logsource = LogSource(
            category=self.logsource.category or None,
            product=self.logsource.product or None,
            service=self.logsource.service or None,
        )

        # Detection blocks
        blocks: list[DetectionBlock] = []
        for idx, block_draft in enumerate(self.detections):
            block = self._block_to_strict(block_draft, idx, issues)
            if block is not None:
                blocks.append(block)

        # Condition — compose a default tree if none was explicitly set.
        condition = self._compose_condition(blocks)
        if condition is None:
            issues.append(
                ValidationIssue(
                    tier=1,
                    code="DRAFT_CONDITION_EMPTY",
                    message="Cannot build a rule: no detection blocks to reference.",
                    location="condition",
                )
            )

        # Title / required metadata
        if not self.title.strip():
            issues.append(
                ValidationIssue(
                    tier=1,
                    code="DRAFT_TITLE_MISSING",
                    message="Rule title is required.",
                    location="title",
                )
            )

        if issues or condition is None or parsed_date is None:
            return issues or [
                ValidationIssue(
                    tier=1,
                    code="DRAFT_INCOMPLETE",
                    message="Draft is not yet a valid rule.",
                )
            ]

        try:
            return SigmaRule(
                title=self.title,
                id=rule_id,
                status=self.status,
                description=self.description,
                references=list(self.references),
                author=self.author,
                date=parsed_date,
                modified=parsed_modified,
                tags=list(self.tags),
                logsource=logsource,
                detections=blocks,
                condition=condition,
                falsepositives=list(self.falsepositives),
                level=self.level,
            )
        except ValidationError as exc:
            for err in exc.errors():
                loc = ".".join(str(p) for p in err.get("loc", ()))
                issues.append(
                    ValidationIssue(
                        tier=1,
                        code="DRAFT_PYDANTIC_REJECTED",
                        message=err.get("msg", "validation failed"),
                        location=loc or None,
                    )
                )
            return issues

    # -------------------------------------------------------------------
    # Stage-gate predicates — used by composer routes to decide whether the
    # Next button is enabled and whether /composer/advance will honor a
    # transition attempt. Symmetric checks so UI and server agree.
    # -------------------------------------------------------------------

    def can_advance_to_stage(self, target: int) -> bool:
        """True when the draft meets the prerequisites for ``target`` stage.

        Gates:
          1: observation selected
          2: at least one match block with at least one populated item
          3: title + date set
          4: draft.to_sigma_rule() returns a strict rule (no issues)
        """
        match target:
            case 1:
                return bool(self.observation_id)
            case 2:
                matches = [b for b in self.detections if not b.is_filter]
                return any(any(item.field and item.values for item in b.items) for b in matches)
            case 3:
                return bool(self.title.strip()) and bool(self.date.strip())
            case 4:
                return not isinstance(self.to_sigma_rule(), list)
            case _:
                return False

    # -------------------------------------------------------------------
    # Mutation helpers used by composer routes
    # -------------------------------------------------------------------

    def add_match_block(self) -> None:
        """Append a new empty match block with an auto-generated name."""
        existing = {b.name for b in self.detections}
        name = self._next_name("match", existing)
        self.detections.append(DetectionBlockDraft(name=name, is_filter=False))

    def add_filter_block(self) -> None:
        existing = {b.name for b in self.detections}
        name = self._next_name("filter", existing)
        self.detections.append(DetectionBlockDraft(name=name, is_filter=True))

    def add_item(self, block_name: str) -> None:
        block = self._find_block(block_name)
        if block is not None:
            block.items.append(DetectionItemDraft())

    def delete_block(self, block_name: str) -> None:
        self.detections = [b for b in self.detections if b.name != block_name]

    def delete_item(self, block_name: str, item_index: int) -> None:
        block = self._find_block(block_name)
        if block is not None and 0 <= item_index < len(block.items):
            del block.items[item_index]

    # -------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------

    def _find_block(self, name: str) -> DetectionBlockDraft | None:
        return next((b for b in self.detections if b.name == name), None)

    @staticmethod
    def _next_name(prefix: str, existing: set[str]) -> str:
        i = 1
        while f"{prefix}_{i}" in existing:
            i += 1
        return f"{prefix}_{i}"

    @staticmethod
    def _parse_date(value: str, field_name: str, issues: list[ValidationIssue]) -> _date | None:
        if not value:
            issues.append(
                ValidationIssue(
                    tier=1,
                    code="DRAFT_DATE_MISSING",
                    message=f"Rule {field_name} is required.",
                    location=field_name,
                )
            )
            return None
        try:
            return _date.fromisoformat(value)
        except ValueError:
            issues.append(
                ValidationIssue(
                    tier=1,
                    code="DRAFT_DATE_INVALID",
                    message=f"Rule {field_name} {value!r} is not an ISO date (YYYY-MM-DD).",
                    location=field_name,
                )
            )
            return None

    @staticmethod
    def _block_to_strict(
        draft: DetectionBlockDraft,
        block_idx: int,
        issues: list[ValidationIssue],
    ) -> DetectionBlock | None:
        if not draft.name.strip():
            issues.append(
                ValidationIssue(
                    tier=1,
                    code="DRAFT_BLOCK_NAME_MISSING",
                    message=f"Detection block {block_idx} has no name.",
                    location=f"detections[{block_idx}]",
                )
            )
            return None
        strict_items: list[DetectionItem] = []
        for item_idx, item in enumerate(draft.items):
            if not item.field.strip():
                issues.append(
                    ValidationIssue(
                        tier=1,
                        code="DRAFT_ITEM_FIELD_MISSING",
                        message="Detection item has no field selected.",
                        location=f"detections[{block_idx}].items[{item_idx}]",
                    )
                )
                continue
            if not item.values:
                issues.append(
                    ValidationIssue(
                        tier=1,
                        code="DRAFT_ITEM_VALUES_MISSING",
                        message=f"Field {item.field!r} has no value(s) set.",
                        location=f"detections[{block_idx}].items[{item_idx}]",
                    )
                )
                continue
            strict_items.append(
                DetectionItem(
                    field=item.field,
                    modifiers=list(item.modifiers),
                    values=list(item.values),
                )
            )
        try:
            return DetectionBlock(
                name=draft.name,
                is_filter=draft.is_filter,
                combinator=draft.combinator,
                items=strict_items,
            )
        except ValidationError as exc:
            for err in exc.errors():
                issues.append(
                    ValidationIssue(
                        tier=1,
                        code="DRAFT_BLOCK_REJECTED",
                        message=err.get("msg", "validation failed"),
                        location=f"detections[{block_idx}]",
                    )
                )
            return None

    def _compose_condition(self, blocks: list[DetectionBlock]) -> ConditionExpression | None:
        """Build a default condition tree from the block list.

        v0 composer UX: ``all of match_* and not any filter_*``. If there's
        only one match block and no filter, the condition is just that one
        selection's name. This auto-composition is replaced in M2.4 when
        the Expert-mode condition editor lands; for now it keeps the
        Guided flow from asking the user about conditions at all.
        """
        if not blocks:
            return None
        matches = [b for b in blocks if not b.is_filter]
        filters = [b for b in blocks if b.is_filter]
        if not matches:
            return None

        # Match side: single block reference, or AND/OR over a glob.
        # ``match_combinator`` picks between ``all of match_*`` (AND across
        # match blocks) and ``1 of match_*`` (OR across match blocks).
        if len(matches) == 1:
            match_expr = ConditionExpression(selection=matches[0].name)
        else:
            op = ConditionOp.ONE_OF if self.match_combinator == "any_of" else ConditionOp.ALL_OF
            match_expr = ConditionExpression(
                op=op,
                children=[ConditionExpression(selection="match_*")],
            )

        if not filters:
            return match_expr

        # Filter side: negate either a single block or an "any of" glob.
        if len(filters) == 1:
            filter_negation = ConditionExpression(
                op=ConditionOp.NOT,
                children=[ConditionExpression(selection=filters[0].name)],
            )
        else:
            filter_negation = ConditionExpression(
                op=ConditionOp.NOT,
                children=[
                    ConditionExpression(
                        op=ConditionOp.ONE_OF,
                        children=[ConditionExpression(selection="filter_*")],
                    )
                ],
            )
        return ConditionExpression(
            op=ConditionOp.AND,
            children=[match_expr, filter_negation],
        )


__all__ = [
    "DetectionBlockDraft",
    "DetectionItemDraft",
    "LogSourceDraft",
    "RuleDraft",
]
