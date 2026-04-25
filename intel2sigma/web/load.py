"""Load an arbitrary Sigma rule into a :class:`RuleDraft`.

Uses pySigma as the permissive parser — it accepts any valid Sigma rule
— and translates its model into ours. Per SPEC.md's ``from_yaml`` narrow-
scope decision, this is how the composer ingests rules written by anyone
other than itself: pySigma parses, we translate.

Translation is best-effort. The composer's internal model (``RuleDraft``)
cannot represent every shape pySigma does — notably, multi-field AND sub-
groups inside a list-of-mappings block collapse to flat items. Where a
loaded rule uses a shape we can't edit cleanly, the translator flags it
as a ``ValidationIssue`` but still returns a usable draft; the user can
decide whether to keep editing or to abandon.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from sigma.exceptions import SigmaError
from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.rule import SigmaRule as PySigmaRule

from intel2sigma.core.validate.issues import ValidationIssue
from intel2sigma.web.draft import (
    DetectionBlockDraft,
    DetectionItemDraft,
    LogSourceDraft,
    RuleDraft,
)

# Bundled examples directory (shipped under data/examples/; curated via
# scripts/curate_examples.py from the SigmaHQ corpus).
_EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "data" / "examples"


# Code prefix for all translator-surfaced issues so the UI can group them
# separately from tier-1/tier-2/composer issues.
_ISSUE_CODE_PREFIX = "LOAD_"


def draft_from_yaml(yaml_text: str) -> tuple[RuleDraft | None, list[ValidationIssue]]:
    """Translate a Sigma YAML document into a :class:`RuleDraft`.

    Returns ``(draft, issues)``:

    * On parse failure: ``(None, [LOAD_PARSE_FAILED])``. The caller should
      show the issue list and stay on the load modal.
    * On partial success (translated, but some fidelity lost): a non-empty
      issue list with ``LOAD_*`` codes. The draft is usable but the user
      should know about the caveats.
    * On full success: issue list is empty.

    Never raises. All pySigma errors are caught and translated.
    """
    try:
        py_rule = PySigmaRule.from_yaml(yaml_text)
    except SigmaError as exc:
        return None, [
            ValidationIssue(
                tier=1,
                code=f"{_ISSUE_CODE_PREFIX}PARSE_FAILED",
                message=f"pySigma could not parse this rule: {exc}",
            )
        ]
    except Exception as exc:
        return None, [
            ValidationIssue(
                tier=1,
                code=f"{_ISSUE_CODE_PREFIX}PARSE_FAILED",
                message=f"Unexpected error parsing rule: {exc}",
            )
        ]

    issues: list[ValidationIssue] = []
    draft = _translate(py_rule, issues)
    return draft, issues


# ---------------------------------------------------------------------------
# Translation
# ---------------------------------------------------------------------------


def _translate(py_rule: PySigmaRule, issues: list[ValidationIssue]) -> RuleDraft:
    """Populate a :class:`RuleDraft` from a pySigma rule."""
    # ``_translate_status`` / ``_translate_level`` narrow back to one of
    # the Literal values; the runtime check inside each function is what
    # mypy can't see.
    draft = RuleDraft(
        title=py_rule.title or "",
        id=py_rule.id,  # UUID or None
        # _translate_status returns one of the Literal members; the runtime
        # check inside it is what mypy can't see across the call boundary.
        status=_translate_status(py_rule.status),  # type: ignore[arg-type]
        description=py_rule.description or "",
        references=list(py_rule.references or []),
        author=py_rule.author or "",
        date=py_rule.date.isoformat() if py_rule.date else "",
        modified=py_rule.modified.isoformat() if py_rule.modified else "",
        tags=[_render_tag(t) for t in py_rule.tags],
        # Same Literal-narrowing as _translate_status.
        level=_translate_level(py_rule.level),  # type: ignore[arg-type]
        falsepositives=list(py_rule.falsepositives or []),
        logsource=LogSourceDraft(
            category=py_rule.logsource.category,
            product=py_rule.logsource.product,
            service=py_rule.logsource.service,
        ),
    )

    _translate_observation(draft, py_rule, issues)
    _translate_detection_blocks(draft, py_rule, issues)
    _set_match_combinator_from_condition(draft, py_rule, issues)

    # Pick the landing stage. If the translated draft converts cleanly into
    # a strict SigmaRule, skip straight to review (stage 3) so the user
    # sees what they loaded. Otherwise drop them into stage 1 with the
    # issue list visible so they can fix whatever needs fixing.
    result = draft.to_sigma_rule()
    draft.stage = 3 if not isinstance(result, list) else 1

    return draft


def _translate_status(status: Any) -> str:
    """pySigma's ``SigmaStatus`` enum → our string-literal status."""
    if status is None:
        return "experimental"
    raw = str(status).lower()
    # enum repr is "SigmaStatus.EXPERIMENTAL" etc.
    for known in ("stable", "test", "experimental", "deprecated", "unsupported"):
        if known in raw:
            return known
    return "experimental"


def _translate_level(level: Any) -> str:
    """pySigma's ``SigmaLevel`` enum → our string-literal level."""
    if level is None:
        return "medium"
    raw = str(level).lower()
    for known in ("informational", "low", "medium", "high", "critical"):
        if known in raw:
            return known
    return "medium"


def _render_tag(tag: Any) -> str:
    """Render a ``SigmaRuleTag`` back into its dotted form (e.g. ``attack.execution``)."""
    ns = getattr(tag, "namespace", None)
    name = getattr(tag, "name", None)
    if ns and name:
        return f"{ns}.{name}"
    return str(tag)


def _translate_observation(
    draft: RuleDraft, py_rule: PySigmaRule, issues: list[ValidationIssue]
) -> None:
    """Best-effort map the rule's logsource category to our observation catalog.

    We don't hard-require a match — catalogues miss things — but flag a
    ``LOAD_OBSERVATION_UNKNOWN`` issue so the composer knows to skip the
    taxonomy-driven field dropdown if the category isn't recognized.
    """
    # Lazy import: core.taxonomy.load_taxonomy has side-effects (I/O) we
    # don't want at module import time.
    from intel2sigma.core.taxonomy import load_taxonomy  # noqa: PLC0415

    try:
        registry = load_taxonomy()
    except Exception as exc:
        issues.append(
            ValidationIssue(
                tier=1,
                code=f"{_ISSUE_CODE_PREFIX}CATALOG_UNAVAILABLE",
                message=f"Could not load observation catalogue: {exc}",
            )
        )
        return

    ls = draft.logsource
    category = ls.category
    product = ls.product
    if not category:
        return

    for obs_id in registry.all_ids():
        spec = registry.get(obs_id)
        if spec.logsource.category != category:
            continue
        # Prefer a platform-matching entry when product is specified.
        if product and spec.platforms:
            products = {p.product for p in spec.platforms}
            if product not in products:
                continue
        draft.observation_id = spec.id
        draft.platform_id = spec.platforms[0].id if spec.platforms else ""
        return

    # No catalogue match — the rule will still render in stage 1 but
    # without the taxonomy-driven field dropdown.
    issues.append(
        ValidationIssue(
            tier=1,
            code=f"{_ISSUE_CODE_PREFIX}OBSERVATION_UNKNOWN",
            message=(
                f"Rule's logsource ({category}"
                + (f", {product}" if product else "")
                + ") doesn't match any catalogued observation type."
                " Fields won't be validated against the taxonomy."
            ),
        )
    )


def _translate_detection_blocks(
    draft: RuleDraft, py_rule: PySigmaRule, issues: list[ValidationIssue]
) -> None:
    """Flatten pySigma's detection tree into our block/item draft shape."""
    blocks: list[DetectionBlockDraft] = []
    for name, detection in py_rule.detection.detections.items():
        block = _translate_one_block(name, detection, issues)
        blocks.append(block)
    draft.detections = blocks


def _translate_one_block(
    name: str, detection: SigmaDetection, issues: list[ValidationIssue]
) -> DetectionBlockDraft:
    """Translate one pySigma ``SigmaDetection`` into a ``DetectionBlockDraft``.

    Blocks whose detection_items list is uniformly flat (all SigmaDetectionItem)
    become ``all_of`` blocks. Blocks whose items are themselves SigmaDetection
    objects are the list-of-mappings form — ``any_of``.

    Multi-field AND sub-groups inside the list form are flattened with a
    per-block warning; our model can't represent arbitrary nested AND-in-OR
    without the v2 correlation-rule work.
    """
    is_filter = name.startswith("filter")

    # Case 1: flat mapping form — detection_items are directly
    # SigmaDetectionItem instances.
    if detection.detection_items and all(
        isinstance(di, SigmaDetectionItem) for di in detection.detection_items
    ):
        # Narrowed by the all-isinstance check above.
        items = [
            _translate_item(di)
            for di in detection.detection_items
            if isinstance(di, SigmaDetectionItem)
        ]
        return DetectionBlockDraft(name=name, is_filter=is_filter, combinator="all_of", items=items)

    # Case 2: list-of-mappings form — detection_items are nested SigmaDetection.
    flat_items: list[DetectionItemDraft] = []
    lost_fidelity = False
    for entry in detection.detection_items:
        if isinstance(entry, SigmaDetectionItem):
            flat_items.append(_translate_item(entry))
            continue
        if isinstance(entry, SigmaDetection):
            sub_items = [di for di in entry.detection_items if isinstance(di, SigmaDetectionItem)]
            if len(sub_items) > 1:
                lost_fidelity = True
            for di in sub_items:
                flat_items.append(_translate_item(di))

    if lost_fidelity:
        issues.append(
            ValidationIssue(
                tier=1,
                code=f"{_ISSUE_CODE_PREFIX}NESTED_SUBGROUPS_FLATTENED",
                message=(
                    f"Block {name!r} contained multi-field sub-groups inside a "
                    "list-of-mappings form; the composer's model flattened them. "
                    "Review the block to make sure the intent is preserved."
                ),
                location=f"detections.{name}",
            )
        )

    return DetectionBlockDraft(
        name=name, is_filter=is_filter, combinator="any_of", items=flat_items
    )


def _translate_item(di: SigmaDetectionItem) -> DetectionItemDraft:
    """One ``SigmaDetectionItem`` → one ``DetectionItemDraft``."""
    field = di.field or ""
    modifiers = [_modifier_name(mod) for mod in (di.modifiers or [])]
    # Filter out modifiers we don't recognize rather than emit an invalid draft.
    known = {
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
    }
    modifiers = [m for m in modifiers if m in known]
    # ``original_value`` is typed as a union; iterate defensively.
    raw_value = di.original_value
    value_iter: list[Any] = (
        list(raw_value)
        if isinstance(raw_value, list)
        else ([raw_value] if raw_value is not None else [])
    )
    values = [_stringify_value(v) for v in value_iter]
    return DetectionItemDraft(
        field=field,
        # ``modifiers`` is a list[str] from the YAML; each entry was already
        # validated against ValueModifier in _modifier_name above.
        modifiers=modifiers,  # type: ignore[arg-type]
        values=values,
    )


def _modifier_name(mod_cls: type) -> str:
    """pySigma modifier class (e.g. ``SigmaEndswithModifier``) → short name."""
    name = mod_cls.__name__
    if name.startswith("Sigma"):
        name = name[len("Sigma") :]
    if name.endswith("Modifier"):
        name = name[: -len("Modifier")]
    return name.lower()


def _stringify_value(v: Any) -> str:
    """Best-effort stringify a pySigma value.

    For ``SigmaString`` this returns the original pattern including wildcards;
    for ``SigmaNumber`` / ``SigmaBool`` it's the decimal / true-false form.
    """
    return str(v)


def _set_match_combinator_from_condition(
    draft: RuleDraft, py_rule: PySigmaRule, issues: list[ValidationIssue]
) -> None:
    """Infer ``match_combinator`` from the raw condition string.

    Simple heuristic: if the condition uses ``1 of match_*`` or ``any of``
    or ``or`` between match blocks, we set ``any_of``. Otherwise ``all_of``
    (the default). Unusual condition shapes trigger a warning so the user
    knows the auto-composed condition may differ from the original.
    """
    conditions = list(py_rule.detection.condition or [])
    if not conditions:
        return
    raw = conditions[0].strip().lower()

    # Heuristic signals the condition is OR-dominated across match blocks.
    or_signals = ("1 of match", "any of match", " or ")
    and_signals = ("all of match", " and ")
    if any(s in raw for s in or_signals) and not any(s in raw for s in and_signals):
        draft.match_combinator = "any_of"

    # Anything more exotic than the shapes our auto-composer can reproduce
    # gets a heads-up. "not" prefixes on matches, nested parens, multi-part
    # conditions with both ANDs and ORs between match and filter — all of
    # these we can't faithfully round-trip through the simple combinator.
    has_both = any(s in raw for s in or_signals) and any(s in raw for s in and_signals)
    if has_both or "(" in raw:
        issues.append(
            ValidationIssue(
                tier=1,
                code=f"{_ISSUE_CODE_PREFIX}CONDITION_UNUSUAL",
                message=(
                    "The loaded rule's condition uses a shape the Guided "
                    "composer's auto-composer can't fully reproduce. Saving "
                    "the rule from here will use a simpler condition than "
                    "the original."
                ),
                location="condition",
            )
        )


# ---------------------------------------------------------------------------
# Example-rule listing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExampleEntry:
    """One entry in the curated examples panel."""

    id: str
    file: str
    description: str
    title: str  # pulled from the rule's ``title:`` field for display


@cache
def list_examples() -> list[ExampleEntry]:
    """Return the bundled example rules, sorted by id.

    Reads the manifest ``data/examples/_index.yml`` written by
    ``scripts/curate_examples.py``. Missing manifest or missing per-example
    files produce an empty list rather than raising — the load modal simply
    shows no examples tab content in that case.
    """
    manifest = _EXAMPLES_DIR / "_index.yml"
    if not manifest.is_file():
        return []
    try:
        yaml = YAML(typ="safe")
        data: Any = yaml.load(manifest.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    entries = data.get("examples", [])
    if not isinstance(entries, list):
        return []
    out: list[ExampleEntry] = []
    for raw in entries:
        if not isinstance(raw, dict):
            continue
        ex_id = str(raw.get("id", ""))
        file = str(raw.get("file", ""))
        desc = str(raw.get("description", ""))
        if not ex_id or not file:
            continue
        path = _EXAMPLES_DIR / file
        if not path.is_file():
            continue
        title = _extract_title(path)
        out.append(ExampleEntry(id=ex_id, file=file, description=desc, title=title))
    return sorted(out, key=lambda e: e.id)


def load_example(example_id: str) -> tuple[RuleDraft | None, list[ValidationIssue]]:
    """Load a curated example by id. Same contract as :func:`draft_from_yaml`."""
    for entry in list_examples():
        if entry.id == example_id:
            path = _EXAMPLES_DIR / entry.file
            return draft_from_yaml(path.read_text(encoding="utf-8"))
    return None, [
        ValidationIssue(
            tier=1,
            code=f"{_ISSUE_CODE_PREFIX}EXAMPLE_UNKNOWN",
            message=f"No bundled example with id {example_id!r}.",
        )
    ]


def _extract_title(path: Path) -> str:
    """Quick title pull for the examples listing UI.

    Cheaper than a full pySigma parse; we just want the display string.
    """
    try:
        yaml = YAML(typ="safe")
        data: Any = yaml.load(path.read_text(encoding="utf-8"))
    except Exception:
        return path.stem
    if isinstance(data, dict):
        title = data.get("title")
        if isinstance(title, str):
            return title
    return path.stem


__all__ = ["ExampleEntry", "draft_from_yaml", "list_examples", "load_example"]
