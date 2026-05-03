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

from intel2sigma._data import data_path
from intel2sigma.core.model import LogSource
from intel2sigma.core.taxonomy.schema import ObservationTypeSpec
from intel2sigma.core.validate.issues import ValidationIssue
from intel2sigma.web.draft import (
    DetectionBlockDraft,
    DetectionItemDraft,
    LogSourceDraft,
    RuleDraft,
)

# Bundled examples directory (shipped under data/examples/; curated via
# scripts/curate_examples.py from the SigmaHQ corpus).
_EXAMPLES_DIR = data_path("examples")


# Code prefix for all translator-surfaced issues so the UI can group them
# separately from tier-1/tier-2/composer issues.
_ISSUE_CODE_PREFIX = "LOAD_"

# Sentinel observation id used when the loaded rule's logsource isn't in
# our taxonomy. Mirrors ``_FREEFORM_OBSERVATION_ID`` in
# ``web/routes/composer.py``; duplicated as a literal here to keep
# ``web/load.py`` from importing the routes layer (load is a service,
# not a presentation concern). If the literal ever changes both sites
# need the update.
_FREEFORM_OBSERVATION_ID = "_freeform"


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
    """Best-effort map the rule's logsource to our observation catalog.

    Match by any combination of (category, product, service) — Sigma
    rules use any non-empty subset to identify their logsource shape.
    Each catalog spec also specifies any subset; matching is "spec
    fields that are set must equal the source's value." Spec fields
    set to ``None`` are wildcards.

    When multiple specs match, the most-specific one wins (highest
    count of explicitly-set logsource fields). This ensures
    ``process_creation_linux`` (cat + product) beats
    ``process_creation`` (cat only) for a rule with both, and
    ``application_kubernetes`` (cat + product) beats nothing
    spurious for k8s rules.

    We don't hard-require a match — catalogues miss things — but
    flag a ``LOAD_OBSERVATION_UNKNOWN`` issue and route to
    ``_freeform`` so the composer keeps a usable Stage 1+ rendering
    instead of falling back to Stage 0.

    Pre-L8-B-2 the matcher only handled category-keyed specs and
    bailed early when ``category`` was unset. The L8-A discovery
    audit found 797 corpus rules (21%) with service-only logsources
    landing with ``observation_id=""`` because of that early-return
    — the screenshot bug from 2026-05-02. 14 of 36 catalog entries
    are service-keyed (windows-security, auditd, cloudtrail, all
    Azure logs, Okta, GitHub, GCP audit, Defender, Task Scheduler,
    application_log, system_log) and were unreachable; this fix
    closes them.
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
    service = ls.service

    # No logsource info at all → nothing to route by. Leave
    # observation_id empty; the renderer falls back to Stage 0,
    # which is the correct UX for a rule with no logsource.
    if not (category or product or service):
        return

    # Find every spec compatible with the source's logsource —
    # see ``_logsource_compatible``. Score each by how many of the
    # source's set fields the spec agrees with; most-specific match
    # wins.
    candidates: list[tuple[ObservationTypeSpec, int]] = []
    for obs_id in registry.all_ids():
        spec = registry.get(obs_id)
        if not _logsource_compatible(ls, spec.logsource):
            continue
        # Platform check: when source has a product, the spec must
        # offer a platform with that product (otherwise the rule
        # can't be authored under this observation as written).
        # ``unspecified`` on a platform is a wildcard, same idiom
        # as ``unspecified`` on the logsource (preserves the pre-
        # L8-B-2 behaviour for proxy.yml and linux_misc.yml).
        if product and spec.platforms:
            products = {_wildcard_or(p.product) for p in spec.platforms}
            if None not in products and product not in products:
                continue
        candidates.append((spec, _spec_match_score(ls, spec)))

    if candidates:
        # Most-specific match wins; ties broken by alphabetical id
        # (deterministic). Existing tests rely on the
        # ``process_creation`` (less-specific) → ``process_creation
        # _linux`` (more-specific) preference, plus the
        # alphabetical-tiebreaker fallback for ambiguous routing.
        spec, _score = max(candidates, key=lambda c: (c[1], -len(c[0].id)))
        draft.observation_id = spec.id
        # Pick the platform whose product matches the loaded rule.
        # Pre-L2-P2 the catalog had one platform per file so this
        # was always ``spec.platforms[0]``; once multi-platform
        # entries land (network_connection windows + linux,
        # file_event windows + macos) the first-platform default
        # would silently route a Linux rule to platform_id="windows"
        # — wrong field set in Stage 1, wrong logsource.product on
        # save. Match by product when we can; fall back to the first
        # platform when the loaded rule has no product (e.g.
        # ``category: webserver``).
        matched_platform = next(
            (p for p in spec.platforms if product and p.product == product),
            spec.platforms[0] if spec.platforms else None,
        )
        draft.platform_id = matched_platform.id if matched_platform else ""
        return

    # No catalogue match. Route to the freeform observation path so
    # the composer treats this as a custom logsource (text-input
    # field rows instead of taxonomy-driven dropdowns) and the
    # breadcrumb / stage render stay in sync with draft.stage.
    # Without this, an unknown logsource left observation_id="" and
    # the render fallback in _render_composer_panel dropped to
    # Stage 0 regardless of the loaded stage — a rule landing at
    # stage 3 (review) would render Stage 0 cards while the
    # breadcrumb still highlighted Stage 3.
    draft.observation_id = _FREEFORM_OBSERVATION_ID
    fields = (("category", category), ("product", product), ("service", service))
    surface = ", ".join(f"{k}={v!r}" for k, v in fields if v)
    issues.append(
        ValidationIssue(
            tier=1,
            code=f"{_ISSUE_CODE_PREFIX}OBSERVATION_UNKNOWN",
            message=(
                f"Rule's logsource ({surface}) doesn't match any catalogued "
                "observation type. Composer will use freeform field-name "
                "inputs; field values won't be validated against the taxonomy."
            ),
        )
    )


def _logsource_compatible(source_ls: LogSourceDraft, spec_ls: LogSource) -> bool:
    """Spec matches source iff their logsource shapes align — every
    field set on both agrees, and the spec doesn't require fields
    the source omits.

    The matching rule for L8-B-2's multi-axis routing.

    Two-direction check:

    * **No contradiction**: when both source and spec set a given
      field (category / product / service), they must agree.
    * **No over-claim**: when the spec sets a field the source
      omits, the spec is more specific than the source — they
      describe different shapes, no match. This guards against the
      "system_log spec false-matching a process_creation rule"
      class that ``at-least-one-match`` permits.

    Wildcard handling: the catalog uses ``"unspecified"`` as a
    placeholder for product/category in generic-shape logsources
    (``proxy.yml``, ``linux_misc.yml``) — the schema requires non-
    empty strings on platforms, and "unspecified" is the convention
    for "no specific constraint." :func:`_wildcard_or` normalizes
    it to ``None`` for matching, so a spec with ``product:
    unspecified`` doesn't reject sources that omit product.

    Spec must have at least one constraint that AGREES with the
    source — guards the no-info case where spec and source both
    have no logsource fields set (would otherwise vacuously match
    every spec).
    """
    spec_cat = _wildcard_or(spec_ls.category)
    spec_prod = _wildcard_or(spec_ls.product)
    spec_svc = _wildcard_or(spec_ls.service)
    matched = 0
    for src, spec in (
        (source_ls.category, spec_cat),
        (source_ls.product, spec_prod),
        (source_ls.service, spec_svc),
    ):
        if spec is not None and src is not None:
            if src != spec:
                return False  # contradiction
            matched += 1
        elif spec is not None and src is None:
            return False  # over-claim: spec requires field source omits
        # src set, spec unset → spec is unconstrained, source is
        # more specific. OK.
    return matched > 0


def _wildcard_or(value: str | None) -> str | None:
    """The catalog's ``"unspecified"`` placeholder normalizes to None
    for matching. See :func:`_logsource_compatible`.
    """
    if value == "unspecified":
        return None
    return value


def _spec_match_score(source_ls: LogSourceDraft, spec: ObservationTypeSpec) -> int:
    """Weighted match score: how meaningfully does this spec describe
    the source's logsource shape?

    Different axes carry different semantic weight:

    * **category** (weight 4) — names a specific event TYPE
      (process_creation, dns_query, file_event). Most semantically
      meaningful — a category match means the spec describes the
      same kind of event the rule is about.
    * **service** (weight 2) — names a log SOURCE / channel
      (security, auditd, cloudtrail). Distinguishes between
      logging systems on the same product.
    * **product** (weight 1) — names the underlying SYSTEM
      (windows, linux, aws). Necessary but not sufficient on its
      own — every product has many event types.

    The weighting matters when multiple specs match. Without it, a
    rule with ``category: network_connection, product: linux`` would
    tie between ``network_connection`` (cat-only) and ``linux_misc``
    (prod-only after wildcard normalization), and a length-based or
    alphabetical tiebreak would arbitrarily pick the wrong one.
    The weights make the category match clearly dominant, picking
    ``network_connection`` regardless of registry order.

    Examples:
      * ``{category: process_creation, product: linux}`` vs
        ``process_creation_linux``: cat (+4) + prod (+1) = 5.
      * Same source vs ``process_creation``: cat (+4) only = 4.
        process_creation_linux wins.
      * ``{product: windows, service: security}`` vs ``security_log``:
        prod (+1) + svc (+2) = 3.
      * ``{category: network_connection, product: linux}`` vs
        ``network_connection``: cat (+4) only = 4.
      * Same source vs ``linux_misc`` (cat unspecified→None,
        prod=linux): prod (+1) only = 1. network_connection wins.
    """
    score = 0
    spec_cat = _wildcard_or(spec.logsource.category)
    spec_prod = _wildcard_or(spec.logsource.product)
    spec_svc = _wildcard_or(spec.logsource.service)
    if spec_cat is not None and source_ls.category is not None and spec_cat == source_ls.category:
        score += 4
    if spec_svc is not None and source_ls.service is not None and spec_svc == source_ls.service:
        score += 2
    if spec_prod is not None and source_ls.product is not None and spec_prod == source_ls.product:
        score += 1
    return score


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
        # ``values`` may contain ``None`` for Sigma's ``Field: null`` idiom;
        # the draft and strict models both accept it post-L2-P1d.
        values=values,
    )


def _modifier_name(mod_cls: type) -> str:
    """pySigma modifier class (e.g. ``SigmaEndswithModifier``) → short name.

    Uses pySigma's authoritative ``modifier_mapping`` (token → class) to
    look up the canonical token for a given class. Fallback to class-
    name munging is kept for defensive operation when an unrecognized
    class somehow flows through (extension modifiers from a future
    pySigma release, etc.) — the fallback's output is unlikely to
    match anything in our ``known`` set, so the modifier gets filtered
    out gracefully rather than crashing.

    Pre-L5 this function did class-name munging unconditionally,
    producing ``"windowsdash"`` from ``SigmaWindowsDashModifier`` —
    but pySigma's known token is ``"windash"``. The loader's
    known-set filter then dropped the modifier silently. The L4
    corpus emit-audit found 50+ rules silently losing modifiers
    this way; ``windash`` was the worst offender but other multi-
    word modifier classes had the same shape. Inverse lookup via
    ``modifier_mapping`` eliminates the entire class.
    """
    token = _MOD_CLS_TO_TOKEN.get(mod_cls)
    if token is not None:
        return token
    # Fallback: class-name munging. Unlikely to produce a token in
    # our ``known`` set, so the modifier filter drops it — preferable
    # to raising on an unexpected class.
    name = mod_cls.__name__
    if name.startswith("Sigma"):
        name = name[len("Sigma") :]
    if name.endswith("Modifier"):
        name = name[: -len("Modifier")]
    return name.lower()


def _build_modifier_class_to_token() -> dict[type, str]:
    """Invert pySigma's ``modifier_mapping`` (token → class) at import time.

    Built lazily-but-once on first import of this module. pySigma's
    mapping is stable across the runtime; we don't need to handle
    runtime changes.
    """
    from sigma.modifiers import modifier_mapping  # noqa: PLC0415

    return {cls: token for token, cls in modifier_mapping.items()}


_MOD_CLS_TO_TOKEN: dict[type, str] = _build_modifier_class_to_token()


def _stringify_value(v: Any) -> str | None:
    """Best-effort stringify a pySigma value, preserving user-literal form.

    For ``SigmaString``, returns ``v.original`` instead of ``str(v)``.
    The two forms differ on values containing pySigma's wildcard
    metacharacters (``?`` / ``*``):

    * ``.original`` is the user's literal input as it appeared in the
      source YAML — ``\\?d=[0-9]{1,3}\\.[0-9]{1,3}`` for a regex with
      a literal ``?`` and escaped dots.
    * ``str(v)`` (and ``.to_plain()``) escapes the wildcard
      metacharacters so the result round-trips through pySigma's own
      parser, but at the cost of doubling backslashes — ``\\\\?d=...``
      — which then drifts when emitted as YAML and re-parsed.

    The L4 corpus emit-audit found 48+ regex/wildcard rules drifting
    this way (``c-uri|re``, ``ScriptBlockText|re``, etc.). Rules
    without metacharacters (plain paths like ``\\powershell.exe``)
    were unaffected because ``.original`` and ``str()`` agree there.

    For ``SigmaNull`` (the YAML ``null`` literal) we return Python
    ``None`` so it round-trips through the draft and strict models.
    Without this branch ``str(SigmaNull())`` produces an ugly
    ``<sigma.types.SigmaNull object at 0x…>`` repr that gets
    serialized literally back into the user's rule — the L2-P1d
    corpus audit found 27+ rules carrying ``CommandLine: null``
    filter blocks that hit this path.

    For ``SigmaNumber`` / ``SigmaBool`` (no ``.original`` attribute),
    falls back to ``str(v)`` — those types stringify deterministically
    to canonical decimal / ``true``-``false`` forms that survive
    YAML round-trip.
    """
    # Lazy import: keeps ``sigma`` off the import path of any consumer
    # that doesn't actually translate values (e.g. ``list_examples``).
    from sigma.types import SigmaNull, SigmaString  # noqa: PLC0415

    if isinstance(v, SigmaNull):
        return None
    if isinstance(v, SigmaString):
        return v.original
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
