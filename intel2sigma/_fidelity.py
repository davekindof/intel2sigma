"""Systematic state-fidelity audit (L8).

For every observable property of :class:`RuleDraft` after loading a
source YAML, a *fidelity dimension* describes what "correct" means
and how to check it. The framework guarantees that adding a new
property to ``RuleDraft`` requires adding a fidelity dimension —
closing the meta-loop where bugs that escape the existing structural
audits (L1 load-content, L4 emit-content) go undetected.

Pre-L8 we measured **two** facets of correctness:

* **L1** — does the load path produce a strict rule with the right
  block / item counts?
* **L4** — does the canonical emit + re-parse preserve those
  structural facts?

Three live bugs escaped both:

* ``8329d04`` (filter-only condition parity) — preview vs save drift
* B1 (modifier dropped on field-name keystroke) — handler over-reach
* The screenshot bug from 2026-05-02 — service-only logsources land
  with ``observation_id=""``, breadcrumb says stage 3, renderer
  falls back to Stage 0

Each was the *symptom* of a different unmeasured dimension.

L8 enumerates **every** observable ``RuleDraft`` property — identity,
prose metadata, list metadata, logsource, routing, detection, UI
state — and checks each one independently. The output is per-
dimension drift counts; the discovery report drives the fix list,
ranked by drift volume.

Module layout:

* :class:`FidelityDimension` — one named check, ``check(py_rule,
  draft) -> DimensionResult``.
* :data:`FIDELITY_DIMENSIONS` — the catalogue of every check.
* :func:`check_fidelity` — runs all dimensions on one corpus rule.
* :func:`audit_corpus_fidelity` — walks a corpus, rolls up per-
  dimension counts.

The categorisation logic is *data*: a new dimension is one entry in
``FIDELITY_DIMENSIONS``, not a new branch in a categoriser.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, TypedDict

from sigma.rule import SigmaRule as PySigmaRule

from intel2sigma.web.draft import RuleDraft
from intel2sigma.web.load import draft_from_yaml

# Sentinel observation id for the freeform routing path. Mirrors
# ``_FREEFORM_OBSERVATION_ID`` in ``web/routes/composer.py``;
# duplicated here as a literal because ``_fidelity.py`` is a
# core-tier module and importing the routes layer for one constant
# would invert the dependency direction (CLAUDE.md I-7).
_FREEFORM_OBSERVATION_ID = "_freeform"


class Status(StrEnum):
    """Per-dimension check outcome."""

    PASS = "pass"
    FAIL = "fail"
    NA = "n/a"


@dataclass(frozen=True)
class DimensionResult:
    """One dimension's check outcome on one rule.

    ``detail`` is a short diagnostic the audit report carries forward
    so a failing rule is debuggable without having to re-run the
    check.
    """

    status: Status
    detail: str = ""


@dataclass(frozen=True)
class FidelityDimension:
    """A named, data-described check. Adding one to
    :data:`FIDELITY_DIMENSIONS` is the only thing required to
    extend the audit's coverage.
    """

    name: str
    group: str
    description: str
    check: Callable[[PySigmaRule, RuleDraft], DimensionResult]


@dataclass(frozen=True)
class FidelityReport:
    """One rule's full per-dimension result."""

    rule_id: str
    title: str
    dimensions: dict[str, DimensionResult] = field(default_factory=dict)

    @property
    def all_passed(self) -> bool:
        return all(r.status is not Status.FAIL for r in self.dimensions.values())


# ---------------------------------------------------------------------------
# Per-dimension check helpers
# ---------------------------------------------------------------------------


def _equal_or_na(source: Any, loaded: Any, *, source_default: Any = None) -> DimensionResult:
    """Common shape: pass on equal, N/A when source omitted, fail otherwise.

    Many fidelity dimensions follow this same shape (title, status,
    description, author, …) — extracted as a helper so each
    dimension's check is one comparison line.
    """
    if source == source_default:
        return DimensionResult(Status.NA, "source omitted this field")
    if source == loaded:
        return DimensionResult(Status.PASS)
    return DimensionResult(Status.FAIL, f"source={source!r} loaded={loaded!r}")


# ---- identity ---------------------------------------------------------------


def _check_title(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    return _equal_or_na(py.title, d.title, source_default=None)


def _check_id(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    return _equal_or_na(py.id, d.id, source_default=None)


def _check_status(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    if py.status is None:
        # Source omitted; draft default is "experimental"
        return DimensionResult(Status.NA, "source omitted this field")
    src = str(py.status).split(".")[-1].lower()
    if src == d.status:
        return DimensionResult(Status.PASS)
    return DimensionResult(Status.FAIL, f"source={src!r} loaded={d.status!r}")


def _check_level(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    if py.level is None:
        return DimensionResult(Status.NA, "source omitted this field")
    src = str(py.level).split(".")[-1].lower()
    if src == d.level:
        return DimensionResult(Status.PASS)
    return DimensionResult(Status.FAIL, f"source={src!r} loaded={d.level!r}")


# ---- prose metadata ---------------------------------------------------------


def _check_description(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    if py.description is None:
        return DimensionResult(Status.NA, "source omitted this field")
    # Trailing/leading whitespace normalization: pySigma preserves
    # the YAML scalar verbatim, so a literal block (``description:
    # |\n  text``) yields ``"text\n"`` with a trailing newline.
    # ``RuleDraft`` has ``str_strip_whitespace=True`` (Pydantic
    # config), which calls ``.strip()`` on every assignment, so
    # the loaded value is the same content with edge whitespace
    # removed. That's not semantic drift — the user's intent is
    # the description text, not the YAML-emit whitespace artifact.
    # The L8-A discovery report flagged 955 rules failing this
    # dimension on exactly this artifact; the contract decision
    # is "leading/trailing whitespace doesn't count as drift,"
    # implemented by stripping both sides. Internal whitespace
    # (paragraph breaks, indentation in code samples) IS
    # preserved on both sides and still compared verbatim.
    if py.description.strip() == d.description.strip():
        return DimensionResult(Status.PASS)
    return DimensionResult(
        Status.FAIL,
        f"source[:60]={py.description.strip()[:60]!r} loaded[:60]={d.description.strip()[:60]!r}",
    )


def _check_author(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    return _equal_or_na(py.author, d.author or None, source_default=None)


def _check_date(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    # ``getattr`` rather than direct attribute access — pySigma's
    # SigmaRule doesn't type-annotate ``date``/``modified``/``status``
    # /``level`` etc. on the class, so mypy infers ``None`` and
    # flags the post-None-check branch as unreachable.
    src_date = getattr(py, "date", None)
    if src_date is None:
        return DimensionResult(Status.NA, "source omitted this field")
    src_iso = src_date.isoformat()
    if src_iso == d.date:
        return DimensionResult(Status.PASS)
    return DimensionResult(Status.FAIL, f"source={src_iso!r} loaded={d.date!r}")


def _check_modified(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    src_modified = getattr(py, "modified", None)
    if src_modified is None:
        return DimensionResult(Status.NA, "source omitted this field")
    src_iso = src_modified.isoformat()
    if src_iso == d.modified:
        return DimensionResult(Status.PASS)
    return DimensionResult(Status.FAIL, f"source={src_iso!r} loaded={d.modified!r}")


# ---- list metadata ----------------------------------------------------------


def _check_references(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    src = list(py.references or [])
    if not src:
        return DimensionResult(Status.NA, "source omitted this field")
    if src == d.references:
        return DimensionResult(Status.PASS)
    return DimensionResult(Status.FAIL, f"source_count={len(src)} loaded_count={len(d.references)}")


def _check_tags(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    src_tags = list(py.tags or [])
    if not src_tags:
        return DimensionResult(Status.NA, "source omitted this field")
    # pySigma's SigmaRuleTag has namespace + name; draft stores the
    # dotted form. Normalize source to dotted form for comparison.
    src_dotted = [
        f"{getattr(t, 'namespace', '')}.{getattr(t, 'name', '')}"
        if getattr(t, "namespace", None)
        else str(t)
        for t in src_tags
    ]
    if src_dotted == d.tags:
        return DimensionResult(Status.PASS)
    return DimensionResult(Status.FAIL, f"source={src_dotted[:3]!r} loaded={d.tags[:3]!r}")


def _check_falsepositives(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    src = list(py.falsepositives or [])
    if not src:
        return DimensionResult(Status.NA, "source omitted this field")
    if src == d.falsepositives:
        return DimensionResult(Status.PASS)
    return DimensionResult(
        Status.FAIL, f"source_count={len(src)} loaded_count={len(d.falsepositives)}"
    )


# ---- logsource --------------------------------------------------------------


def _check_logsource_category(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    src = py.logsource.category
    loaded = d.logsource.category
    if src is None and loaded is None:
        return DimensionResult(Status.NA, "source omitted this field")
    if src == loaded:
        return DimensionResult(Status.PASS)
    return DimensionResult(Status.FAIL, f"source={src!r} loaded={loaded!r}")


def _check_logsource_product(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    src = py.logsource.product
    loaded = d.logsource.product
    if src is None and loaded is None:
        return DimensionResult(Status.NA, "source omitted this field")
    if src == loaded:
        return DimensionResult(Status.PASS)
    return DimensionResult(Status.FAIL, f"source={src!r} loaded={loaded!r}")


def _check_logsource_service(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    src = py.logsource.service
    loaded = d.logsource.service
    if src is None and loaded is None:
        return DimensionResult(Status.NA, "source omitted this field")
    if src == loaded:
        return DimensionResult(Status.PASS)
    return DimensionResult(Status.FAIL, f"source={src!r} loaded={loaded!r}")


# ---- routing (the screenshot bug lives here) -------------------------------


def _check_observation_id_populated(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    """observation_id must be non-empty for any rule with logsource info.

    The screenshot-bug dimension. A rule with ``logsource: { service:
    security }`` and no category currently leaves ``observation_id=""``
    in the draft because the loader's matching loop only fires when
    category is set. Renderer then falls back to Stage 0 even though
    ``draft.stage`` says 3.

    PASS condition: non-empty observation_id (a real catalog entry
    OR ``_freeform`` for genuinely-uncatalogued shapes).
    FAIL condition: empty observation_id when source has any logsource
    info to route by (category, product, or service).
    NA: source has no logsource info at all (rare — mostly malformed
    rules).
    """
    has_routing_info = py.logsource.category or py.logsource.product or py.logsource.service
    if not has_routing_info:
        return DimensionResult(Status.NA, "source has no logsource fields")
    if d.observation_id:
        return DimensionResult(Status.PASS)
    return DimensionResult(
        Status.FAIL,
        f"empty observation_id for logsource (category={py.logsource.category!r}, "
        f"product={py.logsource.product!r}, service={py.logsource.service!r}) "
        f"— renderer will fall back to Stage 0",
    )


def _check_observation_id_matches_catalog(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    """If observation_id points to a catalog entry, that entry's
    logsource must match the source's logsource.

    Stricter than ``_populated`` — checks that the routing was
    *correct*, not just that something got assigned. ``_freeform``
    is N/A (the freeform path doesn't have a single catalog
    logsource to match against).

    Wildcard handling is identical to the loader's
    ``_logsource_compatible``: the catalog's ``"unspecified"``
    placeholder normalizes to ``None`` for matching. Without this,
    the audit reported 27 false-positive fails on this dimension
    after L8-B-2 — proxy.yml and linux_misc.yml use ``"unspecified"``
    as a wildcard, the loader correctly routes through them, but
    the audit's strict ``spec.category != source.category`` check
    flagged the routing as wrong. Audit and loader now share the
    same wildcard semantics by construction.
    """
    if not d.observation_id:
        return DimensionResult(Status.NA, "observation_id empty (covered by _populated)")
    if d.observation_id == _FREEFORM_OBSERVATION_ID:
        return DimensionResult(Status.NA, "freeform path doesn't bind to catalog logsource")
    # Lazy imports: catalog is a runtime-loaded resource, not part
    # of the model surface; the loader's wildcard helper lives in
    # web/load.py and is the single source of truth for the
    # placeholder-handling convention.
    from intel2sigma.core.taxonomy import load_taxonomy  # noqa: PLC0415
    from intel2sigma.web.load import _wildcard_or  # noqa: PLC0415

    try:
        spec = load_taxonomy().get(d.observation_id)
    except KeyError:
        return DimensionResult(
            Status.FAIL,
            f"observation_id={d.observation_id!r} not in taxonomy registry",
        )
    src_cat = py.logsource.category
    src_svc = py.logsource.service
    spec_cat = _wildcard_or(spec.logsource.category)
    spec_svc = _wildcard_or(spec.logsource.service)
    if spec_cat is not None and spec_cat != src_cat:
        return DimensionResult(
            Status.FAIL,
            f"spec.category={spec_cat!r} but source.category={src_cat!r}",
        )
    if spec_svc is not None and spec_svc != src_svc:
        return DimensionResult(
            Status.FAIL,
            f"spec.service={spec_svc!r} but source.service={src_svc!r}",
        )
    return DimensionResult(Status.PASS)


def _check_platform_id_consistent(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    """platform_id must match the source's product when both are set.

    Surfaced incidentally by L2-P1a (pre-fix the loader always picked
    ``spec.platforms[0].id`` regardless of source product, so a Linux
    rule routed to ``platform_id=windows`` for multi-platform
    entries). Locked in here as a permanent dimension.
    """
    if not d.observation_id or d.observation_id == _FREEFORM_OBSERVATION_ID:
        return DimensionResult(Status.NA, "no catalog spec to consult")
    if not py.logsource.product:
        return DimensionResult(Status.NA, "source has no product")
    from intel2sigma.core.taxonomy import load_taxonomy  # noqa: PLC0415

    try:
        spec = load_taxonomy().get(d.observation_id)
    except KeyError:
        return DimensionResult(Status.NA, "observation_id not in taxonomy")
    matched = next((p for p in spec.platforms if p.product == py.logsource.product), None)
    if matched is None:
        return DimensionResult(
            Status.FAIL,
            f"source.product={py.logsource.product!r} not in spec platforms "
            f"({[p.product for p in spec.platforms]})",
        )
    if matched.id != d.platform_id:
        return DimensionResult(
            Status.FAIL,
            f"expected platform_id={matched.id!r} for product "
            f"{py.logsource.product!r}, got {d.platform_id!r}",
        )
    return DimensionResult(Status.PASS)


# ---- UI state ---------------------------------------------------------------


def _check_stage(py: PySigmaRule, d: RuleDraft) -> DimensionResult:
    """Loaded rules that validate should land at stage 3 (review).

    This catches the meta-discord behind the screenshot bug. The
    renderer reads ``observation_id`` to decide what to render; the
    breadcrumb reads ``stage``. When they disagree (stage=3 but
    observation_id="" → renderer renders Stage 0), the user sees
    a broken interface. Both should be 3 for a fully-validating
    loaded rule.
    """
    sigma_or_issues = d.to_sigma_rule()
    if isinstance(sigma_or_issues, list):
        # Draft doesn't validate; stage should be 1 (composer at
        # detection edit) per the loader's contract.
        if d.stage == 1:
            return DimensionResult(Status.PASS, "validation issues — stage 1 expected")
        return DimensionResult(Status.FAIL, f"validation issues but stage={d.stage} (expected 1)")
    # Draft validates; stage should be 3.
    if d.stage == 3:
        return DimensionResult(Status.PASS)
    return DimensionResult(Status.FAIL, f"validates but stage={d.stage} (expected 3)")


# ---------------------------------------------------------------------------
# The dimension catalogue
# ---------------------------------------------------------------------------

FIDELITY_DIMENSIONS: list[FidelityDimension] = [
    # identity
    FidelityDimension("title", "identity", "rule title preserved", _check_title),
    FidelityDimension("id", "identity", "rule UUID preserved", _check_id),
    FidelityDimension("status", "identity", "rule status preserved", _check_status),
    FidelityDimension("level", "identity", "rule level preserved", _check_level),
    # prose metadata
    FidelityDimension(
        "description", "prose_metadata", "description string preserved", _check_description
    ),
    FidelityDimension("author", "prose_metadata", "author string preserved", _check_author),
    FidelityDimension("date", "prose_metadata", "date preserved", _check_date),
    FidelityDimension("modified", "prose_metadata", "modified date preserved", _check_modified),
    # list metadata
    FidelityDimension(
        "references", "list_metadata", "references list preserved", _check_references
    ),
    FidelityDimension("tags", "list_metadata", "tags list preserved", _check_tags),
    FidelityDimension(
        "falsepositives",
        "list_metadata",
        "falsepositives list preserved",
        _check_falsepositives,
    ),
    # logsource
    FidelityDimension(
        "logsource_category", "logsource", "logsource.category preserved", _check_logsource_category
    ),
    FidelityDimension(
        "logsource_product", "logsource", "logsource.product preserved", _check_logsource_product
    ),
    FidelityDimension(
        "logsource_service", "logsource", "logsource.service preserved", _check_logsource_service
    ),
    # routing — the screenshot-bug dimension lives here
    FidelityDimension(
        "observation_id_populated",
        "routing",
        "observation_id non-empty for any rule with logsource info",
        _check_observation_id_populated,
    ),
    FidelityDimension(
        "observation_id_matches_catalog",
        "routing",
        "observation_id points to a spec whose logsource matches the source",
        _check_observation_id_matches_catalog,
    ),
    FidelityDimension(
        "platform_id_consistent_with_product",
        "routing",
        "platform_id matches the spec platform whose product equals source's product",
        _check_platform_id_consistent,
    ),
    # UI state
    FidelityDimension(
        "stage",
        "ui_state",
        "draft.stage agrees with renderer expectations (3 if validates, 1 otherwise)",
        _check_stage,
    ),
]


# ---------------------------------------------------------------------------
# Top-level checking + corpus rollup
# ---------------------------------------------------------------------------


class FidelitySummary(TypedDict):
    """Rollup shape returned by :func:`audit_corpus_fidelity`."""

    total_rules: int
    per_dimension: dict[str, dict[str, int]]
    fail_examples: dict[str, list[dict[str, str]]]


def check_fidelity(rule_record: dict[str, Any]) -> FidelityReport:
    """Run every fidelity dimension against one corpus rule record.

    A corpus record is a ``{id, title, raw_yaml}`` dict matching
    the bundled ``intel2sigma/data/sigmahq_corpus.json`` shape. Source
    parse failures or load failures are recorded as a single FAIL
    against a synthetic ``_meta`` dimension so they show up in the
    rollup but don't crash the walk.
    """
    raw_yaml = rule_record.get("raw_yaml", "")
    rule_id = str(rule_record.get("id", "?"))
    title = str(rule_record.get("title", "?"))[:120]

    try:
        py_rule = PySigmaRule.from_yaml(raw_yaml)
    except Exception as exc:
        return FidelityReport(
            rule_id=rule_id,
            title=title,
            dimensions={
                "_meta_source_parse": DimensionResult(
                    Status.FAIL, f"pySigma rejected source: {type(exc).__name__}"
                ),
            },
        )

    draft, _issues = draft_from_yaml(raw_yaml)
    if draft is None:
        return FidelityReport(
            rule_id=rule_id,
            title=title,
            dimensions={
                "_meta_load": DimensionResult(Status.FAIL, "draft_from_yaml returned None"),
            },
        )

    return FidelityReport(
        rule_id=rule_id,
        title=title,
        dimensions={dim.name: dim.check(py_rule, draft) for dim in FIDELITY_DIMENSIONS},
    )


def audit_corpus_fidelity(
    rules: list[dict[str, Any]],
    *,
    on_progress: Callable[[int, int], None] | None = None,
) -> FidelitySummary:
    """Walk the corpus, run every dimension on every rule, return per-
    dimension pass/fail/n/a counts plus a few examples per drifting
    dimension.
    """
    per_dim: dict[str, Counter[str]] = {dim.name: Counter() for dim in FIDELITY_DIMENSIONS}
    per_dim["_meta_source_parse"] = Counter()
    per_dim["_meta_load"] = Counter()
    fail_examples: dict[str, list[dict[str, str]]] = {name: [] for name in per_dim}

    total = len(rules)
    for i, rule in enumerate(rules, 1):
        report = check_fidelity(rule)
        for name, result in report.dimensions.items():
            per_dim.setdefault(name, Counter())[result.status.value] += 1
            if result.status is Status.FAIL and len(fail_examples.setdefault(name, [])) < 5:
                fail_examples[name].append(
                    {
                        "rule_id": report.rule_id,
                        "title": report.title,
                        "detail": result.detail[:200],
                    }
                )
        if on_progress is not None:
            on_progress(i, total)

    return {
        "total_rules": total,
        "per_dimension": {
            name: {
                "pass": cnt.get("pass", 0),
                "fail": cnt.get("fail", 0),
                "n/a": cnt.get("n/a", 0),
            }
            for name, cnt in per_dim.items()
        },
        "fail_examples": fail_examples,
    }


__all__ = [
    "FIDELITY_DIMENSIONS",
    "DimensionResult",
    "FidelityDimension",
    "FidelityReport",
    "FidelitySummary",
    "Status",
    "audit_corpus_fidelity",
    "check_fidelity",
]
