"""Corpus load-path audit helpers.

Internal module shared by ``scripts/audit_corpus_loads.py`` (the one-shot
CLI tool that produces a human-readable report) and the L3 ratchet test
(``tests/test_corpus_load_audit_ratchet.py``, ``@pytest.mark.slow``)
that locks in the audit's clean-rate floor in CI.

Categorisation is per :func:`categorise_rule` — see its docstring for the
five buckets and their precedence. The aggregate :func:`audit_corpus`
walks a corpus list and rolls up the records into a summary dict shaped
for both the report file and the ratchet test's threshold assertions.

No I/O, no printing, no report writing — those concerns stay in the
script. This module is pure: same input → same output, no globals.
"""

from __future__ import annotations

import traceback
from collections import Counter
from collections.abc import Callable
from typing import Any, TypedDict

from sigma.rule import SigmaRule as PySigmaRule

from intel2sigma.core.heuristics.checks.condition_integrity import (
    condition_references_undefined,
)
from intel2sigma.core.model import SigmaRule
from intel2sigma.web.load import draft_from_yaml

# Truncate raw_yaml in problem-category records so the report stays
# inspectable without ballooning to MBs. 800 chars is enough to read
# the title + logsource + first detection block, which is usually
# the shape needed to repro the symptom.
RAW_YAML_TRUNCATION = 800

# Categories ordered by precedence — the categoriser returns the first
# bucket that matches, so this is also the priority order for triage.
CATEGORIES: tuple[str, ...] = (
    "exception",
    "silent_data_loss",
    "desync",
    "degraded",
    "clean",
)


class AuditSummary(TypedDict):
    """Rollup shape returned by :func:`audit_corpus`."""

    total_rules: int
    category_counts: dict[str, int]
    category_pct: dict[str, float]
    top_symptoms_per_category: dict[str, list[tuple[str, int]]]


class AuditResult(TypedDict):
    """Full audit output: per-rule records plus the rollup."""

    summary: AuditSummary
    records: list[dict[str, Any]]


def _source_structure(raw_yaml: str) -> dict[str, Any] | None:
    """Pull the structural facts we'll compare against from the source.

    Uses pySigma directly as the ground-truth parse (it's permissive
    and is what our own loader delegates to internally). Returns None
    if pySigma itself can't parse — those rules can't be load-tested
    against because we'd be comparing a draft to nothing.
    """
    try:
        py_rule = PySigmaRule.from_yaml(raw_yaml)
    except Exception:
        return None

    blocks: dict[str, int] = {}
    total_items = 0
    for name, detection in py_rule.detection.detections.items():
        # Count flat detection items. Nested sub-detection groups
        # (the list-of-mappings form) get their items counted too.
        count = 0
        for entry in detection.detection_items or []:
            if hasattr(entry, "detection_items"):
                # Sub-group — count its items.
                count += len(entry.detection_items or [])
            else:
                count += 1
        blocks[name] = count
        total_items += count

    return {
        "block_names": sorted(blocks.keys()),
        "block_count": len(blocks),
        "items_per_block": blocks,
        "total_items": total_items,
        "tags_count": len(py_rule.tags or []),
    }


def _draft_structure(sigma: SigmaRule) -> dict[str, Any]:
    """Pull the same structural facts from the loaded draft's SigmaRule."""
    blocks: dict[str, int] = {}
    total_items = 0
    for block in sigma.detections:
        count = len(block.items)
        blocks[block.name] = count
        total_items += count
    return {
        "block_names": sorted(blocks.keys()),
        "block_count": len(blocks),
        "items_per_block": blocks,
        "total_items": total_items,
        "tags_count": len(sigma.tags or []),
    }


def categorise_rule(rule: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0911 — category-precedence logic; one early-return per category is the clearest shape
    """Run one rule through the load path and return its categorisation.

    Categories (in precedence order — first match wins):

    1. ``exception`` — loader can't produce a draft at all (returned
       ``None``, raised, or :meth:`RuleDraft.to_sigma_rule` returned a
       list of validation issues).
    2. ``silent_data_loss`` — load "succeeded" with no LOAD_ issue, but
       structural counts (detection blocks, items, values) differ from
       the source. The most-dangerous category — nothing flags it to
       the user.
    3. ``desync`` — load "succeeded" with no LOAD_ issue, but the
       loaded rule fails ``h-050`` (condition references a selection
       that doesn't exist). The classic "loader synthesised the wrong
       condition shape" failure mode.
    4. ``degraded`` — load succeeded; one or more LOAD_ issues were
       emitted. User sees warnings; functionality is intact.
    5. ``clean`` — load succeeded, no issues, structural counts match,
       h-050 does not fire. The happy path.
    """
    rule_id = rule.get("id", "?")
    title = rule.get("title", "?")
    raw_yaml = rule.get("raw_yaml", "")

    record: dict[str, Any] = {
        "id": rule_id,
        "title": title[:120],
        "category": "clean",
        "symptom": "",
    }

    # 1. Try the load path. Exceptions caught at the outermost level.
    try:
        draft, issues = draft_from_yaml(raw_yaml)
    except Exception as exc:
        record["category"] = "exception"
        record["symptom"] = f"draft_from_yaml raised {type(exc).__name__}: {str(exc)[:200]}"
        record["raw_yaml_excerpt"] = raw_yaml[:RAW_YAML_TRUNCATION]
        record["traceback"] = traceback.format_exc()[-600:]
        return record

    if draft is None:
        record["category"] = "exception"
        codes = [i.code for i in issues] if issues else ["(no issues reported)"]
        record["symptom"] = f"draft_from_yaml returned None; codes: {codes}"
        record["raw_yaml_excerpt"] = raw_yaml[:RAW_YAML_TRUNCATION]
        return record

    # 2. Try to validate into a strict SigmaRule.
    sigma_or_issues = draft.to_sigma_rule()
    if isinstance(sigma_or_issues, list):
        record["category"] = "exception"
        codes = [i.code for i in sigma_or_issues]
        record["symptom"] = f"to_sigma_rule returned validation issues: {codes}"
        record["raw_yaml_excerpt"] = raw_yaml[:RAW_YAML_TRUNCATION]
        record["validation_issue_codes"] = codes
        return record

    sigma = sigma_or_issues  # type: SigmaRule

    # 3. Compare structural counts against the source.
    source = _source_structure(raw_yaml)
    if source is None:
        # pySigma couldn't parse the source — not really our fault, but
        # categorise as exception since we can't audit faithfully.
        record["category"] = "exception"
        record["symptom"] = "pySigma could not parse source raw_yaml for comparison"
        record["raw_yaml_excerpt"] = raw_yaml[:RAW_YAML_TRUNCATION]
        return record

    draft_struct = _draft_structure(sigma)

    # silent_data_loss: counts shrunk from source.
    if (
        draft_struct["block_count"] != source["block_count"]
        or draft_struct["total_items"] != source["total_items"]
        or set(draft_struct["block_names"]) != set(source["block_names"])
    ):
        record["category"] = "silent_data_loss"
        record["symptom"] = (
            f"structure mismatch: source blocks={source['block_names']} items="
            f"{source['total_items']}; draft blocks={draft_struct['block_names']} "
            f"items={draft_struct['total_items']}"
        )
        record["source_structure"] = source
        record["draft_structure"] = draft_struct
        record["raw_yaml_excerpt"] = raw_yaml[:RAW_YAML_TRUNCATION]
        return record

    # 4. desync: condition references a selection that doesn't exist in
    #    the loaded draft. Detected via the existing h-050 check.
    h050_result = condition_references_undefined(sigma)
    if h050_result is not None:
        record["category"] = "desync"
        record["symptom"] = h050_result.message
        record["raw_yaml_excerpt"] = raw_yaml[:RAW_YAML_TRUNCATION]
        record["block_names"] = draft_struct["block_names"]
        return record

    # 5. degraded: load succeeded but emitted at least one LOAD_ issue.
    if issues:
        record["category"] = "degraded"
        record["symptom"] = "; ".join(f"{i.code}: {i.message}" for i in issues[:3])
        record["issue_codes"] = [i.code for i in issues]
        return record

    # 6. clean.
    return record


def audit_corpus(
    rules: list[dict[str, Any]],
    *,
    on_progress: Callable[[int, int], None] | None = None,
) -> AuditResult:
    """Walk every rule and return the per-rule records + rollup summary.

    ``rules`` is the parsed corpus list (typically from
    ``intel2sigma/data/sigmahq_corpus.json``). Each entry must have at
    minimum ``id``, ``title``, and ``raw_yaml`` keys.

    ``on_progress`` is an optional callback invoked after every rule
    with ``(processed_count, total_count)``. The script uses it to
    print "...250 processed" lines on the ~6-second walk; the ratchet
    test passes ``None`` since pytest already shows progress.

    Pure function except for the optional callback — no I/O, no
    printing. Callers (the script, the ratchet test) handle output
    formatting themselves.
    """
    records: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()

    total = len(rules)
    for i, rule in enumerate(rules, 1):
        record = categorise_rule(rule)
        records.append(record)
        counts[record["category"]] += 1
        if on_progress is not None:
            on_progress(i, total)

    # Per-category top-failure-mode rollup for the non-clean buckets,
    # so L2 can plan fixes by symptom-frequency rather than per-rule.
    by_category_symptom: dict[str, Counter[str]] = {}
    for rec in records:
        cat = rec["category"]
        if cat == "clean":
            continue
        # Use the first 80 chars of the symptom as the dedup key —
        # close-enough to group "the same failure with different rule
        # names" without overfitting on per-rule details.
        key = rec.get("symptom", "")[:80]
        by_category_symptom.setdefault(cat, Counter())[key] += 1

    summary: AuditSummary = {
        "total_rules": total,
        "category_counts": dict(counts),
        "category_pct": {cat: round(100.0 * n / total, 2) for cat, n in counts.items()},
        "top_symptoms_per_category": {
            cat: ctr.most_common(15) for cat, ctr in by_category_symptom.items()
        },
    }

    return {"summary": summary, "records": records}


# ---------------------------------------------------------------------------
# Emit-path audit (L4). Mirror of the load-path audit above, in the other
# direction: load → re-emit via the composer's canonical path → re-parse
# the emitted YAML through pySigma → compare structural facts.
# ---------------------------------------------------------------------------

# Emit-path categories ordered by precedence — first match wins.
EMIT_CATEGORIES: tuple[str, ...] = (
    "skipped_no_strict_rule",
    "emit_exception",
    "structural_drift",
    "degraded",
    "clean",
)


def _normalize_modifier_chain(modifiers: list[str]) -> tuple[str, ...]:
    """Drop modifiers the canonical serializer normalizes away.

    ``"exact"`` is filtered out because the serializer collapses it to
    bare key on emit — see ``core/serialize.py:_detection_item_key``.
    Any other future emit-side normalizations the serializer applies
    should be mirrored here so the comparison reflects "did the rule
    survive structurally," not "did the bytes match exactly."
    """
    return tuple(m for m in modifiers if m != "exact")


def _rich_facts(py_rule: PySigmaRule) -> dict[str, Any]:
    """Pull a richer structural fingerprint than ``_source_structure``.

    L1's audit cares about block counts and names. L4 also needs
    per-item facts (field, normalized modifier chain, value set) to
    detect emit-side drift like a dropped ``|contains`` modifier or
    a missing value. Same input shape (a parsed ``PySigmaRule``);
    different — strictly richer — output.

    Output is JSON-serializable so the audit report can include it.
    """
    blocks: dict[str, dict[str, Any]] = {}
    for name, detection in py_rule.detection.detections.items():
        items: list[dict[str, Any]] = []
        for entry in detection.detection_items or []:
            # Sub-detection (list-of-mappings form) — flatten its
            # detection_items into the block-level item list. This
            # matches what the loader does (``DetectionBlock`` in
            # core/model.py is documented as accepting fidelity loss
            # on multi-field sub-groups).
            if hasattr(entry, "detection_items"):
                for sub in entry.detection_items or []:
                    items.append(_item_facts(sub))
                continue
            items.append(_item_facts(entry))
        blocks[name] = {"item_count": len(items), "items": items}
    return {
        "block_names": sorted(blocks.keys()),
        "block_count": len(blocks),
        "blocks": blocks,
        "tags_count": len(py_rule.tags or []),
    }


def _item_facts(detection_item: Any) -> dict[str, Any]:
    """Per-item structural facts: field, normalized mods, value set.

    ``detection_item`` is a pySigma ``SigmaDetectionItem``. The fields
    we care about for drift detection:
      * ``field`` — empty for keyword-search items
      * ``modifiers`` — class names like ``SigmaContainsModifier``,
        normalized to short tokens (``contains``) and run through
        ``_normalize_modifier_chain``
      * ``original_value`` — the value list / scalar before pySigma
        type-coerced it; we stringify and put in a frozenset so order
        differences (any_of blocks may shuffle) don't false-flag drift
    """
    field = getattr(detection_item, "field", None) or ""
    raw_mods = getattr(detection_item, "modifiers", []) or []
    mod_tokens = [_short_modifier_name(m) for m in raw_mods]
    raw_value = getattr(detection_item, "original_value", None)
    if isinstance(raw_value, list):
        value_iter = raw_value
    elif raw_value is None:
        value_iter = []
    else:
        value_iter = [raw_value]
    return {
        "field": field,
        "modifiers": list(_normalize_modifier_chain(mod_tokens)),
        # Frozenset-equivalent — sort for JSON-serializable
        # determinism. Drift comparison treats values as a set
        # because any_of blocks legitimately reorder.
        "values": sorted(str(v) for v in value_iter),
    }


def _short_modifier_name(mod_cls: type) -> str:
    """``SigmaContainsModifier`` → ``"contains"``."""
    name = mod_cls.__name__
    if name.startswith("Sigma"):
        name = name[len("Sigma") :]
    if name.endswith("Modifier"):
        name = name[: -len("Modifier")]
    return name.lower()


def _facts_diff(source: dict[str, Any], reemitted: dict[str, Any]) -> str | None:
    """Return a human-readable diff string if the structures differ; else None."""
    if source["block_names"] != reemitted["block_names"]:
        return (
            f"block names: source={source['block_names']} vs re-emitted={reemitted['block_names']}"
        )
    if source["block_count"] != reemitted["block_count"]:
        return (
            f"block count: source={source['block_count']} vs re-emitted={reemitted['block_count']}"
        )
    for name in source["block_names"]:
        s_block = source["blocks"][name]
        r_block = reemitted["blocks"][name]
        if s_block["item_count"] != r_block["item_count"]:
            return (
                f"block {name!r} item count: source={s_block['item_count']} "
                f"vs re-emitted={r_block['item_count']}"
            )

        # Compare item facts as sets (any_of ordering doesn't matter).
        def _key(it: dict[str, Any]) -> tuple[Any, ...]:
            return (it["field"], tuple(it["modifiers"]), tuple(it["values"]))

        s_items = {_key(it) for it in s_block["items"]}
        r_items = {_key(it) for it in r_block["items"]}
        if s_items != r_items:
            missing = s_items - r_items
            added = r_items - s_items
            parts = []
            if missing:
                parts.append(f"missing in re-emit: {sorted(missing)[:3]}")
            if added:
                parts.append(f"added by re-emit: {sorted(added)[:3]}")
            return f"block {name!r} item drift: {'; '.join(parts)}"
    return None


def categorise_emit_rule(rule: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0911, PLR0915 — flat precedence chain reads more clearly than split-into-helpers
    """L4 categoriser: load → re-emit → re-parse → compare.

    Categories (precedence order):

    1. ``skipped_no_strict_rule`` — the load path didn't yield a
       strict ``SigmaRule`` (loader returned ``None``,
       ``to_sigma_rule()`` returned validation issues, or pySigma
       couldn't parse the source). Emit testing isn't applicable;
       these rules are L1's territory.
    2. ``emit_exception`` — ``to_yaml`` raised, or pySigma can't
       parse the re-emitted output. The composer produced YAML that
       downstream tools won't accept. **Bug 2 (`|exact` non-standard
       modifier) lands here pre-fix.**
    3. ``structural_drift`` — re-emitted parses, but its structural
       facts (block names, item counts, fields, normalized modifier
       chains, value sets) differ from the originally-loaded rule.
       The composer silently changed the rule's meaning during
       round-trip.
    4. ``degraded`` — re-emit + re-parse + facts-match all clean,
       but the original load surfaced ``LOAD_*`` warnings. The user
       sees those warnings on load; emit fidelity is intact.
    5. ``clean`` — round-trips with no structural change and no
       loader warnings. The happy path.
    """
    rule_id = rule.get("id", "?")
    title = rule.get("title", "?")
    raw_yaml = rule.get("raw_yaml", "")

    record: dict[str, Any] = {
        "id": rule_id,
        "title": title[:120],
        "category": "clean",
        "symptom": "",
    }

    # 1. Try the load path. If it doesn't produce a strict rule, this
    #    is L1's territory; record + skip.
    try:
        draft, load_issues = draft_from_yaml(raw_yaml)
    except Exception as exc:
        record["category"] = "skipped_no_strict_rule"
        record["symptom"] = f"draft_from_yaml raised {type(exc).__name__}"
        return record

    if draft is None:
        record["category"] = "skipped_no_strict_rule"
        record["symptom"] = "draft_from_yaml returned None"
        return record

    sigma_or_issues = draft.to_sigma_rule()
    if isinstance(sigma_or_issues, list):
        record["category"] = "skipped_no_strict_rule"
        record["symptom"] = f"to_sigma_rule returned issues: {[i.code for i in sigma_or_issues]}"
        return record
    sigma = sigma_or_issues

    # 2. Try emitting via the canonical path.
    from intel2sigma.core.serialize import to_yaml  # noqa: PLC0415 — lazy

    try:
        reemitted_yaml = to_yaml(sigma)
    except Exception as exc:
        record["category"] = "emit_exception"
        record["symptom"] = f"to_yaml raised {type(exc).__name__}: {str(exc)[:160]}"
        record["raw_yaml_excerpt"] = raw_yaml[:RAW_YAML_TRUNCATION]
        record["traceback"] = traceback.format_exc()[-600:]
        return record

    # 3. Try re-parsing the emitted YAML through pySigma.
    try:
        reemitted_pyrule = PySigmaRule.from_yaml(reemitted_yaml)
    except Exception as exc:
        record["category"] = "emit_exception"
        record["symptom"] = (
            f"pySigma rejected re-emitted YAML: {type(exc).__name__}: {str(exc)[:160]}"
        )
        record["raw_yaml_excerpt"] = raw_yaml[:RAW_YAML_TRUNCATION]
        record["reemitted_yaml_excerpt"] = reemitted_yaml[:RAW_YAML_TRUNCATION]
        return record

    # 4. Both sides parse; compare structural facts.
    try:
        source_pyrule = PySigmaRule.from_yaml(raw_yaml)
    except Exception:
        # Source was un-parseable but our composer somehow accepted it
        # and re-emit was clean. Skip — comparing against nothing.
        record["category"] = "skipped_no_strict_rule"
        record["symptom"] = "pySigma could not parse source for comparison"
        return record

    source_facts = _rich_facts(source_pyrule)
    reemit_facts = _rich_facts(reemitted_pyrule)
    diff = _facts_diff(source_facts, reemit_facts)
    if diff is not None:
        record["category"] = "structural_drift"
        record["symptom"] = diff
        record["raw_yaml_excerpt"] = raw_yaml[:RAW_YAML_TRUNCATION]
        record["reemitted_yaml_excerpt"] = reemitted_yaml[:RAW_YAML_TRUNCATION]
        record["source_facts"] = source_facts
        record["reemit_facts"] = reemit_facts
        return record

    # 5. Structural identity. Was the original load clean or degraded?
    if load_issues:
        record["category"] = "degraded"
        record["symptom"] = "; ".join(f"{i.code}" for i in load_issues[:3])
        record["issue_codes"] = [i.code for i in load_issues]
        return record

    # 6. Clean.
    return record


def audit_corpus_emits(
    rules: list[dict[str, Any]],
    *,
    on_progress: Callable[[int, int], None] | None = None,
) -> AuditResult:
    """Walk every rule through the L4 emit categoriser. Returns an
    :class:`AuditResult` mirroring the load-audit shape.

    Same progress-callback contract as :func:`audit_corpus` so the
    script can tick through a long walk and the L6 ratchet test can
    pass ``None`` for silent runs.
    """
    records: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()

    total = len(rules)
    for i, rule in enumerate(rules, 1):
        record = categorise_emit_rule(rule)
        records.append(record)
        counts[record["category"]] += 1
        if on_progress is not None:
            on_progress(i, total)

    by_category_symptom: dict[str, Counter[str]] = {}
    for rec in records:
        cat = rec["category"]
        if cat in {"clean", "skipped_no_strict_rule"}:
            continue
        key = rec.get("symptom", "")[:80]
        by_category_symptom.setdefault(cat, Counter())[key] += 1

    summary: AuditSummary = {
        "total_rules": total,
        "category_counts": dict(counts),
        "category_pct": {cat: round(100.0 * n / total, 2) for cat, n in counts.items()},
        "top_symptoms_per_category": {
            cat: ctr.most_common(15) for cat, ctr in by_category_symptom.items()
        },
    }

    return {"summary": summary, "records": records}


__all__ = [
    "CATEGORIES",
    "EMIT_CATEGORIES",
    "RAW_YAML_TRUNCATION",
    "AuditResult",
    "AuditSummary",
    "audit_corpus",
    "audit_corpus_emits",
    "categorise_emit_rule",
    "categorise_rule",
]
