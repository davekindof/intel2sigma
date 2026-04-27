#!/usr/bin/env python
"""L1 — corpus load-audit. Read-only.

Walks every rule in ``intel2sigma/data/sigmahq_corpus.json`` (3,708
rules at last calibration), exercises the full ``web/load.py``
load path on each, and categorises the outcome. Writes a per-rule
breakdown + rollup totals to ``reports/corpus_load_audit.json``
and prints a summary table to stdout.

No fixes. No code changes outside this script. Output is the
input to L2 — the failure-mode breakdown drives the prioritised
fix sweep.

Categories (precedence in order):

  1. exception       — loader can't produce a draft at all
                       (returned None, or to_sigma_rule() returned a
                       list of validation issues).
  2. silent_data_loss — load "succeeded" with no LOAD_ issue, but
                       structural counts (detection blocks, items,
                       values) differ from the source. The most-
                       dangerous category — nothing flags it to the
                       user. P1-class bugs from earlier dogfooding
                       fall here when they don't trigger h-050.
  3. desync          — load "succeeded" with no LOAD_ issue, but
                       the loaded rule fails h-050 (condition
                       references a selection that doesn't exist).
                       The classic "loader synthesised the wrong
                       condition shape" failure mode.
  4. degraded        — load succeeded; one or more LOAD_ issues
                       were emitted (LOAD_OBSERVATION_UNKNOWN,
                       LOAD_CONDITION_UNUSUAL, LOAD_NESTED_
                       SUBGROUPS_FLATTENED, etc.). User sees
                       warnings; functionality is intact.
  5. clean           — load succeeded, no issues, structural
                       counts match, h-050 does not fire. The
                       happy path.

Run via:
    uv run python scripts/audit_corpus_loads.py

The script is intentionally a one-off — no CLI flags, no test
mode. L3 will convert it into a slow integration test once L2
clears the desync / silent_data_loss categories to zero.
"""

from __future__ import annotations

import json
import sys
import traceback
from collections import Counter
from pathlib import Path
from typing import Any

from sigma.rule import SigmaRule as PySigmaRule

from intel2sigma.core.heuristics.checks.condition_integrity import (
    condition_references_undefined,
)
from intel2sigma.core.model import SigmaRule
from intel2sigma.web.load import draft_from_yaml

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "intel2sigma" / "data" / "sigmahq_corpus.json"
REPORT = ROOT / "reports" / "corpus_load_audit.json"

# Truncate raw_yaml in problem-category records so the report stays
# inspectable without ballooning to MBs. 800 chars is enough to read
# the title + logsource + first detection block, which is usually
# the shape needed to repro the symptom.
RAW_YAML_TRUNCATION = 800


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


def _categorise(rule: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0911 — category-precedence logic; one early-return per category is the clearest shape
    """Run one rule through the load path and return its categorisation."""
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


def main() -> int:
    if not CORPUS.is_file():
        print(f"FATAL: corpus not found at {CORPUS}", file=sys.stderr)
        return 1

    rules = json.loads(CORPUS.read_text(encoding="utf-8"))
    if not isinstance(rules, list):
        print("FATAL: corpus JSON is not a list", file=sys.stderr)
        return 1

    print(f"Auditing {len(rules)} corpus rules...")
    records: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()

    for i, rule in enumerate(rules, 1):
        record = _categorise(rule)
        records.append(record)
        counts[record["category"]] += 1
        if i % 250 == 0:
            print(f"  ...{i} processed")

    total = len(records)

    # Rollup.
    summary = {
        "total_rules": total,
        "category_counts": dict(counts),
        "category_pct": {cat: round(100.0 * n / total, 2) for cat, n in counts.items()},
    }

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

    summary["top_symptoms_per_category"] = {
        cat: ctr.most_common(15) for cat, ctr in by_category_symptom.items()
    }

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        json.dumps(
            {"summary": summary, "records": records},
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    # Stdout summary table.
    print()
    print(f"Audited {total} corpus rules. Report written to {REPORT}")
    print()
    print(f"  {'category':<20s}  {'count':>6s}  {'%':>6s}")
    print(f"  {'-' * 20}  {'-' * 6}  {'-' * 6}")
    for cat in ("clean", "degraded", "desync", "silent_data_loss", "exception"):
        n = counts.get(cat, 0)
        pct = 100.0 * n / total if total else 0
        print(f"  {cat:<20s}  {n:>6d}  {pct:>5.2f}%")
    print()

    # Top 5 symptoms per non-clean category for at-a-glance L2 planning.
    for cat in ("exception", "silent_data_loss", "desync", "degraded"):
        if cat not in by_category_symptom:
            continue
        print(f"Top symptoms — {cat}:")
        for symptom, n in by_category_symptom[cat].most_common(5):
            print(f"  [{n:>4d}] {symptom}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
