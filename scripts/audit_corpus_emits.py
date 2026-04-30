#!/usr/bin/env python
"""L4 — corpus emit-audit. Read-only.

Walks every rule in ``intel2sigma/data/sigmahq_corpus.json``, runs
each through the composer's emit path, re-parses through pySigma,
and categorises the outcome by structural fidelity. The mirror of
``scripts/audit_corpus_loads.py`` (L1) for the OTHER direction —
the load-path sweep verified what we ingest, this verifies what we
emit.

For each corpus rule:

  1. Load via ``web/load.draft_from_yaml``.
  2. Build a strict ``SigmaRule`` via ``draft.to_sigma_rule()``.
  3. Re-emit via ``core/serialize.to_yaml``.
  4. Parse the re-emitted YAML through pySigma's permissive parser.
  5. Compare structural facts (block names, item counts, fields,
     normalized modifier chains, value sets) against the original.

Categories (precedence order):

  1. ``skipped_no_strict_rule`` — couldn't get a SigmaRule out of
                                  the loader. L1's territory; we
                                  count and move on.
  2. ``emit_exception``         — to_yaml raised, OR pySigma can't
                                  parse the re-emitted output. The
                                  composer produced YAML downstream
                                  tools won't accept.
  3. ``structural_drift``       — re-emitted parses, but its facts
                                  differ from the source. The
                                  composer silently changed the
                                  rule's meaning during round-trip.
  4. ``degraded``               — round-trip clean, but original
                                  load surfaced LOAD_* warnings.
                                  Acceptable.
  5. ``clean``                  — round-trips with no structural
                                  change and no loader warnings.

The categorisation logic itself lives in :mod:`intel2sigma._audit`
so the L6 ratchet test can call it without reaching into
``scripts/``. This script is a thin CLI wrapper — load corpus,
call ``audit_corpus_emits``, write the report, print summary.

Run via:
    uv run python scripts/audit_corpus_emits.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from intel2sigma._audit import audit_corpus_emits

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "intel2sigma" / "data" / "sigmahq_corpus.json"
REPORT = ROOT / "reports" / "corpus_emit_audit.json"


def main() -> int:
    if not CORPUS.is_file():
        print(f"FATAL: corpus not found at {CORPUS}", file=sys.stderr)
        return 1

    rules = json.loads(CORPUS.read_text(encoding="utf-8"))
    if not isinstance(rules, list):
        print("FATAL: corpus JSON is not a list", file=sys.stderr)
        return 1

    print(f"Auditing emit path on {len(rules)} corpus rules...")

    def _tick(processed: int, total: int) -> None:
        # Tick every 250 so the user sees progress on the long walk.
        # Emit-audit is roughly twice the per-rule cost of load-audit
        # because it parses pySigma three times per rule (source for
        # comparison, draft_from_yaml's internal parse, re-parse of
        # the emitted output).
        if processed % 250 == 0:
            print(f"  ...{processed} processed")

    full = audit_corpus_emits(rules, on_progress=_tick)
    summary = full["summary"]

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        json.dumps(
            {"summary": summary, "records": full["records"]},
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    total = summary["total_rules"]
    counts = summary["category_counts"]

    # Stdout summary table.
    print()
    print(f"Audited {total} corpus rules. Report written to {REPORT}")
    print()
    print(f"  {'category':<25s}  {'count':>6s}  {'%':>6s}")
    print(f"  {'-' * 25}  {'-' * 6}  {'-' * 6}")
    for cat in (
        "clean",
        "degraded",
        "structural_drift",
        "emit_exception",
        "skipped_no_strict_rule",
    ):
        n = counts.get(cat, 0)
        pct = 100.0 * n / total if total else 0
        print(f"  {cat:<25s}  {n:>6d}  {pct:>5.2f}%")
    print()

    # Top 5 symptoms per non-clean category.
    by_symptom = summary["top_symptoms_per_category"]
    for cat in ("emit_exception", "structural_drift", "degraded"):
        if cat not in by_symptom:
            continue
        print(f"Top symptoms — {cat}:")
        for symptom, n in by_symptom[cat][:5]:
            print(f"  [{n:>4d}] {symptom}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
