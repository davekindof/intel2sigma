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

The categorisation logic itself lives in
:mod:`intel2sigma._audit` so the L3 ratchet test
(``tests/test_corpus_load_audit_ratchet.py``) can call it without
reaching into ``scripts/``. This script is a thin CLI wrapper —
load the corpus, call :func:`audit_corpus`, write the report,
print a human summary.

Run via:
    uv run python scripts/audit_corpus_loads.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from intel2sigma._audit import audit_corpus

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "intel2sigma" / "data" / "sigmahq_corpus.json"
REPORT = ROOT / "reports" / "corpus_load_audit.json"


def main() -> int:
    if not CORPUS.is_file():
        print(f"FATAL: corpus not found at {CORPUS}", file=sys.stderr)
        return 1

    rules = json.loads(CORPUS.read_text(encoding="utf-8"))
    if not isinstance(rules, list):
        print("FATAL: corpus JSON is not a list", file=sys.stderr)
        return 1

    print(f"Auditing {len(rules)} corpus rules...")

    def _tick(processed: int, total: int) -> None:
        # Tick every 250 so the user sees progress on the ~6s walk.
        if processed % 250 == 0:
            print(f"  ...{processed} processed")

    full = audit_corpus(rules, on_progress=_tick)
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
    print(f"  {'category':<20s}  {'count':>6s}  {'%':>6s}")
    print(f"  {'-' * 20}  {'-' * 6}  {'-' * 6}")
    for cat in ("clean", "degraded", "desync", "silent_data_loss", "exception"):
        n = counts.get(cat, 0)
        pct = 100.0 * n / total if total else 0
        print(f"  {cat:<20s}  {n:>6d}  {pct:>5.2f}%")
    print()

    # Top 5 symptoms per non-clean category for at-a-glance L2 planning.
    by_symptom = summary["top_symptoms_per_category"]
    for cat in ("exception", "silent_data_loss", "desync", "degraded"):
        if cat not in by_symptom:
            continue
        print(f"Top symptoms — {cat}:")
        for symptom, n in by_symptom[cat][:5]:
            print(f"  [{n:>4d}] {symptom}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
