#!/usr/bin/env python
"""L8-A — corpus state-fidelity audit. Read-only.

The third audit script in the v1.x sweep family, after L1
(``audit_corpus_loads.py``, load-content fidelity) and L4
(``audit_corpus_emits.py``, emit-content fidelity). L8 measures
**every** observable property of ``RuleDraft`` post-load — identity,
prose metadata, list metadata, logsource, routing, and UI state —
each one as a separate "fidelity dimension."

The discovery problem this solves: bugs that escape L1 + L4 because
their structural checks don't measure the failing dimension. The
screenshot bug from 2026-05-02 (service-only logsource → empty
observation_id → renderer falls back to Stage 0 even though
``draft.stage`` says 3) was the third such finding; L8's catalogue
guarantees the next undiscovered dimension drift fails CI instead
of slipping to a user.

For each corpus rule:

  1. Parse source via pySigma.
  2. Load via ``web/load.draft_from_yaml``.
  3. Run every dimension in ``_fidelity.FIDELITY_DIMENSIONS`` —
     each returns PASS / FAIL / N/A.

Output: ``reports/corpus_fidelity_audit.json`` with per-dimension
counts + 5 fail-examples per drifting dimension. Adding a new
dimension is data — append to ``FIDELITY_DIMENSIONS``, no script
changes required.

Run via:
    uv run python scripts/audit_corpus_fidelity.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from intel2sigma._fidelity import FIDELITY_DIMENSIONS, audit_corpus_fidelity

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "intel2sigma" / "data" / "sigmahq_corpus.json"
REPORT = ROOT / "reports" / "corpus_fidelity_audit.json"


def main() -> int:
    if not CORPUS.is_file():
        print(f"FATAL: corpus not found at {CORPUS}", file=sys.stderr)
        return 1

    rules = json.loads(CORPUS.read_text(encoding="utf-8"))
    if not isinstance(rules, list):
        print("FATAL: corpus JSON is not a list", file=sys.stderr)
        return 1

    print(
        f"Auditing fidelity across {len(FIDELITY_DIMENSIONS)} "
        f"dimensions on {len(rules)} corpus rules..."
    )

    def _tick(processed: int, total: int) -> None:
        if processed % 250 == 0:
            print(f"  ...{processed} processed")

    summary = audit_corpus_fidelity(rules, on_progress=_tick)

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    total = summary["total_rules"]
    print()
    print(f"Audited {total} corpus rules. Report written to {REPORT}")
    print()

    # Group dimensions by their declared group for readable output.
    by_group: dict[str, list[str]] = {}
    for dim in FIDELITY_DIMENSIONS:
        by_group.setdefault(dim.group, []).append(dim.name)

    print(f"  {'dimension':<42s}  {'pass':>6s}  {'fail':>6s}  {'n/a':>6s}")
    print(f"  {'-' * 42}  {'-' * 6}  {'-' * 6}  {'-' * 6}")
    for group, names in by_group.items():
        print(f"  [{group}]")
        for name in names:
            cnt = summary["per_dimension"].get(name, {})
            print(
                f"  {name:<42s}  {cnt.get('pass', 0):>6d}  "
                f"{cnt.get('fail', 0):>6d}  {cnt.get('n/a', 0):>6d}"
            )
    # Meta dimensions (parse / load failures recorded outside the
    # dimension catalogue so they show up in the rollup but don't
    # crash the walk).
    print("  [meta]")
    for name in ("_meta_source_parse", "_meta_load"):
        cnt = summary["per_dimension"].get(name, {})
        if cnt.get("fail", 0):
            print(
                f"  {name:<42s}  {cnt.get('pass', 0):>6d}  "
                f"{cnt.get('fail', 0):>6d}  {cnt.get('n/a', 0):>6d}"
            )
    print()

    # Drift symptoms — top 3 examples per failing dimension.
    drifting = [name for name, cnt in summary["per_dimension"].items() if cnt.get("fail", 0) > 0]
    if drifting:
        print(f"Drifting dimensions ({len(drifting)}):")
        for name in drifting:
            cnt = summary["per_dimension"][name]
            print(f"  {name} ({cnt['fail']} fails):")
            for ex in summary["fail_examples"].get(name, [])[:3]:
                detail = ex.get("detail", "")[:100]
                print(f"    [{ex['rule_id'][:8]}] {ex['title'][:60]}")
                if detail:
                    print(f"      {detail}")
            print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
