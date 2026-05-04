"""L8-C — corpus state-fidelity ratchet test.

Mirrors L3 (load-content) and L6 (emit-content) for the fidelity-
dimension audit. Wraps :func:`intel2sigma._audit.audit_corpus_fidelity
<intel2sigma._fidelity.audit_corpus_fidelity>` as ``@pytest.mark.slow``
checks that lock in per-dimension drift floors.

The contract Pattern L8 enforces:

* every observable property of ``RuleDraft`` post-load is measured
* per-dimension drift counts must not regress
* the catalogue is data: adding a new property to ``RuleDraft``
  requires adding a fidelity dimension, and CI catches the
  regression at ratchet-floor time

This file is the structural endpoint of that contract. Future PRs
that touch the loader, serializer, or model surface re-run the slow
suite; if any dimension's fail count rises above its floor, CI
fails and the regression is named per-dimension in the failure
message.

Slow-suite cost: ~5 min wall-clock per pass. Module-scoped fixture
keeps it at one pass for all checks.
"""

from __future__ import annotations

import json

import pytest

from intel2sigma._data import data_path
from intel2sigma._fidelity import (
    FIDELITY_DIMENSIONS,
    FidelitySummary,
    audit_corpus_fidelity,
)

# ----- Per-dimension fail-count floors ---------------------------------------
#
# Each dimension's fail count must stay AT OR BELOW this number. When a
# fix improves the count, bump the floor in the same commit.
#
# History:
#   2026-05-02 (533c9d0, L8-A baseline)
#                          description=955, observation_id_populated=797,
#                          observation_id_matches_catalog=212
#   2026-05-02 (c8b9b66, L8-B-1 description normalization)
#                          description=0
#   2026-05-02 (dc47960, L8-B-2 multi-axis routing)
#                          observation_id_populated=0,
#                          observation_id_matches_catalog=27 (residual)
#   2026-05-02 (a06e946, L8-B-3 audit/loader wildcard alignment)
#                          observation_id_matches_catalog=0
#
# Every dimension at 0 fails as of L8-B-3.
_MAX_FAIL_PER_DIMENSION: dict[str, int] = {
    "title": 0,
    "id": 0,
    "status": 0,
    "level": 0,
    "description": 0,
    "author": 0,
    "date": 0,
    "modified": 0,
    "references": 0,
    "tags": 0,
    "falsepositives": 0,
    "logsource_category": 0,
    "logsource_product": 0,
    "logsource_service": 0,
    "observation_id_populated": 0,
    "observation_id_matches_catalog": 0,
    "platform_id_consistent_with_product": 0,
    "stage": 0,
}

# Meta dimensions track parse / load failures. Both must stay at 0
# — non-zero means the audit framework itself is breaking on some
# corpus rule, not measuring real drift.
_META_DIMENSIONS = ("_meta_source_parse", "_meta_load")


@pytest.fixture(scope="module")
def corpus_fidelity_audit() -> FidelitySummary:
    """Run the full fidelity audit ONCE per test module.

    Module scope makes the slow suite ~5 min instead of N x 5 min
    where N is the number of test cases below.
    """
    corpus_path = data_path("sigmahq_corpus.json")
    rules = json.loads(corpus_path.read_text(encoding="utf-8"))
    assert isinstance(rules, list), f"corpus must be a JSON list, got {type(rules).__name__}"
    return audit_corpus_fidelity(rules)


@pytest.mark.slow
def test_meta_dimensions_stay_zero(
    corpus_fidelity_audit: FidelitySummary,
) -> None:
    """Audit framework must successfully measure every corpus rule.

    The meta dimensions track cases where the audit itself failed:

    * ``_meta_source_parse`` — pySigma rejected the corpus rule
      (we couldn't get a SigmaRule to compare against). Should be
      zero on a curated, validated corpus.
    * ``_meta_load`` — our loader returned ``None`` (LOAD_PARSE_FAILED
      or similar). Must stay zero — every corpus rule loads.

    Non-zero counts here invalidate the per-dimension measurements
    for the affected rules; the framework itself is broken, not the
    product code under audit.
    """
    failures: list[str] = []
    for name in _META_DIMENSIONS:
        cnt = corpus_fidelity_audit["per_dimension"].get(name, {})
        n = cnt.get("fail", 0)
        if n != 0:
            failures.append(f"  {name}: {n} (must stay 0)")
    assert not failures, (
        "Audit meta-dimension failures (framework broke, not the audit subject):\n"
        + "\n".join(failures)
    )


@pytest.mark.slow
def test_no_dimension_drifts_above_its_floor(
    corpus_fidelity_audit: FidelitySummary,
) -> None:
    """Every fidelity dimension's fail count must stay at or below its
    declared floor in ``_MAX_FAIL_PER_DIMENSION``.

    On regression, prints the offending dimensions, their actual
    counts, the floor, and three example failing rules each — the
    triage info needed to decide whether to fix the underlying bug
    or relax the floor (and document why).

    On improvement: this test still passes (actual ≤ floor with
    headroom). The convention is to bump the floor in the same
    commit as the fix; the soft-staleness check below catches
    forgotten bumps.
    """
    failures: list[str] = []
    for dim in FIDELITY_DIMENSIONS:
        floor = _MAX_FAIL_PER_DIMENSION.get(dim.name)
        if floor is None:
            failures.append(
                f"  {dim.name}: missing from _MAX_FAIL_PER_DIMENSION — "
                f"add an entry whenever a new dimension lands"
            )
            continue
        cnt = corpus_fidelity_audit["per_dimension"].get(dim.name, {})
        actual = cnt.get("fail", 0)
        if actual > floor:
            examples = corpus_fidelity_audit["fail_examples"].get(dim.name, [])
            example_lines = "\n".join(
                f"      [{ex['rule_id'][:8]}] {ex['title'][:60]}: {ex.get('detail', '')[:100]}"
                for ex in examples[:3]
            )
            failures.append(f"  {dim.name}: {actual} fails (floor {floor})\n{example_lines}")
    assert not failures, "Fidelity ratchet: dimension(s) drifted above floor.\n" + "\n".join(
        failures
    )


@pytest.mark.slow
def test_floor_not_too_stale(
    corpus_fidelity_audit: FidelitySummary,
) -> None:
    """Soft check: every dimension's floor shouldn't be more than 50
    above its actual fail count.

    When a PR ships a fix that improves a dimension and forgets to
    bump the floor, the primary ratchet still passes (actual ≤
    floor) and the dev never sees the lag. This test catches that
    case — if floor exceeds actual by >50 for any dimension, the
    constant is due for a downward bump.

    Tolerance is 50 because work-in-progress branches can
    legitimately leave the floor temporarily lax for a single
    commit. The lag becomes obvious-and-actionable past that.
    """
    stale: list[str] = []
    for dim in FIDELITY_DIMENSIONS:
        floor = _MAX_FAIL_PER_DIMENSION.get(dim.name)
        if floor is None:
            continue
        actual = corpus_fidelity_audit["per_dimension"].get(dim.name, {}).get("fail", 0)
        lag = floor - actual
        if lag > 50:
            stale.append(f"  {dim.name}: floor={floor} actual={actual} lag=+{lag} (tolerance 50)")
    assert not stale, (
        "Fidelity ratchet: floor(s) stale.\n"
        + "\n".join(stale)
        + "\n\nBump _MAX_FAIL_PER_DIMENSION for the listed dimensions "
        "in your next commit so future regressions catch sooner."
    )
