"""L3 — corpus load-audit ratchet test.

Wraps the L1 audit (``intel2sigma._audit.audit_corpus``) as a
``@pytest.mark.slow`` integration test that locks in the corpus
clean-rate floor. Replaces the prior "run the script manually,
spot-check the report" workflow with a CI gate that fails fast on
any regression in:

* the **exception** count (must stay 0)
* the **desync** count (must stay 0)
* the **silent_data_loss** count (must stay 0)
* the **clean** count (must not drop below ``MIN_CLEAN_COUNT``)

The ratchet is one-way. When a fix improves the clean count, the
test stays green — but the dev should bump ``MIN_CLEAN_COUNT`` in
the same PR so the new floor is locked in. A comment-only update
to the constant is the right shape for those PRs.

Why this exists: the L2-P1 sweep moved clean from 88.75% (3,291) to
91.64% (3,398) in four commits; without a ratchet, a future loader
or serializer change could quietly take some of that back. The
audit script catches it but only when someone runs it. CI catches
it on every PR.

Marked ``slow`` because the walk is ~7 minutes across 3,708 rules
(each rule pays for two pySigma parses + a strict-model build + an
h-050 check; the cost is real and the corpus is intentionally
exhaustive). The :func:`corpus_audit` fixture is module-scoped so
the three ratchet checks share a single audit pass instead of
running it three times. ``uv run pytest -m "not slow"`` excludes
the test from the default loop; ``uv run pytest -m slow``
(or ``pytest tests/test_corpus_load_audit_ratchet.py``) runs it
explicitly. CI runs the slow suite as a separate stage so it
doesn't gate the fast pre-commit feedback loop.
"""

from __future__ import annotations

import json

import pytest

from intel2sigma._audit import AuditResult, audit_corpus
from intel2sigma._data import data_path

# ----- Ratchet floors -----------------------------------------------------
#
# Clean-count floor. The test fails if the current clean count drops
# below this number. When you ship a fix that improves the count, bump
# this constant in the same commit — that's how the ratchet locks in.
#
# History:
#   2026-04-26 (e9a040b, L1 baseline)  — 3291 (88.75%)
#   2026-04-27 (781faea, L2-P1a)       — 3296 (88.89%)
#   2026-04-27 (cebaa00, L2-P1b)       — 3366 (90.78%)
#   2026-04-27 (4100c67, L2-P1c)       — 3367 (90.80%)
#   2026-04-27 (625776e, L2-P1d)       — 3398 (91.64%)
MIN_CLEAN_COUNT = 3398

# Categories that MUST stay at zero. Any non-zero count is either a
# regression (loader started raising or losing data) or evidence that
# the fix wasn't complete (something snuck back into desync). All three
# are blocking — the audit script's exit code uses the same contract.
ZERO_CATEGORIES = ("exception", "desync", "silent_data_loss")


@pytest.fixture(scope="module")
def corpus_audit() -> AuditResult:
    """Load corpus + run the audit ONCE per test module.

    The audit walk is ~7 minutes across 3,708 rules. Module scoping is
    not just a JSON-parse optimisation — without it, each of the three
    ratchet tests would re-run the full audit, blowing the slow suite
    out to ~21 minutes per CI run. With module scope, all three
    assertions read from a single audit pass.
    """
    corpus_path = data_path("sigmahq_corpus.json")
    rules = json.loads(corpus_path.read_text(encoding="utf-8"))
    assert isinstance(rules, list), f"corpus must be a JSON list, got {type(rules).__name__}"
    return audit_corpus(rules)


@pytest.mark.slow
def test_audit_zero_categories_stay_at_zero(
    corpus_audit: AuditResult,
) -> None:
    """No corpus rule may trip exception / desync / silent_data_loss.

    These three buckets are the audit's "must never happen" contract.
    A non-zero count means either:

    * **exception** — the loader can't produce a draft (raised, returned
      ``None``, or ``to_sigma_rule()`` returned validation issues). The
      L2-P1 sweep cleared this to 0 in commit ``625776e``; it should
      stay there.
    * **desync** — the loader returned a draft whose condition
      references a selection that doesn't exist in the loaded
      detection blocks. The classic "loader synthesised the wrong
      condition shape" failure mode.
    * **silent_data_loss** — load "succeeded" with no LOAD_ issue, but
      the structural counts (block names, item counts) don't match
      pySigma's parse of the source. The most-dangerous category —
      nothing flags it to the user. Held at 0 throughout the sweep.

    On failure, dumps the top symptoms so the failing CI log shows
    which rule shape regressed.
    """
    counts = corpus_audit["summary"]["category_counts"]
    by_symptom = corpus_audit["summary"]["top_symptoms_per_category"]

    failures: list[str] = []
    for cat in ZERO_CATEGORIES:
        n = counts.get(cat, 0)
        if n != 0:
            symptoms = by_symptom.get(cat, [])
            top = "\n".join(f"    [{c:>4d}] {s}" for s, c in symptoms[:5])
            failures.append(f"  {cat}: {n} (expected 0)\n{top}")

    assert not failures, "Audit ratchet: zero-categories regressed.\n" + "\n".join(failures)


@pytest.mark.slow
def test_audit_clean_count_holds_floor(
    corpus_audit: AuditResult,
) -> None:
    """The clean-rule count may not drop below ``MIN_CLEAN_COUNT``.

    A drop means a regression took rules that used to round-trip
    cleanly and broke them — by adding a new LOAD_ warning, by
    changing tier-1 to reject something it used to accept, by
    introducing a structural mismatch, or by triggering h-050 on
    something that previously passed.

    On improvement, this test still passes. The convention is to bump
    ``MIN_CLEAN_COUNT`` in the same commit as the fix, which both
    locks in the new floor and documents the win in the constant's
    history comment above. A "soft floor lag" — a fix in flight that
    hasn't ratcheted the constant yet — is fine; the test only fails
    on actual regressions.
    """
    counts = corpus_audit["summary"]["category_counts"]
    actual = counts.get("clean", 0)
    assert actual >= MIN_CLEAN_COUNT, (
        f"Audit ratchet: clean count regressed from floor.\n"
        f"  expected >= {MIN_CLEAN_COUNT}\n"
        f"  actual    = {actual}\n"
        f"  delta     = {actual - MIN_CLEAN_COUNT}\n"
        f"  full counts: {counts}"
    )


@pytest.mark.slow
def test_audit_floor_not_too_stale(
    corpus_audit: AuditResult,
) -> None:
    """Soft check: ``MIN_CLEAN_COUNT`` shouldn't lag actual by >100.

    When a PR ships a load-path fix that takes the clean count from
    3,398 to 3,500 and forgets to bump ``MIN_CLEAN_COUNT``, the
    primary ratchet still passes (3,500 >= 3,398) so the dev never
    sees the lag. This test catches that case — if the actual clean
    count exceeds the constant by more than 100, the constant is due
    for a bump.

    Tolerance is 100 because work-in-progress branches can legitimately
    be ahead of the constant for a single commit. The lag becomes
    obvious-and-actionable past that.
    """
    actual = corpus_audit["summary"]["category_counts"].get("clean", 0)
    lag = actual - MIN_CLEAN_COUNT
    assert lag <= 100, (
        f"Audit ratchet: MIN_CLEAN_COUNT is stale.\n"
        f"  constant: {MIN_CLEAN_COUNT}\n"
        f"  actual:   {actual}\n"
        f"  lag:      +{lag} (tolerance: +100)\n"
        f"Bump MIN_CLEAN_COUNT in tests/test_corpus_load_audit_ratchet.py "
        f"to {actual} in your next commit."
    )
