"""L6 — corpus emit-audit ratchet test.

Mirror of ``tests/test_corpus_load_audit_ratchet.py`` (L3) for the
emit-path direction. Wraps the L4 audit
(``intel2sigma._audit.audit_corpus_emits``) as a
``@pytest.mark.slow`` integration test that locks in the corpus
emit-clean-rate floor. Replaces the prior "run the script manually,
spot-check the report" workflow with a CI gate that fails fast on
any regression in:

* the **emit_exception** count (must stay 0 — composer must never
  produce YAML pySigma can't parse back)
* the **clean** count (must not drop below ``MIN_EMIT_CLEAN_COUNT``)

* the **structural_drift** count (must stay at
  ``MAX_STRUCTURAL_DRIFT``, currently 0)

This file long described drift as floored rather than zeroed, on the
assumption that a residual was inevitable — some Sigma idioms our
model can't losslessly represent (multi-field AND-in-OR sub-groups,
exotic condition shapes captured by L2-P3) would register as drift.
No floor was ever actually implemented, and the four rules sitting in
that bucket turned out not to be unrepresentable idioms at all: they
were a silent-data-loss bug in the loader's modifier handling, found
2026-08-02. Drift is now zero and gated. See ``MAX_STRUCTURAL_DRIFT``
for what to do if a genuinely unrepresentable idiom ever appears.

The ratchet is one-way. When a fix improves the clean count, the
test stays green — but the dev should bump ``MIN_EMIT_CLEAN_COUNT``
in the same PR so the new floor is locked in. A comment-only update
to the constant is the right shape for those PRs.

Why this exists: the L4 sweep moved emit_clean from 87.57% (3247) to
93.07% (3451) in one round of L5 fixes; without a ratchet, a future
serializer or loader change could quietly take some of that back.
The audit script catches it but only when someone runs it. CI catches
it on every PR.

Marked ``slow`` because the walk is ~25 minutes across 3,708 rules
(each rule pays for two pySigma parses + a strict-model build + a
to_yaml + a re-parse + structural comparison). The
:func:`corpus_emit_audit` fixture is module-scoped so the three
ratchet checks share a single audit pass instead of running it
three times. ``uv run pytest -m "not slow"`` excludes the test
from the default loop; ``uv run pytest -m slow``
(or ``pytest tests/test_corpus_emit_audit_ratchet.py``) runs it
explicitly. CI runs the slow suite as a separate stage so it
doesn't block the fast pre-commit feedback loop.
"""

from __future__ import annotations

import json

import pytest

from intel2sigma._audit import AuditResult, audit_corpus_emits
from intel2sigma._data import data_path

# ----- Ratchet floors -----------------------------------------------------
#
# Emit-clean-count floor. The test fails if the current count drops
# below this number. When you ship a fix that improves the count,
# bump this constant in the same commit — that's how the ratchet
# locks in.
#
# History:
#   2026-04-30 (9d29157, L4 baseline)        — 3247 (87.57%)
#   2026-04-30 (5bec168, L5-A SigmaNull)     — audit-only fix; product
#                                              numbers measured next
#   2026-04-30 (8631a72, L5-B windash)       — 3451 (93.07%)
#   2026-04-30 (dc4101b, L5-C YAML-1.1 bool) — 3455 (93.18%) [+4 emit_
#                                              exception cleared]
#   2026-05-01 (65cb708, L5-D regex/.original) — 3565 (96.14%)
#   2026-05-01 (14b29cd, L5-E keyword|all)     — 3578 (96.49%)
#   2026-07-27 (corpus r2026-07-01 + L8-B-2 routing fix) — 3419
#     Moves DOWN in lockstep with MIN_CLEAN_COUNT in the load-audit
#     ratchet (3582 -> 3423). The emit audit inherits routing from
#     the same loader, so it tracks the identical split: +211
#     genuine regressions recovered by the category-anchored service
#     exemption, ~159 rules newly *reported* (uncatalogued
#     service-only logsources that previously counted clean with an
#     empty observation_id). See that constant's history entry for
#     the full reasoning — a measurement correction, not lost
#     functionality.
#   2026-08-02 (keyword-list parser + modifier fixes) — 3423
#     +4: the four rules that were losing `fieldref` / `re|i` on load
#     now round-trip, so they move from structural_drift into clean.
#   2026-08-30 (2026-Q3 catalog expansion) — 3543
#     +120, tracking MIN_CLEAN_COUNT exactly. The emit audit inherits
#     routing from the loader, so 17 new catalog entries lift both
#     counts identically — the two are now equal at 3543, which is
#     expected rather than a coincidence worth chasing.
MIN_EMIT_CLEAN_COUNT = 3543

# Structural drift must now stay at zero.
#
# This module's docstring has always said drift "is floored instead" of
# held at zero — but no floor existed, which is exactly how four rules
# sat in that bucket unnoticed. They were not an unrepresentable Sigma
# idiom; they were a real silent-data-loss bug. web/load.py kept a
# hardcoded copy of ValueModifier that had drifted from the model, so
# `Image|fieldref: ParentImage` loaded with the modifier stripped and
# quietly became a literal match on the string "ParentImage".
#
# Zero is the honest floor today. If a future corpus refresh introduces
# a genuinely unrepresentable idiom (multi-field AND-in-OR sub-groups
# are the documented example), raise this with a history line saying
# which rule and why — but check first that it is not another modifier
# or value silently going missing, because that is what it was last
# time.
MAX_STRUCTURAL_DRIFT = 0

# Categories that MUST stay at zero. ``emit_exception`` means the
# composer produced YAML pySigma rejects on re-parse — a hard
# correctness failure; we can't ship rules downstream tools won't
# accept. ``skipped_no_strict_rule`` is L1's territory (the load
# audit has its own zero-floor for ``exception``); we let it pass
# at any level since this test focuses on the emit half.
ZERO_EMIT_CATEGORIES = ("emit_exception",)


@pytest.fixture(scope="module")
def corpus_emit_audit() -> AuditResult:
    """Load corpus + run the L4 emit audit ONCE per test module.

    The audit walk is ~25 minutes across 3,708 rules. Module scoping
    is essential — without it, each of the three ratchet tests would
    re-run the full audit, blowing the slow suite out to ~75 minutes
    per CI run. With module scope, all three assertions read from a
    single audit pass.
    """
    corpus_path = data_path("sigmahq_corpus.json")
    rules = json.loads(corpus_path.read_text(encoding="utf-8"))
    assert isinstance(rules, list), f"corpus must be a JSON list, got {type(rules).__name__}"
    return audit_corpus_emits(rules)


@pytest.mark.slow
def test_emit_zero_categories_stay_at_zero(
    corpus_emit_audit: AuditResult,
) -> None:
    """No corpus rule may trip ``emit_exception``.

    The hard correctness gate. ``emit_exception`` means the composer
    produced YAML pySigma can't parse back — a downstream tool would
    reject the file we wrote. The L5 wave cleared this bucket via
    L5-B (windash modifier preservation) and L5-C (YAML 1.1 boolean
    quoting). Future regressions in the loader or serializer must
    fail this gate, not silently re-introduce broken output.

    On failure, dumps the top symptoms so the failing CI log shows
    which shape regressed.
    """
    counts = corpus_emit_audit["summary"]["category_counts"]
    by_symptom = corpus_emit_audit["summary"]["top_symptoms_per_category"]

    failures: list[str] = []
    for cat in ZERO_EMIT_CATEGORIES:
        n = counts.get(cat, 0)
        if n != 0:
            symptoms = by_symptom.get(cat, [])
            top = "\n".join(f"    [{c:>4d}] {s}" for s, c in symptoms[:5])
            failures.append(f"  {cat}: {n} (expected 0)\n{top}")

    assert not failures, "Emit-audit ratchet: zero-categories regressed.\n" + "\n".join(failures)


@pytest.mark.slow
def test_emit_clean_count_holds_floor(
    corpus_emit_audit: AuditResult,
) -> None:
    """The emit-clean-rule count may not drop below ``MIN_EMIT_CLEAN_COUNT``.

    A drop means a regression took rules that used to round-trip
    through composer → YAML → pySigma cleanly and broke them — by
    introducing a structural drift, by adding a new emit_exception,
    or by reclassifying a previously-clean rule as degraded.

    On improvement, this test still passes. The convention is to
    bump ``MIN_EMIT_CLEAN_COUNT`` in the same commit as the fix,
    which both locks in the new floor and documents the win in the
    constant's history comment above. A "soft floor lag" — a fix in
    flight that hasn't ratcheted the constant yet — is fine; the
    test only fails on actual regressions.
    """
    counts = corpus_emit_audit["summary"]["category_counts"]
    actual = counts.get("clean", 0)
    assert actual >= MIN_EMIT_CLEAN_COUNT, (
        f"Emit-audit ratchet: clean count regressed from floor.\n"
        f"  expected >= {MIN_EMIT_CLEAN_COUNT}\n"
        f"  actual    = {actual}\n"
        f"  delta     = {actual - MIN_EMIT_CLEAN_COUNT}\n"
        f"  full counts: {counts}"
    )


@pytest.mark.slow
def test_emit_floor_not_too_stale(
    corpus_emit_audit: AuditResult,
) -> None:
    """Soft check: ``MIN_EMIT_CLEAN_COUNT`` shouldn't lag actual by >100.

    Same shape as ``test_audit_floor_not_too_stale`` in the L3
    ratchet — catches PRs that improve the count but forget to bump
    the constant. Tolerance is 100 because work-in-progress branches
    can legitimately be ahead of the constant for a single commit;
    past that, the lag becomes obvious-and-actionable.
    """
    actual = corpus_emit_audit["summary"]["category_counts"].get("clean", 0)
    lag = actual - MIN_EMIT_CLEAN_COUNT
    assert lag <= 100, (
        f"Emit-audit ratchet: MIN_EMIT_CLEAN_COUNT is stale.\n"
        f"  constant: {MIN_EMIT_CLEAN_COUNT}\n"
        f"  actual:   {actual}\n"
        f"  lag:      +{lag} (tolerance: +100)\n"
        f"Bump MIN_EMIT_CLEAN_COUNT in "
        f"tests/test_corpus_emit_audit_ratchet.py to {actual} in your "
        f"next commit."
    )


@pytest.mark.slow
def test_structural_drift_holds_at_zero(
    corpus_emit_audit: AuditResult,
) -> None:
    """No rule may lose structure on the composer → YAML round trip.

    ``structural_drift`` means the re-emitted rule differs structurally
    from what was loaded: a block, item, value or modifier went missing
    without anything telling the user. It is the most dangerous category
    the emit audit has, because the rule still looks fine — it just
    means something else now.

    The module docstring described a floor for this from the beginning,
    but none was ever implemented, and four rules lived here as a
    result. They were not the "unrepresentable Sigma idiom" the
    docstring anticipated; they were a bug. ``web/load.py`` carried a
    hardcoded duplicate of ``ValueModifier`` that had fallen behind it,
    so ``Image|fieldref: ParentImage`` — "this process's image equals
    its own parent's" — loaded with the modifier stripped and became a
    literal string match on ``"ParentImage"``.

    If this fails, check for a dropped modifier or value before
    concluding it is an idiom we cannot represent.
    """
    counts = corpus_emit_audit["summary"]["category_counts"]
    actual = counts.get("structural_drift", 0)
    symptoms = corpus_emit_audit["summary"]["top_symptoms_per_category"].get("structural_drift", [])
    top = "\n".join(f"    [{c:>4d}] {s}" for s, c in symptoms[:5])
    assert actual <= MAX_STRUCTURAL_DRIFT, (
        f"Emit-audit ratchet: structural drift regressed.\n"
        f"  allowed = {MAX_STRUCTURAL_DRIFT}\n"
        f"  actual  = {actual}\n"
        f"{top}"
    )
