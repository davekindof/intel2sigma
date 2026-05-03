"""Smoke tests for the L8 state-fidelity audit framework.

Three tests:

* The framework runs end-to-end on a fully-clean rule: every
  applicable dimension reports PASS, ``all_passed`` is True.
* The screenshot-bug dimension (``observation_id_populated``)
  correctly identifies the service-only-logsource failure mode.
* The corpus-walk rollup (``audit_corpus_fidelity``) returns a
  per-dimension count summary matching the input.

Per-dimension comprehensive testing happens in lockstep with the
L8-B fix commits — each "fix dimension X" commit adds the
fixture-based tests that pin the contract for X.
"""

from __future__ import annotations

from intel2sigma._fidelity import (
    FIDELITY_DIMENSIONS,
    Status,
    audit_corpus_fidelity,
    check_fidelity,
)

_CLEAN_RULE = {
    "id": "12345678-1234-5678-1234-567812345678",
    "title": "fully-clean fixture",
    "raw_yaml": """
title: fully-clean fixture
id: 12345678-1234-5678-1234-567812345678
status: experimental
description: A fixture that should pass every applicable fidelity dimension.
references:
    - https://example.invalid/ref
author: tests
date: 2026-05-02
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection
falsepositives:
    - Administrative scripts
level: high
""",
}


_SERVICE_ONLY_RULE = {
    "id": "4c198a60-7d05-4daf-8bf7-4136fb6f5c62",
    "title": "service-only logsource (screenshot-bug fixture)",
    "raw_yaml": """
title: service-only logsource (screenshot-bug fixture)
id: 4c198a60-7d05-4daf-8bf7-4136fb6f5c62
status: test
date: 2024-02-20
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4663
        ObjectType: File
    condition: selection
level: high
""",
}


def test_clean_rule_passes_every_applicable_dimension() -> None:
    """Sanity: a fixture chosen to exercise every dimension reports
    PASS or N/A for all of them, never FAIL.

    This is the framework's "happy path" — if it fails, the
    framework itself has a bug, not the rule.
    """
    report = check_fidelity(_CLEAN_RULE)
    failures = [
        (name, r.detail) for name, r in report.dimensions.items() if r.status is Status.FAIL
    ]
    assert not failures, f"Clean fixture has unexpected drift: {failures}"
    assert report.all_passed


def test_service_only_logsource_flags_observation_id_populated() -> None:
    """The screenshot-bug fixture trips the routing dimension.

    A rule with ``logsource: { product: windows, service: security }``
    (no category) currently leaves ``observation_id=""`` in the draft.
    The ``observation_id_populated`` dimension must flag this as
    FAIL — that's the L8-A discovery surface.

    Other dimensions (logsource_category being N/A, logsource_product
    pass, logsource_service pass, etc.) should be reported as
    expected. This test pins the dimension's behaviour against the
    canonical instance of the bug.
    """
    report = check_fidelity(_SERVICE_ONLY_RULE)
    populated = report.dimensions["observation_id_populated"]
    assert populated.status is Status.FAIL, (
        f"Expected FAIL on observation_id_populated for service-only "
        f"logsource; got {populated.status} ({populated.detail})"
    )
    # Sanity: logsource fields preserved (those dimensions PASS) —
    # the routing failure is independent of logsource preservation.
    assert report.dimensions["logsource_product"].status is Status.PASS
    assert report.dimensions["logsource_service"].status is Status.PASS
    assert report.dimensions["logsource_category"].status is Status.NA


def test_audit_corpus_fidelity_rollup_matches_inputs() -> None:
    """The corpus rollup correctly sums per-dimension counts.

    Walks 2 rules: the clean fixture and the service-only fixture.
    For each dimension, expects:
      - clean fixture contributes one of {pass, n/a}
      - service-only fixture contributes the appropriate result
    """
    summary = audit_corpus_fidelity([_CLEAN_RULE, _SERVICE_ONLY_RULE])

    assert summary["total_rules"] == 2

    # observation_id_populated: clean fixture passes (process_creation
    # is catalogued); service-only fixture fails. So per-dim should
    # be pass=1, fail=1.
    obs_id = summary["per_dimension"]["observation_id_populated"]
    assert obs_id["pass"] == 1
    assert obs_id["fail"] == 1

    # title preservation: both should pass.
    assert summary["per_dimension"]["title"]["pass"] == 2
    assert summary["per_dimension"]["title"]["fail"] == 0

    # tags: clean fixture has tags (1 pass), service-only doesn't
    # (1 n/a).
    tags = summary["per_dimension"]["tags"]
    assert tags["pass"] == 1
    assert tags["n/a"] == 1

    # Fail examples: should include the service-only id under
    # observation_id_populated.
    examples = summary["fail_examples"]["observation_id_populated"]
    assert any(ex["rule_id"] == _SERVICE_ONLY_RULE["id"] for ex in examples)


def test_description_trailing_whitespace_does_not_count_as_drift() -> None:
    """L8-B-1 contract: trailing/leading whitespace in description
    is normalization, not drift.

    L8-A discovery flagged 955 rules failing this dimension on the
    same artifact: source has ``"text\\n"`` (literal block YAML
    scalar's implicit trailing newline), loaded has ``"text"``
    because ``RuleDraft.str_strip_whitespace=True`` calls ``.strip()``
    on every assignment. The user's intent is the description text;
    the trailing newline is a YAML emit artifact.

    The contract is captured here:

    * trailing newline → PASS (audit-side normalization)
    * leading whitespace → PASS
    * internal whitespace → still compared verbatim, drift IS drift

    The third bullet is the safety property — we're not papering
    over real differences, just the edge-whitespace artifact.
    """
    rule = {
        "id": "12345678-1234-5678-1234-567812345678",
        "title": "trailing-newline fixture",
        "raw_yaml": """
title: trailing-newline fixture
id: 12345678-1234-5678-1234-567812345678
status: experimental
description: |
    A literal block scalar leaves a trailing newline in
    pySigma's output. The loaded draft strips it. Audit
    must treat that as PASS.
date: 2026-05-02
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection
level: high
""",
    }
    report = check_fidelity(rule)
    desc = report.dimensions["description"]
    assert desc.status is Status.PASS, (
        f"Expected PASS on trailing-newline-only difference; got {desc.status} ({desc.detail})"
    )


def test_description_internal_whitespace_difference_still_drifts() -> None:
    """Sanity: the L8-B-1 normalization doesn't paper over real drift.

    A description that genuinely differs in internal content (more
    than just edge whitespace) MUST still report FAIL. Otherwise
    the dimension is useless — every difference looks like a
    "normalization" mismatch and we'd never catch real corruption.

    Verified by directly checking the dimension function with hand-
    constructed source/loaded values; this avoids needing a fixture
    where the loader actually corrupts the description (which
    would itself be a bug to fix).
    """
    from intel2sigma._fidelity import _check_description  # noqa: PLC0415

    class _FakePy:
        description = "Detects suspicious activity in real life."

    class _FakeDraft:
        description = "Detects suspicious activity in REAL LIFE."  # different case mid-string

    result = _check_description(_FakePy(), _FakeDraft())  # type: ignore[arg-type]
    assert result.status is Status.FAIL, (
        f"Expected FAIL on real internal difference; got {result.status} ({result.detail})"
    )


def test_dimension_catalogue_is_non_empty_and_grouped() -> None:
    """Sanity: the catalogue is populated and dimensions have valid
    metadata (name, group, description, callable check).

    Catches mistakes where a new dimension is added without all the
    required fields, OR where the catalogue accidentally becomes
    empty during a refactor.
    """
    assert len(FIDELITY_DIMENSIONS) >= 10, (
        "FIDELITY_DIMENSIONS shrunk unexpectedly — check the catalogue"
    )
    for dim in FIDELITY_DIMENSIONS:
        assert dim.name, f"Dimension has empty name: {dim}"
        assert dim.group, f"Dimension {dim.name!r} has empty group"
        assert dim.description, f"Dimension {dim.name!r} has empty description"
        assert callable(dim.check), f"Dimension {dim.name!r}'s check is not callable"
    # Names must be unique.
    names = [d.name for d in FIDELITY_DIMENSIONS]
    assert len(set(names)) == len(names), f"Duplicate dimension names: {names}"
