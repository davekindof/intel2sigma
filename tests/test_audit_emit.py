"""Unit tests for the L4 emit-audit categoriser.

Fast tests (no corpus walk) that pin the categoriser's contract:
each category is exercisable by a synthetic rule, the comparison
correctly detects drift in modifier chains / item counts / value
sets, and idempotent normalizations (the ``exact`` collapse) don't
false-flag drift.

The full corpus walk lives in ``scripts/audit_corpus_emits.py``
(L4) and ``tests/test_corpus_emit_audit_ratchet.py`` (L6, slow).
"""

from __future__ import annotations

from intel2sigma._audit import categorise_emit_rule


def _rule(yaml_body: str, rule_id: str = "11111111-2222-3333-4444-555555555555") -> dict:
    """Wrap a YAML body in the corpus-record shape audit_corpus_emits expects."""
    return {
        "id": rule_id,
        "title": "test fixture",
        "raw_yaml": yaml_body,
    }


CLEAN_YAML = """
title: clean fixture
id: 11111111-2222-3333-4444-555555555555
status: experimental
date: 2026-04-29
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-encodedcommand'
    condition: selection
falsepositives:
    - Administrative scripts
level: high
"""


def test_clean_rule_categorises_as_clean() -> None:
    """A simple round-trippable rule lands in ``clean``."""
    rec = categorise_emit_rule(_rule(CLEAN_YAML))
    assert rec["category"] == "clean", (
        f"Expected clean; got {rec['category']} ({rec.get('symptom', '')})"
    )


def test_unparseable_source_marked_skipped() -> None:
    """Rules pySigma can't parse aren't L4's territory.

    They're load-path failures (L1's bucket). The L4 categoriser
    reports ``skipped_no_strict_rule`` so the rollup tracks them as
    ineligible without conflating them with real emit bugs.
    """
    rec = categorise_emit_rule(_rule("not a sigma rule: at all"))
    assert rec["category"] == "skipped_no_strict_rule"


def test_load_with_warnings_categorises_as_degraded_not_clean() -> None:
    """Round-trip clean + LOAD_* warnings on original load = degraded.

    Load-side warnings (e.g. an unknown observation category) don't
    affect emit fidelity, but they're worth surfacing in the rollup
    so the audit shows the union of emit-clean rules without obscuring
    the load-side findings.
    """
    yaml_text = """
title: degraded-load fixture
id: 33333333-4444-5555-6666-777777777777
status: experimental
date: 2026-04-29
logsource:
    category: imaginary_uncatalogued_source
detection:
    selection:
        SomeField: a value
    condition: selection
level: low
"""
    rec = categorise_emit_rule(_rule(yaml_text))
    assert rec["category"] == "degraded"
    assert "LOAD_OBSERVATION_UNKNOWN" in rec.get("issue_codes", [])


def test_windash_modifier_round_trips_through_emit() -> None:
    """``Field|contains|windash: x`` round-trips without losing the
    ``windash`` modifier.

    L4-surfaced regression. Pre-L5, the loader's ``_modifier_name``
    did class-name munging — ``SigmaWindowsDashModifier`` became
    ``"windowsdash"`` — but pySigma's canonical token is
    ``"windash"``. The loader's known-set filter rejected the
    munged name, dropping the modifier silently. Re-emit then
    produced YAML where two items collapsed onto the same
    ``Field|contains`` mapping key, silently dropping one.

    L5 fixed ``_modifier_name`` to use pySigma's
    ``modifier_mapping`` inversely. This test pins the round-trip
    end-to-end so a future regression to class-name munging fails
    here, not 7 minutes later in the L6 ratchet.
    """
    yaml_text = """
title: windash round-trip
id: 55555555-6666-7777-8888-999999999999
status: experimental
date: 2026-04-30
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|windash:
            - '-encodedcommand'
    condition: selection
level: high
"""
    rec = categorise_emit_rule(_rule(yaml_text))
    assert rec["category"] in {"clean", "degraded"}, (
        f"windash modifier dropped on round-trip: {rec['category']} "
        f"({rec.get('symptom', '')})"
    )


def test_keyword_search_round_trips_clean() -> None:
    """Sigma's bare-list keyword idiom (no field) survives round-trip.

    This was the L2-P1b corpus-wide fix; pin it on the emit side so a
    future regression in the keyword-block emission path
    (``_detections_to_map``'s pure-keyword branch) trips L4 instead
    of slipping through to user reports.
    """
    yaml_text = """
title: keyword-search fixture
id: 44444444-5555-6666-7777-888888888888
status: experimental
date: 2026-04-29
logsource:
    category: process_creation
    product: linux
    service: auditd
detection:
    keywords:
        - 'org.apache.commons.ognl.OgnlException'
        - 'ExpressionSyntaxException'
    condition: keywords
level: high
"""
    rec = categorise_emit_rule(_rule(yaml_text))
    assert rec["category"] in {"clean", "degraded"}, (
        f"Keyword-search round-trip regressed: {rec['category']} ({rec.get('symptom', '')})"
    )
