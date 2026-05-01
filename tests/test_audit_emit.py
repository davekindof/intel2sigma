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
        f"windash modifier dropped on round-trip: {rec['category']} ({rec.get('symptom', '')})"
    )


def test_yaml11_boolean_literal_value_round_trips_through_emit() -> None:
    """``CommandLine|contains|all: [recoveryenabled, 'no']`` round-trips.

    L4-surfaced regression. The literal string ``"no"`` is a YAML 1.1
    boolean (``False``) but a plain scalar string in YAML 1.2. Ruamel
    (our emit) uses 1.2 and emits ``- no`` unquoted; PyYAML (pySigma
    by default) uses 1.1 and parses ``- no`` as ``False``, then
    pySigma rejects with ``SigmaTypeError: Modifier
    SigmaContainsModifier incompatible to value type of 'False'``.

    SigmaHQ rule 1444443e-… ("Boot Configuration Tampering Via
    Bcdedit.EXE") was the surfaced instance — bcdedit's
    ``recoveryenabled no`` flag matches as a string, but our emit
    silently turned it into a boolean.

    L5-C fix: the serializer wraps any string matching a YAML 1.1
    boolean literal in ``SingleQuotedScalarString`` to force quoted
    emission. Other YAML 1.1 booleans (yes / on / off / y / n /
    case variants) are caught by the same set.
    """
    yaml_text = """
title: yaml-1.1 bool round-trip
id: 77777777-8888-9999-aaaa-bbbbbbbbbbbb
status: experimental
date: 2026-04-30
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|contains|all:
              - 'recoveryenabled'
              - 'no'
    condition: selection
level: high
"""
    rec = categorise_emit_rule(_rule(yaml_text))
    assert rec["category"] in {"clean", "degraded"}, (
        f"YAML 1.1 boolean string regressed: {rec['category']} ({rec.get('symptom', '')})"
    )


def test_regex_modifier_value_round_trips_through_emit() -> None:
    r"""``Field|re: '\?d=[0-9]+\.[0-9]+'`` round-trips bit-for-bit.

    L4-surfaced regression. ``str(SigmaString)`` doubles backslashes
    around pySigma's wildcard metacharacters (``?``, ``*``) so the
    resulting string round-trips through pySigma's own parser. But
    when that double-escaped string is emitted as YAML and re-parsed,
    pySigma escapes AGAIN — every emit→re-parse cycle multiplies the
    backslashes, drifting the regex value.

    SigmaHQ rule 0066d244-… ("Potential CVE-2023-36884 Exploitation
    Pattern") was the canonical instance — ``c-uri|re: '\?d=[0-9]
    {1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'`` (an IP-address
    pattern). After one round-trip the value drifted from 1 backslash
    before ``?`` to 2; another round-trip would have made it 3.

    L5-D fix: the loader uses ``SigmaString.original`` (the user's
    literal input as it appeared in source YAML) instead of
    ``str(v)`` (pySigma's escape-doubled form). Re-emit puts that
    literal back into YAML; re-parse produces an equivalent
    SigmaString with the same ``.original``.

    Affects all rules using ``|re``, ``|contains``, ``|startswith``,
    ``|endswith`` with values containing literal ``?`` / ``*`` /
    ``\\`` characters — ~48 corpus rules surfaced by L4.
    """
    yaml_text = r"""
title: regex round-trip
id: 99999999-aaaa-bbbb-cccc-dddddddddddd
status: experimental
date: 2026-04-30
logsource:
    category: proxy
detection:
    selection:
        c-uri|re: '\?d=[0-9]{1,3}\.[0-9]{1,3}'
    condition: selection
level: medium
"""
    rec = categorise_emit_rule(_rule(yaml_text))
    assert rec["category"] == "clean", (
        f"Regex value drifted on round-trip: {rec['category']} ({rec.get('symptom', '')[:200]})"
    )


def test_keyword_block_with_all_modifier_round_trips() -> None:
    """``keywords: { '|all': [a, b, c] }`` round-trips with the modifier.

    L4-surfaced regression. Sigma's keyword-search shape supports
    optional modifier-only keys: ``'|all'`` requires ALL of the
    listed strings in the same event (vs the default any-of
    semantics of a bare-list keyword block). Pre-L5-E the serializer's
    pure-keyword branch flattened EVERY keyword block to a bare list
    regardless of the items' modifier chain — silently changing
    any-of-of-all to plain any-of and breaking the rule's meaning.

    SigmaHQ rule 0506a799-… ("PwnKit Local Privilege Escalation")
    was the canonical instance: matches when ALL three strings
    (``pkexec``, the XAUTHORITY environment-variable warning, the
    USER=root TTY indicator) appear in the same auth-log line.
    Pre-fix re-emit dropped ``|all``, making the rule fire on any
    of the three — wildly more false positives.

    L5-E fix: the keyword-block emission groups items by their
    (exact-collapsed) modifier chain. All-empty → bare list (the
    canonical idiom). Single non-empty chain → ``'|mod1|mod2':
    [values]`` mapping form. Mixed chains → multi-key mapping.

    L4 found 16+ rules with this shape — all PwnKit-style
    ``|all``-keyword detections plus a handful of less-common
    ``|contains``-keyword shapes.
    """
    yaml_text = """
title: keyword-with-all round-trip
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
status: experimental
date: 2026-04-30
logsource:
    product: linux
    service: auth
detection:
    keywords:
        '|all':
            - 'pkexec'
            - 'The value for environment variable XAUTHORITY contains suspicious content'
            - '[USER=root]'
    condition: keywords
level: high
"""
    rec = categorise_emit_rule(_rule(yaml_text))
    assert rec["category"] == "clean", (
        f"|all keyword block regressed: {rec['category']} ({rec.get('symptom', '')[:200]})"
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
