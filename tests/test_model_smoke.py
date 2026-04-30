"""Smoke tests for the core model and serializer.

These cover the v0 exit criteria:
  1. Instantiate a ``SigmaRule``.
  2. Serialize to YAML via ``serialize.to_yaml``.
  3. Parse the result back via ``serialize.from_yaml``.
  4. Round-trip preserves all fields.
  5. Re-serialization is byte-identical (the canonical round-trip guarantee).
"""

from __future__ import annotations

from intel2sigma.core.model import SigmaRule
from intel2sigma.core.serialize import from_yaml, to_yaml


def test_rule_instantiates(smoke_rule: SigmaRule) -> None:
    assert smoke_rule.title.startswith("Smoke rule")
    assert smoke_rule.logsource.product == "windows"
    assert len(smoke_rule.detections) == 2
    assert smoke_rule.detections[0].is_filter is False
    assert smoke_rule.detections[1].is_filter is True


def test_to_yaml_emits_canonical_key_order(smoke_rule: SigmaRule) -> None:
    text = to_yaml(smoke_rule)
    # Canonical ordering: title, id, status, description, ..., detection, falsepositives, level
    assert text.startswith("title:")
    ordered_keys = [
        "title:",
        "id:",
        "status:",
        "description:",
        "references:",
        "author:",
        "date:",
        "tags:",
        "logsource:",
        "detection:",
        "falsepositives:",
        "level:",
    ]
    last = -1
    for key in ordered_keys:
        idx = text.find(f"\n{key}") if last >= 0 else text.find(key)
        assert idx > last, f"{key!r} appears out of canonical order in:\n{text}"
        last = idx


def test_yaml_round_trip_preserves_all_fields(smoke_rule: SigmaRule) -> None:
    text = to_yaml(smoke_rule)
    parsed = from_yaml(text)

    assert parsed.title == smoke_rule.title
    assert parsed.id == smoke_rule.id
    assert parsed.status == smoke_rule.status
    assert parsed.description == smoke_rule.description
    assert parsed.references == smoke_rule.references
    assert parsed.author == smoke_rule.author
    assert parsed.date == smoke_rule.date
    assert parsed.modified == smoke_rule.modified
    assert parsed.tags == smoke_rule.tags
    assert parsed.logsource == smoke_rule.logsource
    assert parsed.falsepositives == smoke_rule.falsepositives
    assert parsed.level == smoke_rule.level

    assert len(parsed.detections) == len(smoke_rule.detections)
    for got, want in zip(parsed.detections, smoke_rule.detections, strict=True):
        assert got.name == want.name
        assert got.is_filter == want.is_filter
        assert len(got.items) == len(want.items)
        for got_item, want_item in zip(got.items, want.items, strict=True):
            assert got_item.field == want_item.field
            assert list(got_item.modifiers) == list(want_item.modifiers)
            assert list(got_item.values) == list(want_item.values)


def test_yaml_round_trip_is_byte_identical(smoke_rule: SigmaRule) -> None:
    first = to_yaml(smoke_rule)
    parsed = from_yaml(first)
    second = to_yaml(parsed)
    assert first == second, (
        "Canonical round-trip must be byte-identical.\n"
        f"--- first ---\n{first}\n--- second ---\n{second}"
    )


# ---------------------------------------------------------------------------
# Modifier emission — B2 regression
# ---------------------------------------------------------------------------


def test_emit_collapses_exact_modifier_to_bare_key() -> None:
    """``modifiers=["exact"]`` must emit as bare ``field: value``.

    B2 regression (filed during 0.3.0 testing). The Sigma spec has no
    ``|exact`` modifier — bare ``field: value`` IS exact match by
    definition. The composer surfaces "exactly matches" as a dropdown
    choice for UX clarity (per SPEC.md decision log, 2026-04-24), and
    the in-memory ``ValueModifier`` Literal accepts ``"exact"`` so
    catalogs can express ``default_modifier: exact`` naturally — but
    the canonical YAML must collapse to bare. Pre-fix the serializer
    emitted ``type|exact: SOCKADDR``, which downstream pySigma backends
    reject or convert inconsistently.
    """
    from datetime import date  # noqa: PLC0415
    from uuid import UUID  # noqa: PLC0415

    from intel2sigma.core.model import (  # noqa: PLC0415
        ConditionExpression,
        DetectionBlock,
        DetectionItem,
        LogSource,
        SigmaRule,
    )

    rule = SigmaRule(
        title="exact-modifier emission test",
        id=UUID("11111111-2222-3333-4444-555555555555"),
        date=date(2026, 4, 29),
        logsource=LogSource(product="linux", service="auditd"),
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    # User picked "exactly matches" in the dropdown.
                    DetectionItem(field="type", modifiers=["exact"], values=["SOCKADDR"]),
                ],
            ),
        ],
        condition=ConditionExpression(selection="match_1"),
    )
    yaml_text = to_yaml(rule)
    # Bare key — no |exact suffix.
    assert "type: SOCKADDR" in yaml_text
    assert "type|exact" not in yaml_text


def test_emit_preserves_other_modifiers_when_chained_with_exact() -> None:
    """Chains like ``["contains", "exact"]`` drop only the ``exact`` token.

    Edge case — a user could plausibly chain ``contains|exact`` via a
    multi-modifier widget (M1.4+ feature), or a loaded rule could
    carry such a chain. The exact-collapse must not nuke the rest of
    the chain; only the ``exact`` token itself is dropped.
    """
    from datetime import date  # noqa: PLC0415
    from uuid import UUID  # noqa: PLC0415

    from intel2sigma.core.model import (  # noqa: PLC0415
        ConditionExpression,
        DetectionBlock,
        DetectionItem,
        LogSource,
        SigmaRule,
    )

    rule = SigmaRule(
        title="chained-modifier test",
        id=UUID("66666666-7777-8888-9999-aaaaaaaaaaaa"),
        date=date(2026, 4, 29),
        logsource=LogSource(product="windows", category="process_creation"),
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(
                        field="CommandLine",
                        # contains AND exact in the chain — exact gets stripped,
                        # contains stays.
                        modifiers=["contains", "exact"],
                        values=["/c calc"],
                    ),
                ],
            ),
        ],
        condition=ConditionExpression(selection="match_1"),
    )
    yaml_text = to_yaml(rule)
    assert "CommandLine|contains: /c calc" in yaml_text
    assert "exact" not in yaml_text


def test_load_then_emit_normalizes_user_typed_pipe_exact() -> None:
    """A loaded rule with ``field|exact: x`` re-emits as bare ``field: x``.

    The asymmetry the L4 ROADMAP entry calls out — load preserves the
    user's lexical input (so the editor reflects what they wrote), emit
    normalizes to canonical Sigma (so downstream tools accept the
    output). Semantically identical; lexically different.
    """
    yaml_in = """
title: load-then-emit normalization
id: 22222222-3333-4444-5555-666666666666
status: experimental
date: 2026-04-29
logsource:
    product: linux
    service: auditd
detection:
    match_1:
        type|exact: SOCKADDR
    condition: match_1
level: medium
"""
    parsed = from_yaml(yaml_in)
    yaml_out = to_yaml(parsed)
    # The re-emitted YAML must use the canonical bare-key form.
    assert "type: SOCKADDR" in yaml_out
    assert "type|exact" not in yaml_out
