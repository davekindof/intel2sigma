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
