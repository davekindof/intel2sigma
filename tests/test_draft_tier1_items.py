"""Tier-1 validation behaviour for item-level field/values combinations.

The composer adds blank rows for users to fill in. The first iteration
of tier-1 validation flagged every empty row as an error, which made
the preview pane scream warnings while the user was still typing.

Current behaviour:

* completely-empty item (no field, no values) → silently skipped, treated
  as an in-progress placeholder. ``can_advance_to_stage(2)`` still
  guards against advancing with ALL empty items.
* field set, values empty → ``DRAFT_ITEM_VALUES_MISSING``
* values set, field empty → ``DRAFT_ITEM_FIELD_MISSING``
* both populated → contributes to the strict :class:`SigmaRule`
"""

from __future__ import annotations

import json

from intel2sigma.core.model import DetectionItem
from intel2sigma.web.draft import RuleDraft


def _stage_with_items(items: list[dict[str, object]]) -> RuleDraft:
    """Build a Stage-1+ draft populated with the given detection items."""
    return RuleDraft.from_json(
        json.dumps(
            {
                "observation_id": "process_creation",
                "platform_id": "windows",
                "logsource": {
                    "category": "process_creation",
                    "product": "windows",
                    "service": None,
                },
                "detections": [
                    {
                        "name": "match_1",
                        "is_filter": False,
                        "combinator": "all_of",
                        "items": items,
                    }
                ],
                "match_combinator": "all_of",
                "stage": 1,
            }
        )
    )


def _codes(draft: RuleDraft) -> list[str]:
    result = draft.to_sigma_rule()
    if not isinstance(result, list):
        return []
    return [issue.code for issue in result]


def test_completely_empty_item_does_not_emit_validation_issue() -> None:
    """A blank row that the user hasn't started typing into is a placeholder,
    not a validation failure. We may still emit a "draft incomplete"
    issue from a different code path, but DRAFT_ITEM_FIELD_MISSING /
    VALUES_MISSING shouldn't fire just for an empty placeholder.
    """
    draft = _stage_with_items(
        [
            {
                "field": "Image",
                "modifiers": ["endswith"],
                "values": ["\\evil.exe"],
            },
            {"field": "", "modifiers": [], "values": []},
        ]
    )
    codes = _codes(draft)
    assert "DRAFT_ITEM_FIELD_MISSING" not in codes
    assert "DRAFT_ITEM_VALUES_MISSING" not in codes


def test_field_set_but_values_empty_still_flags_values_missing() -> None:
    """Half-filled rows still earn an issue — the user has expressed
    intent to use that field but hasn't supplied a value yet.
    """
    draft = _stage_with_items(
        [
            {"field": "Image", "modifiers": ["endswith"], "values": []},
        ]
    )
    assert "DRAFT_ITEM_VALUES_MISSING" in _codes(draft)


def test_empty_field_with_values_does_not_flag_field_missing() -> None:
    """Empty field + populated values is a Sigma keyword-search item.

    L2-P1b shipped support for Sigma's bare-list keyword idiom — a
    detection block whose value list lacks a field name fires when
    *any* event field contains any of the listed strings. SigmaHQ
    rules use this shape heavily in auditd / Zeek / network-traffic
    contexts (e.g. ``filter_keywords: [samr, lsarpc, winreg]``).

    Before P1b the strict ``DetectionItem.field`` had ``min_length=1``
    and tier-1 emitted DRAFT_ITEM_FIELD_MISSING for empty-field
    items, which broke 106+ corpus rules. The contract now: empty
    field + populated values is a keyword item, accepted at all
    layers; only whitespace-only field names ("   ") are typos and
    rejected.

    Composer UX implication: a user authoring a brand-new rule who
    leaves the field dropdown blank and types a value will now
    produce a keyword-search rule. That's almost certainly oversight
    rather than intent — but the surface for catching that lives in
    the UI hint, not the strict model.
    """
    draft = _stage_with_items(
        [
            {"field": "", "modifiers": [], "values": ["\\evil.exe"]},
        ]
    )
    # The keyword shape no longer trips FIELD_MISSING. Other tier-1
    # codes (DRAFT_TITLE_MISSING etc. from the bare-bones fixture)
    # may still fire — the assertion is specifically about the
    # item-level FIELD_MISSING regression we shipped P1b to fix.
    assert "DRAFT_ITEM_FIELD_MISSING" not in _codes(draft)


def test_strict_detection_item_accepts_keyword_shape() -> None:
    """The strict ``DetectionItem`` model accepts ``field=""`` directly.

    Companion to the tier-1 test above — exercises the model layer
    in isolation, no tier-1 / metadata interference. Confirms
    P1b's relaxed ``min_length=1`` constraint and the
    ``is_keyword`` property.
    """
    item = DetectionItem(field="", values=["\\evil.exe"])
    assert item.is_keyword is True
    assert item.field == ""
    assert item.values == ["\\evil.exe"]

    field_match = DetectionItem(field="Image", values=["\\evil.exe"])
    assert field_match.is_keyword is False


def test_completely_populated_item_yields_strict_rule_with_metadata() -> None:
    """Sanity: a fully populated item plus complete metadata round-trips
    cleanly to a strict SigmaRule, no validation issues.
    """
    draft = _stage_with_items(
        [
            {"field": "Image", "modifiers": ["endswith"], "values": ["\\evil.exe"]},
        ]
    )
    draft.title = "Test rule"
    draft.date = "2026-04-25"
    result = draft.to_sigma_rule()
    assert not isinstance(result, list), f"Expected strict rule, got issues: {result}"


def test_one_populated_one_empty_item_is_valid() -> None:
    """The reproduction case for Bug 5: a rule with one good item plus an
    extra blank row should validate as if the blank row didn't exist.
    Blank rows are placeholders, not errors.
    """
    draft = _stage_with_items(
        [
            {"field": "Image", "modifiers": ["endswith"], "values": ["\\evil.exe"]},
            {"field": "", "modifiers": [], "values": []},
        ]
    )
    draft.title = "Test rule"
    draft.date = "2026-04-25"
    result = draft.to_sigma_rule()
    assert not isinstance(result, list), (
        f"A populated item + a blank placeholder should validate; got {result}"
    )


def test_whitespace_value_is_preserved_not_stripped() -> None:
    """An item with a literal whitespace value passes validation.

    Sigma rules legitimately use whitespace as meaningful values:
    ``CommandLine|endswith: ' '`` is the macOS masquerading-via-
    trailing-space pattern at SigmaHQ rule b6e2a2e3-… The earlier
    behaviour treated whitespace-only values as missing, silently
    nuking the user's literal value. The L1 corpus audit (e9a040b)
    found 55+ rules failing this way. Now we accept any non-zero-
    length string as a value; only TRULY empty (``""``) values are
    flagged as missing.
    """
    draft = _stage_with_items(
        [
            {"field": "CommandLine", "modifiers": ["endswith"], "values": [" "]},
        ]
    )
    assert "DRAFT_ITEM_VALUES_MISSING" not in _codes(draft)


def test_empty_string_value_is_still_treated_as_missing() -> None:
    """A truly empty value (length-0 string) still trips DRAFT_ITEM_VALUES_MISSING.

    The companion to the test above: we relaxed whitespace-as-empty
    but kept zero-length-as-empty. An item with field set and
    ``values=[""]`` is a half-completed row the user is in the
    middle of editing — flag it so the composer doesn't ship a
    rule with an empty match condition.
    """
    draft = _stage_with_items(
        [
            {"field": "Image", "modifiers": ["endswith"], "values": [""]},
        ]
    )
    assert "DRAFT_ITEM_VALUES_MISSING" in _codes(draft)
