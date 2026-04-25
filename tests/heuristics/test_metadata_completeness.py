"""Tests for the metadata-completeness category (h-060, h-061, h-062)."""

from __future__ import annotations

from intel2sigma.core.heuristics.checks.metadata_completeness import (
    description_too_short,
    no_attack_tags,
    title_length_out_of_range,
)
from intel2sigma.core.model import SigmaRule

# ---------------------------------------------------------------------------
# h-060 — title length out of range
# ---------------------------------------------------------------------------


def test_h060_fires_on_too_short_title(benign_rule: SigmaRule) -> None:
    """A 5-character title is well below the 10-char minimum."""
    stub = benign_rule.model_copy(update={"title": "evil"})
    result = title_length_out_of_range(stub)
    assert result is not None
    assert result.heuristic_id == "h-060"
    assert "too short" in result.message.lower()


def test_h060_does_not_fire_on_in_range_title(benign_rule: SigmaRule) -> None:
    """The benign baseline title is ~40 chars — comfortably in range."""
    assert title_length_out_of_range(benign_rule) is None


# ---------------------------------------------------------------------------
# h-061 — description too short
# ---------------------------------------------------------------------------


def test_h061_fires_on_empty_description(benign_rule: SigmaRule) -> None:
    """An empty description fires h-061."""
    blanked = benign_rule.model_copy(update={"description": ""})
    result = description_too_short(blanked)
    assert result is not None
    assert result.heuristic_id == "h-061"


def test_h061_does_not_fire_on_full_description(benign_rule: SigmaRule) -> None:
    """The benign baseline has a full sentence — no advisory."""
    assert description_too_short(benign_rule) is None


# ---------------------------------------------------------------------------
# h-062 — no ATT&CK tags
# ---------------------------------------------------------------------------


def test_h062_fires_when_no_attack_tags(benign_rule: SigmaRule) -> None:
    """Strip the attack.* tags → h-062 fires."""
    untagged = benign_rule.model_copy(
        update={"tags": [t for t in benign_rule.tags if not t.startswith("attack.")]},
    )
    result = no_attack_tags(untagged)
    assert result is not None
    assert result.heuristic_id == "h-062"


def test_h062_does_not_fire_with_attack_tags(benign_rule: SigmaRule) -> None:
    """The benign baseline carries attack.* tags — clean."""
    assert no_attack_tags(benign_rule) is None
