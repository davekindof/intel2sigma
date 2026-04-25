"""Heuristics for the metadata fields a shareable Sigma rule needs.

A rule that's technically valid but missing a usable title, a real
description, or any ATT&CK tags is harder for downstream consumers to
triage. These checks are conservative — short titles or empty
descriptions are common on hand-built rules and we don't want to
shower the user with low-signal warnings. The thresholds match the
SigmaHQ submission guidelines.
"""

from __future__ import annotations

from intel2sigma.core.heuristics.base import HeuristicResult, register
from intel2sigma.core.model import SigmaRule

# Title bounds. Below 10 chars almost always means a placeholder
# ("evil rule"); above 100 means the title is a paragraph and should be
# split between title + description.
_TITLE_MIN = 10
_TITLE_MAX = 100

# Description threshold. 30 chars is roughly "one short sentence" — below
# that the rule's purpose is genuinely unclear to a downstream reader.
_DESC_MIN = 30


@register("h-060", category="metadata_completeness")
def title_length_out_of_range(rule: SigmaRule) -> HeuristicResult | None:
    """Title is too short to convey intent or too long to scan."""
    title_len = len(rule.title.strip())
    if title_len == 0:
        # Tier 1 already requires a non-empty title; this case shouldn't
        # reach us, but be defensive.
        return None
    if _TITLE_MIN <= title_len <= _TITLE_MAX:
        return None
    if title_len < _TITLE_MIN:
        message = (
            f"Title is {title_len} characters — too short to convey the "
            f"rule's purpose to a downstream analyst."
        )
        suggestion = (
            "Aim for a one-line phrase (e.g. 'Encoded PowerShell from "
            "non-SYSTEM') of at least 10 characters."
        )
    else:
        message = (
            f"Title is {title_len} characters — too long to scan in a "
            f"detection-management UI. Consider moving detail to the "
            f"description."
        )
        suggestion = (
            "Keep the title under ~100 characters; put context, "
            "rationale, and references in the description field."
        )
    return HeuristicResult(
        heuristic_id="h-060",
        message=message,
        suggestion=suggestion,
        location="title",
    )


@register("h-061", category="metadata_completeness")
def description_too_short(rule: SigmaRule) -> HeuristicResult | None:
    """Description is empty or essentially empty."""
    desc_len = len(rule.description.strip())
    if desc_len >= _DESC_MIN:
        return None
    return HeuristicResult(
        heuristic_id="h-061",
        message=(
            f"Description is {desc_len} characters — anyone shipping this "
            f"rule downstream will struggle to triage what it's for."
        ),
        suggestion=(
            "Describe in one or two sentences what behaviour the rule "
            "detects and why it matters. Reference the technique or the "
            "advisory you're operationalising."
        ),
        location="description",
    )


@register("h-062", category="metadata_completeness")
def no_attack_tags(rule: SigmaRule) -> HeuristicResult | None:
    """Rule has no ``attack.*`` tags despite the picker existing.

    Fires when none of the rule's tags are MITRE ATT&CK references.
    Other tag namespaces (``tlp.*``, ``cve.*`` etc.) are fine; they just
    don't satisfy this check on their own.
    """
    if any(tag.startswith("attack.") for tag in rule.tags):
        return None
    return HeuristicResult(
        heuristic_id="h-062",
        message=(
            "Rule has no MITRE ATT&CK tags. Downstream consumers rely on "
            "ATT&CK tagging to map the rule to their detection coverage."
        ),
        suggestion=(
            "Open the ATT&CK picker on the metadata stage and add at "
            "least one tactic plus the relevant technique or "
            "sub-technique."
        ),
        location="tags",
    )


__all__ = [
    "description_too_short",
    "no_attack_tags",
    "title_length_out_of_range",
]
