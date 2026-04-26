"""Heuristics that flag selections likely to match too much.

Three angles:

* ``h-010`` — *structural*: a single-item match block on a high-cardinality
  field with no other detection logic. Even if the value is specific, the
  rule has no exclusionary context.
* ``h-011`` — *lexical*: the sole value is a famous-utility keyword
  (``powershell``, ``cmd``, ``rundll32`` etc.). Almost always overbroad
  without additional differentiation.
* ``h-012`` — *short-suffix*: ``Image|endswith`` with a value under 5
  characters matches an enormous swath of filenames (e.g. ``.exe`` alone).

These three deliberately overlap: a rule of
``CommandLine|contains: powershell`` and nothing else fires h-010 *and*
h-011, with two different suggestions. That's by design — the lenses
catch related-but-distinct anti-patterns.
"""

from __future__ import annotations

from intel2sigma.core.heuristics.base import HeuristicResult, register
from intel2sigma.core.model import SigmaRule

# Fields whose value space is large enough that a substring match alone
# is rarely specific enough. Frequency-derived from the SigmaHQ corpus —
# these are the four fields that account for ~80% of overbroad rules in
# the corpus's ``rules-emerging-threats`` stratum.
_HIGH_CARDINALITY_FIELDS: frozenset[str] = frozenset(
    {
        "CommandLine",
        "Image",
        "ParentImage",
        "ParentCommandLine",
    }
)

# Modifiers that produce substring matches (as opposed to exact / regex).
# A high-card field with one of these modifiers is the h-010 trigger.
_SUBSTRING_MODIFIERS: frozenset[str] = frozenset({"contains", "startswith", "endswith"})

# Famous-utility keywords. A match block whose only condition is one of
# these (case-insensitive substring) is almost certainly overbroad —
# admin scripts, SCCM jobs, MDT, monitoring tools all hit these strings
# in normal operation. Curated by hand from the SigmaHQ false-positives
# corpus; expand quarterly per docs/recalibration.md.
_COMMON_PROCESS_KEYWORDS: frozenset[str] = frozenset(
    {
        "powershell",
        "cmd",
        "cmd.exe",
        "rundll32",
        "rundll32.exe",
        "regsvr32",
        "regsvr32.exe",
        "wmic",
        "wmic.exe",
        "schtasks",
        "schtasks.exe",
        "net.exe",
        "net1.exe",
        "mshta",
        "mshta.exe",
    }
)

# Length floor for ``Image|endswith`` values, leading backslash excluded.
# A value of "\\py" (3 chars after the backslash) catches both
# ``python.exe`` and ``Mercury.py`` — clearly overbroad. Five characters
# is the corpus-derived threshold below which fire rate exceeds ~90% of
# the time on a benign rule sweep.
_MIN_IMAGE_ENDSWITH_LENGTH: int = 5


@register("h-010", category="overbroad_selection")
def single_high_cardinality_match(rule: SigmaRule) -> HeuristicResult | None:
    """Sole detection logic is one substring item on a high-cardinality field.

    Fires when:

    * exactly one match block,
    * which contains exactly one item,
    * the item's field is in :data:`_HIGH_CARDINALITY_FIELDS`,
    * the item uses a substring-style modifier.

    With no second item and no filter blocks, the rule has no
    differentiating context. The fix is usually adding an item (User,
    ParentImage) or a filter block excluding common admin tooling.
    """
    match_blocks = [b for b in rule.detections if not b.is_filter]
    if len(match_blocks) != 1:
        return None
    block = match_blocks[0]
    if len(block.items) != 1:
        return None
    item = block.items[0]
    if item.field not in _HIGH_CARDINALITY_FIELDS:
        return None
    if not item.modifiers or item.modifiers[0] not in _SUBSTRING_MODIFIERS:
        return None
    return HeuristicResult(
        heuristic_id="h-010",
        message=(
            f"This rule's only match is a substring check on "
            f"{item.field!r}. High-cardinality fields like this need a "
            "second condition (User, ParentImage, integrity level) or "
            "the rule fires on too much benign activity."
        ),
        suggestion=(
            "Add a second item to this block, or pair it with a filter "
            "block that excludes common admin / SCCM / monitoring tools."
        ),
        location=f"detections.{block.name}",
    )


@register("h-011", category="overbroad_selection")
def single_common_keyword(rule: SigmaRule) -> HeuristicResult | None:
    """Sole detection value is a famous-utility name.

    A rule whose only match item carries a value like ``powershell`` or
    ``rundll32`` (case-insensitive substring) is overbroad in practice —
    these utilities run constantly in normal operation. Distinct from
    h-010: a rule of ``CommandLine|contains: powershell`` fires both
    h-010 (single substring on a high-card field) and h-011 (the value
    is a common keyword), with different suggestions.
    """
    match_blocks = [b for b in rule.detections if not b.is_filter]
    if len(match_blocks) != 1:
        return None
    block = match_blocks[0]
    if len(block.items) != 1:
        return None
    item = block.items[0]
    if not item.values:
        return None
    # ``DetectionItem.values`` is ``list[str | int | bool]`` — only string
    # values can match a keyword list, ints/bools obviously can't. The
    # str() is a safety net in case a future model change loosens the type;
    # today a non-string value just means "not a keyword", so the rule
    # legitimately doesn't fire.
    values_lower = [str(v).strip().lower() for v in item.values]
    if not all(v in _COMMON_PROCESS_KEYWORDS for v in values_lower):
        return None
    matched = ", ".join(sorted(set(values_lower)))
    return HeuristicResult(
        heuristic_id="h-011",
        message=(
            f"The only match value is a common utility name "
            f"({matched}). These run in normal operation — the rule "
            "will be loud unless paired with a more specific signal."
        ),
        suggestion=(
            "Add a distinguishing item — encoded-command flag, parent "
            "process, IntegrityLevel, or a script-path pattern — that "
            "separates malicious use from administrative use."
        ),
        location=f"detections.{block.name}",
    )


@register("h-012", category="overbroad_selection")
def short_image_endswith(rule: SigmaRule) -> HeuristicResult | None:
    """``Image|endswith`` value under 5 characters catches too many filenames.

    Sigma's path-suffix idiom is ``\\malware.exe`` — the leading
    backslash anchors to a filename boundary. The leading backslash is
    not counted toward the length floor, but a value like ``\\py.exe``
    is short enough that it'd match both ``python.exe`` and
    ``XPython.exe`` (the ``X`` ahead of ``py`` makes the suffix match
    happy). Fires per offending item; checks every match block.
    """
    for block in rule.detections:
        if block.is_filter:
            continue
        for item in block.items:
            if item.field != "Image":
                continue
            if not item.modifiers or item.modifiers[0] != "endswith":
                continue
            for value in item.values:
                # Image|endswith of an int/bool is meaningless and tier-1
                # would normally reject it, but DetectionItem.values is
                # typed permissively to accommodate other (field, type)
                # combinations. Cast defensively rather than narrow the
                # model.
                stripped = str(value).lstrip("\\")
                if 0 < len(stripped) < _MIN_IMAGE_ENDSWITH_LENGTH:
                    return HeuristicResult(
                        heuristic_id="h-012",
                        message=(
                            f"Image|endswith value {value!r} is too "
                            "short. Suffixes under 5 characters match "
                            "many unrelated executables."
                        ),
                        suggestion=(
                            "Use the full filename (e.g. \\powershell.exe "
                            "instead of \\ll.exe), or switch to a regex "
                            "anchored to a path component."
                        ),
                        location=f"detections.{block.name}",
                    )
    return None


__all__ = [
    "short_image_endswith",
    "single_common_keyword",
    "single_high_cardinality_match",
]
