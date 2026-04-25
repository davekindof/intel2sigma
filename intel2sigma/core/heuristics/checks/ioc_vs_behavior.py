"""Heuristics that flag rules with no behavioural context.

A rule that matches *only* on hashes / IPs / domains is brittle: any
indicator rotation by the actor invalidates the entire rule. Pairing
indicators with behaviour (process name, command line shape, file
operation) is what makes detections survive.
"""

from __future__ import annotations

from intel2sigma.core.heuristics.base import HeuristicResult, register
from intel2sigma.core.model import SigmaRule

# Fields whose values are pure indicators (no behavioural signal).
# Matched against DetectionItem.field, both Sigma-canonical names
# (PascalCase) and common SIEM-mapped lowercase variants.
_INDICATOR_FIELDS: frozenset[str] = frozenset(
    {
        # Hashes
        "Hashes",
        "MD5",
        "md5",
        "SHA1",
        "sha1",
        "SHA256",
        "sha256",
        "Imphash",
        "imphash",
        # Network endpoints
        "DestinationIp",
        "dst_ip",
        "DstIp",
        "DestinationHostname",
        "dst_host",
        "QueryName",
        "query",
        "SourceIp",
        "src_ip",
        # Authenticode-style indicators
        "Signature",
        "SignatureStatus",
    }
)


@register("h-001", category="ioc_vs_behavior")
def ioc_only_rule(rule: SigmaRule) -> HeuristicResult | None:
    """Rule contains only IOC-type values with no behavioral context.

    Fires when every match block (filters excluded) lists only fields in
    :data:`_INDICATOR_FIELDS`. The IOC paste-and-classify flow can produce
    these naturally — pasting just hashes builds an all-Hashes rule —
    and the suggestion nudges the user to add a process/command-line/path
    block before shipping.
    """
    match_blocks = [b for b in rule.detections if not b.is_filter]
    if not match_blocks:
        # Nothing to evaluate; tier-1 already requires at least one match.
        return None
    saw_any_field = False
    for block in match_blocks:
        for item in block.items:
            saw_any_field = True
            if item.field not in _INDICATOR_FIELDS:
                return None
    if not saw_any_field:
        return None
    return HeuristicResult(
        heuristic_id="h-001",
        message=(
            "This rule matches only on indicators (hashes, IPs, domains). "
            "It will stop working as soon as the actor rotates them."
        ),
        suggestion=(
            "Add a behavioural selection block — process image, command-line "
            "fragment, or file-operation pattern — alongside the indicators."
        ),
    )


__all__ = ["ioc_only_rule"]
