"""Heuristics that flag rules with no behavioural context.

A rule that matches *only* on hashes / IPs / domains is brittle: any
indicator rotation by the actor invalidates the entire rule. Pairing
indicators with behaviour (process name, command line shape, file
operation) is what makes detections survive.

Three checks share the field-classification tables below:

* ``h-001`` — ``warn``  — every match block is IOC-only (the catch-all)
* ``h-002`` — ``info``  — a single match block is hash-only
* ``h-003`` — ``info``  — every match block is *network*-IOC-only
                          (suggests building a sibling process rule)

The three deliberately overlap on the worst case (a fully-hash rule
fires both h-001 and h-002) — that's intentional, the messages address
different fixes (add behaviour vs. consider whether the hash block adds
value at all).
"""

from __future__ import annotations

from intel2sigma.core.heuristics.base import HeuristicResult, register
from intel2sigma.core.model import SigmaRule

# Hash-typed indicator fields. Used by h-001 (as part of the global
# indicator set) and h-002 (as the standalone trigger).
_HASH_FIELDS: frozenset[str] = frozenset(
    {
        "Hashes",
        "MD5",
        "md5",
        "SHA1",
        "sha1",
        "SHA256",
        "sha256",
        "Imphash",
        "imphash",
    }
)

# Network-endpoint indicator fields. Used by h-001 and h-003.
_NETWORK_INDICATOR_FIELDS: frozenset[str] = frozenset(
    {
        "DestinationIp",
        "dst_ip",
        "DstIp",
        "DestinationHostname",
        "dst_host",
        "QueryName",
        "query",
        "SourceIp",
        "src_ip",
    }
)

# Fields whose values are pure indicators (no behavioural signal).
# Matched against DetectionItem.field, both Sigma-canonical names
# (PascalCase) and common SIEM-mapped lowercase variants. Authenticode
# signature fields are indicators too — they identify a specific cert,
# not a behaviour.
_INDICATOR_FIELDS: frozenset[str] = (
    _HASH_FIELDS | _NETWORK_INDICATOR_FIELDS | frozenset({"Signature", "SignatureStatus"})
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


@register("h-002", category="ioc_vs_behavior")
def hash_only_block(rule: SigmaRule) -> HeuristicResult | None:
    """A match block contains only hash fields.

    Even when the rule has other behavioural blocks, a hash-only block
    is brittle in isolation — any sample variant invalidates it. The
    info-level nudge asks the user to either add a behavioural item to
    the same block or accept that the block is exact-match-only and
    plan accordingly.

    Distinct from h-001 (which fires only when *every* match block is
    IOC-only) — h-002 fires per-block, including in mixed rules where
    h-001 would not fire.
    """
    for block in rule.detections:
        if block.is_filter or not block.items:
            continue
        if all(item.field in _HASH_FIELDS for item in block.items):
            return HeuristicResult(
                heuristic_id="h-002",
                message=(
                    f"Match block '{block.name}' contains only hash fields. "
                    "Hashes are the easiest indicator type for an actor to "
                    "rotate; this block alone won't fire on the next sample."
                ),
                suggestion=(
                    "Add an Image / CommandLine / OriginalFileName item to "
                    "this block, or pair the block with a behavioural one "
                    "via condition logic."
                ),
                location=f"detections.{block.name}",
            )
    return None


@register("h-003", category="ioc_vs_behavior")
def network_indicator_only_rule(rule: SigmaRule) -> HeuristicResult | None:
    """The rule matches only on network indicators (IPs / domains).

    A pure network-IOC rule will catch the C2 traffic but tells you
    nothing about the binary that originated it. The info-level nudge
    suggests building a sibling rule on ``process_creation`` /
    ``image_load`` so the same campaign is caught at both layers.

    Distinct from h-001: h-001 includes hash and signature fields in the
    "indicator" set, so a hash-and-IP rule fires h-001 but not h-003.
    h-003 is specifically the "all-network-no-process" pattern.
    """
    match_blocks = [b for b in rule.detections if not b.is_filter]
    if not match_blocks:
        return None
    saw_any = False
    for block in match_blocks:
        for item in block.items:
            saw_any = True
            if item.field not in _NETWORK_INDICATOR_FIELDS:
                return None
    if not saw_any:
        return None
    return HeuristicResult(
        heuristic_id="h-003",
        message=(
            "Every match in this rule is a network indicator (IP or "
            "domain). You'll catch the C2 traffic but nothing tells you "
            "what binary originated the connection."
        ),
        suggestion=(
            "Build a sibling rule on process_creation / image_load that "
            "detects the malware initiating these connections — running "
            "both rules together gives you the actor at both layers."
        ),
    )


__all__ = ["hash_only_block", "ioc_only_rule", "network_indicator_only_rule"]
