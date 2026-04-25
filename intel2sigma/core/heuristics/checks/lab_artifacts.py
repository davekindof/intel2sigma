"""Heuristics that detect researcher-lab leakage in detection values.

Sandboxes and analysis VMs leave fingerprints in IOCs: RFC1918
addresses, hostname patterns like ``DESKTOP-XXXX`` or ``WIN-XXXX``,
researcher usernames in paths. A rule that hard-codes one of these will
fire only inside the lab, not in production.

v1.0 ships the RFC1918 check. Hostname-pattern (h-022) and username-in-
path (h-020) follow in v1.7.
"""

from __future__ import annotations

import ipaddress

from intel2sigma.core.heuristics.base import HeuristicResult, register
from intel2sigma.core.model import SigmaRule

# Bound to a name so ruff 0.15.x doesn't strip the parens off the
# ``except (X, Y):`` form below — see web/mitre.py for the same workaround.
_PARSE_FAILURES = (ipaddress.AddressValueError, ValueError)


def _looks_like_rfc1918(value: str) -> bool:
    """True if ``value`` is or contains an obvious RFC1918 / link-local IP.

    Tolerates ``1.2.3.4:port`` and trims surrounding whitespace; skips
    anything that doesn't parse as an IPv4 address.
    """
    candidate = value.strip().split(":", 1)[0]
    try:
        addr = ipaddress.IPv4Address(candidate)
    except _PARSE_FAILURES:
        return False
    return addr.is_private or addr.is_link_local or addr.is_loopback


@register("h-021", category="lab_artifacts")
def rfc1918_value(rule: SigmaRule) -> HeuristicResult | None:
    """Detection value contains an RFC1918 / loopback / link-local IP.

    Fires for *match* blocks only — filter blocks legitimately list
    private ranges to exclude internal traffic.
    """
    for block in rule.detections:
        if block.is_filter:
            continue
        for item in block.items:
            for raw in item.values:
                if isinstance(raw, str) and _looks_like_rfc1918(raw):
                    return HeuristicResult(
                        heuristic_id="h-021",
                        message=(
                            f"Detection value {raw!r} looks like a private "
                            f"(RFC1918 / loopback / link-local) IP. These "
                            f"are nearly always lab leakage, not real C2."
                        ),
                        suggestion=(
                            "If you meant to *exclude* the private range, "
                            "move the value into a filter block. Otherwise "
                            "remove it — production attackers don't C2 to "
                            "10.x or 192.168.x."
                        ),
                        location=f"detections.{block.name}.{item.field}",
                    )
    return None


__all__ = ["rfc1918_value"]
