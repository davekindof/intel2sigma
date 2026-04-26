"""Heuristics that detect researcher-lab leakage in detection values.

Sandboxes and analysis VMs leave fingerprints in IOCs: RFC1918
addresses, hostname patterns like ``DESKTOP-XXXX`` or ``WIN-XXXX``,
researcher usernames in paths. A rule that hard-codes one of these will
fire only inside the lab, not in production.

v1.0 shipped the RFC1918 check (h-021). v1.7 adds the sandbox-hostname
check (h-022). The username-in-path check (h-020) is still queued.

These checks are particularly important for sandbox-driven rule
generation (the v1.1 CAPE / Triage parsers): a rule auto-derived from a
sandbox report will *naturally* embed the analysis VM's hostname in any
field that captures it. The heuristic catches that before the user
ships the rule.
"""

from __future__ import annotations

import ipaddress
import re

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


# Hostname / computer-name fields that a sandbox VM commonly bleeds into.
# Match against ``DetectionItem.field`` exactly (no fuzz) so unrelated
# fields named "host" in cloud schemas don't trip on private IP literals.
_HOSTNAME_FIELDS: frozenset[str] = frozenset(
    {
        "Hostname",
        "hostname",
        "Computer",
        "ComputerName",
        "computer_name",
        "host",
        "Host",
        "src_host",
        "SourceHostname",
    }
)

# Famous sandbox / VM hostname patterns. Drawn from:
#   * Windows 10 OOBE default: ``DESKTOP-XXXXXXXX`` (8 alphanumeric).
#   * Windows Server default: ``WIN-XXXXXXXXXXX`` (11 alphanumeric).
#   * Common analysis platforms: cuckoo, joe-sandbox, cape, any.run, hybrid.
#   * VM-vendor prefixes: vmware, vbox / virtualbox, hyper-v.
#   * Generic researcher pseudonyms: sandbox, analysis, malware, lab.
#
# Pattern is anchored with ``\b`` so a value like ``mycuckoo-server`` that
# happens to contain "cuckoo" still fires (false-positive cost low,
# false-negative cost high — sandboxes auto-name and don't always strip
# the vendor token).
_SANDBOX_HOSTNAME_PATTERN = re.compile(
    r"\b("
    r"DESKTOP-[A-Z0-9]{6,8}"
    r"|WIN-[A-Z0-9]{8,11}"
    r"|SANDBOX[-_]?\w*"
    r"|ANALYSIS[-_]?\w*"
    r"|MALWARE[-_]?\w*"
    r"|CUCKOO[-_]?\w*"
    r"|JOE[-_]?SANDBOX"
    r"|CAPE[-_]?\w*"
    r"|ANYRUN|HYBRID[-_]?ANALYSIS"
    r"|VMWARE[-_]?\w*|VBOX[-_]?\w*|VIRTUAL[-_]?BOX"
    r"|HYPERV[-_]?\w*"
    r"|LAB[-_]?\w+"
    r")\b",
    re.IGNORECASE,
)


@register("h-022", category="lab_artifacts")
def sandbox_hostname_value(rule: SigmaRule) -> HeuristicResult | None:
    """Detection value matches a known sandbox / VM hostname pattern.

    Only fires on hostname-shaped fields (``Hostname``, ``Computer``,
    ``ComputerName``, etc.) and only on match blocks. Filter blocks that
    legitimately exclude the org's hypervisor host names are not flagged.

    Particularly important for sandbox-derived rules — a CAPE or Triage
    report will surface the sandbox VM's hostname in any field that
    captures host context, and without this check the user would ship a
    rule that fires only inside the analysis VM.
    """
    for block in rule.detections:
        if block.is_filter:
            continue
        for item in block.items:
            if item.field not in _HOSTNAME_FIELDS:
                continue
            for raw in item.values:
                if not isinstance(raw, str):
                    continue
                m = _SANDBOX_HOSTNAME_PATTERN.search(raw)
                if m is None:
                    continue
                return HeuristicResult(
                    heuristic_id="h-022",
                    message=(
                        f"Hostname value {raw!r} matches a sandbox / VM "
                        f"naming pattern ({m.group(0)!r}). This rule will "
                        f"fire inside your analysis VM and almost nowhere "
                        f"in production."
                    ),
                    suggestion=(
                        "Remove the hostname from the match — the rule "
                        "should describe behaviour, not which machine ran "
                        "the sample. If you genuinely want a host filter, "
                        "move it to a filter block excluding *your* lab."
                    ),
                    location=f"detections.{block.name}.{item.field}",
                )
    return None


__all__ = ["rfc1918_value", "sandbox_hostname_value"]
