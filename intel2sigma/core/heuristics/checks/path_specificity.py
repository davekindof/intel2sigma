"""Heuristics about path-shaped values being too specific to one host.

The classic case: ``C:\\Users\\jdoe\\AppData\\Roaming\\evil.exe`` — works
on the analyst's lab box, fails everywhere else. Wildcarding the user
profile segment (``C:\\Users\\*\\AppData\\…``) preserves the detection
intent without binding it to one machine.

v1.0 shipped the user-profile-without-wildcard check (h-030). v1.7
adds drive-letter hardcoding (h-032). ProgramFiles arch wildcarding
(h-031) and env-var suggestions (h-033) are still queued for a later
pass.
"""

from __future__ import annotations

import re

from intel2sigma.core.heuristics.base import HeuristicResult, register
from intel2sigma.core.model import SigmaRule

# Matches ``C:\Users\<not-wildcard>\…`` — case-insensitive on the drive
# letter and the ``Users`` segment, since Sigma values are typically not
# case-sensitive on Windows path components. The negative character
# class for the username segment rejects ``*`` (already wildcarded) and
# ``%`` (env-var form, also acceptable).
_USER_PROFILE_NO_WILDCARD = re.compile(
    r"[A-Za-z]:\\Users\\[^\\*%]+\\",
    re.IGNORECASE,
)


@register("h-030", category="path_specificity")
def user_profile_without_wildcard(rule: SigmaRule) -> HeuristicResult | None:
    """Path value uses ``C:\\Users\\<name>\\…`` instead of ``C:\\Users\\*\\…``.

    Fires only on match blocks; filter blocks listing specific users
    (``C:\\Users\\Administrator\\``) are common for legitimate excludes.
    """
    for block in rule.detections:
        if block.is_filter:
            continue
        for item in block.items:
            for raw in item.values:
                if not isinstance(raw, str):
                    continue
                if _USER_PROFILE_NO_WILDCARD.search(raw):
                    return HeuristicResult(
                        heuristic_id="h-030",
                        message=(
                            f"Path {raw!r} hardcodes a specific user profile. "
                            f"This rule will only match on systems where "
                            f"that exact username exists."
                        ),
                        suggestion=(
                            "Replace the username segment with a wildcard: "
                            "``C:\\Users\\*\\AppData\\…``. The ``*`` matches "
                            "any user — preserves intent, gains portability."
                        ),
                        location=f"detections.{block.name}.{item.field}",
                    )
    return None


# Hardcoded non-C: drive letter at the start of a path. ``C:\…`` is the
# overwhelming default for Windows; rules referencing ``D:\``, ``E:\``,
# etc. are usually capturing where the sample happened to land in the
# analyst's lab. Anchored to a path-segment start (^ or after a quote /
# space) so a CommandLine like ``cmd /C dir D:\share`` doesn't match
# accidentally.
_NON_C_DRIVE = re.compile(
    r"(?:^|[\s\"'=])([D-Zd-z]):\\",
)


@register("h-032", category="path_specificity")
def non_c_drive_hardcoded(rule: SigmaRule) -> HeuristicResult | None:
    """A path value starts with a drive letter other than ``C:``.

    Most Windows installs put the OS, profiles, and Program Files on
    ``C:``. A rule referencing ``D:\\…``, ``E:\\…``, etc. is almost
    always overfit to the lab (the analyst's secondary disk, the
    sandbox's mapped share). Filter blocks are exempt because legitimate
    excludes do reference specific non-C: paths (``D:\\Backups\\``).
    """
    for block in rule.detections:
        if block.is_filter:
            continue
        for item in block.items:
            for raw in item.values:
                if not isinstance(raw, str):
                    continue
                m = _NON_C_DRIVE.search(raw)
                if m is None:
                    continue
                drive = m.group(1).upper()
                return HeuristicResult(
                    heuristic_id="h-032",
                    message=(
                        f"Path {raw!r} hardcodes drive letter {drive}:. "
                        "Almost all production Windows installs put "
                        "everything on C:; a non-C: drive is usually a "
                        "lab secondary disk."
                    ),
                    suggestion=(
                        "Drop the drive letter (let the path match any "
                        "drive), or replace with a wildcard segment if "
                        "the rule depends on a particular relative "
                        "structure."
                    ),
                    location=f"detections.{block.name}.{item.field}",
                )
    return None


__all__ = ["non_c_drive_hardcoded", "user_profile_without_wildcard"]
