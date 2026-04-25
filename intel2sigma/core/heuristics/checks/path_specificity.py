"""Heuristics about path-shaped values being too specific to one host.

The classic case: ``C:\\Users\\jdoe\\AppData\\Roaming\\evil.exe`` — works
on the analyst's lab box, fails everywhere else. Wildcarding the user
profile segment (``C:\\Users\\*\\AppData\\…``) preserves the detection
intent without binding it to one machine.

v1.0 ships the user-profile-without-wildcard check. Drive-letter
hardcoding (h-032), ProgramFiles arch wildcarding (h-031), and env-var
suggestions (h-033) follow in v1.7.
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


__all__ = ["user_profile_without_wildcard"]
