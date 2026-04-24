"""Tiered validation.

Tier 1 and tier 2 are blocking; tier 3 (SigmaHQ conventions, advisory) will
live alongside when v1 ships. Callers typically invoke tiers in order and
stop at the first one that returns a non-empty issue list, since tier 2's
output is less informative when the rule has structural problems tier 1
would have caught.
"""

from intel2sigma.core.validate.issues import ValidationIssue, ValidationTier
from intel2sigma.core.validate.tier1 import validate_tier1
from intel2sigma.core.validate.tier2 import validate_tier2

__all__ = [
    "ValidationIssue",
    "ValidationTier",
    "validate_tier1",
    "validate_tier2",
]
