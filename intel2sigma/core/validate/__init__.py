"""Tiered validation.

Tier 1 and tier 2 are blocking; tier 3 is advisory and runs the heuristic
catalog over a complete rule. Callers typically invoke tiers 1 and 2 in
order and stop at the first one that returns a non-empty issue list,
since tier 2's output is less informative when the rule has structural
problems tier 1 would have caught. Tier 3 only runs once tier 1 + 2 are
clean — there's no point heuristically reviewing a rule that doesn't
parse.
"""

from intel2sigma.core.validate.issues import ValidationIssue, ValidationTier
from intel2sigma.core.validate.tier1 import validate_tier1
from intel2sigma.core.validate.tier2 import validate_tier2
from intel2sigma.core.validate.tier3 import validate_tier3

__all__ = [
    "ValidationIssue",
    "ValidationTier",
    "validate_tier1",
    "validate_tier2",
    "validate_tier3",
]
