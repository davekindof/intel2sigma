"""Tier-2 validation — pySigma acceptance of the canonical YAML.

After tier 1 passes, the rule is serialized to canonical Sigma YAML via
:func:`intel2sigma.core.serialize.to_yaml` and passed through pySigma's own
parser. Anything pySigma rejects surfaces here as a structured
:class:`ValidationIssue` so the web UI can render a specific error message
next to the offending field.

Tier 2 runs only after tier 1 returns an empty list — a rule that has
structural model problems isn't worth feeding to pySigma, and pySigma's
error messages are less specific than our own tier-1 messages.
"""

from __future__ import annotations

from sigma.exceptions import (
    SigmaConditionError,
    SigmaDetectionError,
    SigmaError,
    SigmaLogsourceError,
    SigmaModifierError,
    SigmaValueError,
)
from sigma.rule import SigmaRule as PySigmaRule

from intel2sigma.core.model import SigmaRule
from intel2sigma.core.serialize import to_yaml
from intel2sigma.core.validate.issues import ValidationIssue

# Error codes. The subdivision mirrors pySigma's own exception hierarchy so
# consumers can branch on condition vs. detection vs. modifier issues without
# parsing the free-text message.
CODE_PYSIGMA_CONDITION = "T2_PYSIGMA_CONDITION"
CODE_PYSIGMA_DETECTION = "T2_PYSIGMA_DETECTION"
CODE_PYSIGMA_MODIFIER = "T2_PYSIGMA_MODIFIER"
CODE_PYSIGMA_LOGSOURCE = "T2_PYSIGMA_LOGSOURCE"
CODE_PYSIGMA_VALUE = "T2_PYSIGMA_VALUE"
CODE_PYSIGMA_OTHER = "T2_PYSIGMA_OTHER"


def validate_tier2(rule: SigmaRule) -> list[ValidationIssue]:  # noqa: PLR0911 (one return per pySigma exception class is clearer than a dispatch table)
    """Serialize ``rule`` to canonical YAML and check pySigma accepts it.

    Returns a list of :class:`ValidationIssue` (empty = passes). pySigma
    exceptions are translated into structured issues with stable codes.
    """
    try:
        yaml_text = to_yaml(rule)
    except (ValueError, TypeError) as exc:
        # Serialization itself failed — the in-memory rule is malformed in a
        # way tier 1 should have caught. Surface as a tier-2 issue anyway so
        # the user isn't left with a silent failure.
        return [
            ValidationIssue(
                tier=2,
                code=CODE_PYSIGMA_OTHER,
                message=f"Serialization failed before pySigma: {exc}",
            )
        ]

    try:
        PySigmaRule.from_yaml(yaml_text)
    except SigmaConditionError as exc:
        return [_issue(CODE_PYSIGMA_CONDITION, exc, "condition")]
    except SigmaDetectionError as exc:
        return [_issue(CODE_PYSIGMA_DETECTION, exc, "detection")]
    except SigmaModifierError as exc:
        return [_issue(CODE_PYSIGMA_MODIFIER, exc)]
    except SigmaLogsourceError as exc:
        return [_issue(CODE_PYSIGMA_LOGSOURCE, exc, "logsource")]
    except SigmaValueError as exc:
        return [_issue(CODE_PYSIGMA_VALUE, exc)]
    except SigmaError as exc:
        return [_issue(CODE_PYSIGMA_OTHER, exc)]

    return []


def _issue(code: str, exc: Exception, location: str | None = None) -> ValidationIssue:
    return ValidationIssue(
        tier=2,
        code=code,
        message=f"pySigma rejected the rule: {exc}",
        location=location,
    )


__all__ = [
    "CODE_PYSIGMA_CONDITION",
    "CODE_PYSIGMA_DETECTION",
    "CODE_PYSIGMA_LOGSOURCE",
    "CODE_PYSIGMA_MODIFIER",
    "CODE_PYSIGMA_OTHER",
    "CODE_PYSIGMA_VALUE",
    "validate_tier2",
]
