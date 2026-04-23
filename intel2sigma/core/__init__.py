"""Core rule engine: model, serialization, validation, conversion, heuristics.

This package MUST NOT import from ``intel2sigma.web`` or ``intel2sigma.cli``.
See CLAUDE.md invariant I-7.
"""

from intel2sigma.core.model import (
    ConditionExpression,
    DetectionBlock,
    DetectionItem,
    LogSource,
    SigmaRule,
)

__all__ = [
    "ConditionExpression",
    "DetectionBlock",
    "DetectionItem",
    "LogSource",
    "SigmaRule",
]
