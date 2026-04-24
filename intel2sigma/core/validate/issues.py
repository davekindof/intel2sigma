"""Structured validation issue model shared by tier-1 and tier-2.

An empty ``list[ValidationIssue]`` from a validator means the rule passed that
tier. The model is intentionally small; tier-3 (advisory) will live alongside
and can emit the same shape with a different ``severity``.

Per CLAUDE.md, errors are typed. Consumers can branch on ``code`` for
programmatic handling (e.g., surface a specific fix-it button in the web UI)
and still fall back to ``message`` for free-text display.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ValidationTier = Literal[1, 2]


class ValidationIssue(BaseModel):
    """One validation problem.

    ``location`` is a dotted path into the rule model where the issue lives,
    e.g. ``detections[0].items[2]`` or ``condition``. Optional — some issues
    (unknown logsource, malformed top-level metadata) don't map cleanly to a
    single sub-path.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    tier: ValidationTier
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    location: str | None = None
