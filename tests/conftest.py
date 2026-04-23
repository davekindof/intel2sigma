"""Shared test fixtures."""

from __future__ import annotations

from datetime import date
from uuid import UUID

import pytest

from intel2sigma.core.model import (
    ConditionExpression,
    ConditionOp,
    DetectionBlock,
    DetectionItem,
    LogSource,
    SigmaRule,
)


@pytest.fixture
def smoke_rule() -> SigmaRule:
    """A trivial but complete rule used by the smoke tests.

    Chosen so that every emission path is exercised:
      - metadata fields non-empty
      - both a match and a filter block
      - modifier chain on one detection item
      - multi-value list on another
      - ATT&CK-style tags
    """
    match_block = DetectionBlock(
        name="match_1",
        is_filter=False,
        items=[
            DetectionItem(
                field="Image",
                modifiers=["endswith"],
                values=["\\evil.exe"],
            ),
            DetectionItem(
                field="CommandLine",
                modifiers=["contains", "all"],
                values=["-encodedcommand", "-nop"],
            ),
        ],
    )
    filter_block = DetectionBlock(
        name="filter_1",
        is_filter=True,
        items=[
            DetectionItem(
                field="User",
                modifiers=["contains"],
                values=["SYSTEM"],
            ),
        ],
    )
    condition = ConditionExpression(
        op=ConditionOp.AND,
        children=[
            ConditionExpression(selection="match_1"),
            ConditionExpression(
                op=ConditionOp.NOT,
                children=[ConditionExpression(selection="filter_1")],
            ),
        ],
    )
    return SigmaRule(
        title="Smoke rule: encoded PowerShell from evil.exe",
        id=UUID("12345678-1234-5678-1234-567812345678"),
        status="experimental",
        description="A minimal rule used by the intel2sigma round-trip smoke tests.",
        references=["https://example.invalid/ref"],
        author="intel2sigma tests",
        date=date(2026, 4, 23),
        tags=["attack.execution", "attack.t1059.001"],
        logsource=LogSource(product="windows", category="process_creation"),
        detections=[match_block, filter_block],
        condition=condition,
        falsepositives=["Administrative scripts"],
        level="high",
    )
