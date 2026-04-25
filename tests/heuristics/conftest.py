"""Shared fixtures for heuristic tests.

The ``benign_rule`` fixture is a fully-formed, advisory-free rule:
metadata complete, behavioural detection, ATT&CK tags, no lab
artifacts, no path-specificity issues, condition references defined
selections. Each test pair takes the benign baseline and mutates one
field to verify both the fire and the no-fire path of a single
heuristic.
"""

from __future__ import annotations

from datetime import date as _date
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
def benign_rule() -> SigmaRule:
    """A rule that fires zero of the v1.0 MVP heuristics.

    Useful as the "no-fire" baseline that test pairs mutate. Keep this
    rule clean of lab artifacts, tag-less metadata, short titles, etc.
    Adding a new heuristic to the MVP set may require updating this
    fixture so it remains advisory-free.
    """
    return SigmaRule(
        title="Encoded PowerShell from non-SYSTEM context",
        id=UUID("12345678-1234-5678-1234-567812345678"),
        description=(
            "Detects encoded PowerShell command lines launched from non-"
            "SYSTEM accounts; common in initial-access loaders."
        ),
        author="intel2sigma tests",
        date=_date(2026, 4, 25),
        tags=["attack.execution", "attack.t1059.001"],
        logsource=LogSource(product="windows", category="process_creation"),
        detections=[
            DetectionBlock(
                name="match_1",
                is_filter=False,
                items=[
                    DetectionItem(
                        field="Image",
                        modifiers=["endswith"],
                        values=["\\powershell.exe"],
                    ),
                    DetectionItem(
                        field="CommandLine",
                        modifiers=["contains"],
                        values=["-encodedcommand"],
                    ),
                ],
            ),
            DetectionBlock(
                name="filter_1",
                is_filter=True,
                items=[
                    DetectionItem(
                        field="User",
                        modifiers=["contains"],
                        values=["SYSTEM"],
                    ),
                ],
            ),
        ],
        condition=ConditionExpression(
            op=ConditionOp.AND,
            children=[
                ConditionExpression(selection="match_1"),
                ConditionExpression(
                    op=ConditionOp.NOT,
                    children=[ConditionExpression(selection="filter_1")],
                ),
            ],
        ),
        falsepositives=["Administrative scripts"],
        level="high",
    )
