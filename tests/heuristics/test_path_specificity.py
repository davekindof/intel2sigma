"""Tests for the path-specificity category (h-030)."""

from __future__ import annotations

from intel2sigma.core.heuristics.checks.path_specificity import (
    user_profile_without_wildcard,
)
from intel2sigma.core.model import DetectionBlock, DetectionItem, SigmaRule


def test_h030_fires_on_hardcoded_username(benign_rule: SigmaRule) -> None:
    """``C:\\Users\\jdoe\\AppData\\…`` triggers h-030."""
    hardcoded = benign_rule.model_copy(
        update={
            "detections": [
                DetectionBlock(
                    name="match_path",
                    is_filter=False,
                    items=[
                        DetectionItem(
                            field="TargetFilename",
                            values=[r"C:\Users\jdoe\AppData\Roaming\evil.exe"],
                        ),
                    ],
                ),
            ],
        }
    )
    result = user_profile_without_wildcard(hardcoded)
    assert result is not None
    assert result.heuristic_id == "h-030"
    assert "jdoe" in result.message


def test_h030_does_not_fire_on_wildcarded_path(benign_rule: SigmaRule) -> None:
    """``C:\\Users\\*\\AppData\\…`` is the recommended form — no advisory."""
    wildcarded = benign_rule.model_copy(
        update={
            "detections": [
                DetectionBlock(
                    name="match_path",
                    is_filter=False,
                    items=[
                        DetectionItem(
                            field="TargetFilename",
                            values=[r"C:\Users\*\AppData\Roaming\evil.exe"],
                        ),
                    ],
                ),
            ],
        }
    )
    assert user_profile_without_wildcard(wildcarded) is None
