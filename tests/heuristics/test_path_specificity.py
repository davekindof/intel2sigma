"""Tests for the path-specificity category (h-030, h-032)."""

from __future__ import annotations

from intel2sigma.core.heuristics.checks.path_specificity import (
    non_c_drive_hardcoded,
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


# --- h-032: non-C: drive hardcoded -------------------------------------------


def test_h032_fires_on_d_drive_value(benign_rule: SigmaRule) -> None:
    """A path starting with ``D:\\`` fires h-032."""
    d_drive = benign_rule.model_copy(
        update={
            "detections": [
                DetectionBlock(
                    name="match_path",
                    is_filter=False,
                    items=[
                        DetectionItem(
                            field="TargetFilename",
                            values=[r"D:\sandbox\samples\evil.exe"],
                        ),
                    ],
                ),
            ],
        }
    )
    result = non_c_drive_hardcoded(d_drive)
    assert result is not None
    assert result.heuristic_id == "h-032"
    assert "D" in result.message  # the drive letter


def test_h032_does_not_fire_on_c_drive(benign_rule: SigmaRule) -> None:
    """A regular ``C:\\`` path is the canonical case — must not fire."""
    c_drive = benign_rule.model_copy(
        update={
            "detections": [
                DetectionBlock(
                    name="match_path",
                    is_filter=False,
                    items=[
                        DetectionItem(
                            field="TargetFilename",
                            values=[r"C:\Windows\Temp\evil.exe"],
                        ),
                    ],
                ),
            ],
        }
    )
    assert non_c_drive_hardcoded(c_drive) is None
