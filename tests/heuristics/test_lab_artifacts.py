"""Tests for the lab-artifacts category (h-021)."""

from __future__ import annotations

from intel2sigma.core.heuristics.checks.lab_artifacts import rfc1918_value
from intel2sigma.core.model import DetectionBlock, DetectionItem, SigmaRule


def test_h021_fires_on_rfc1918_value_in_match_block(benign_rule: SigmaRule) -> None:
    """A match block with a 192.168.x value fires h-021."""
    leaky = benign_rule.model_copy(
        update={
            "detections": [
                *benign_rule.detections,
                DetectionBlock(
                    name="match_2",
                    is_filter=False,
                    items=[
                        DetectionItem(
                            field="DestinationIp",
                            values=["192.168.0.42:8080"],
                        ),
                    ],
                ),
            ],
        }
    )
    result = rfc1918_value(leaky)
    assert result is not None
    assert result.heuristic_id == "h-021"
    assert "192.168" in result.message


def test_h021_does_not_fire_on_rfc1918_in_filter_block(benign_rule: SigmaRule) -> None:
    """RFC1918 in a filter block is a legitimate exclude — must not fire."""
    excluded = benign_rule.model_copy(
        update={
            "detections": [
                *benign_rule.detections,
                DetectionBlock(
                    name="filter_internal",
                    is_filter=True,
                    items=[
                        DetectionItem(
                            field="DestinationIp",
                            values=["10.0.0.0/8"],
                        ),
                    ],
                ),
            ],
        }
    )
    assert rfc1918_value(excluded) is None
