"""Tests for the IOC-vs-behavior category (h-001)."""

from __future__ import annotations

from intel2sigma.core.heuristics.checks.ioc_vs_behavior import ioc_only_rule
from intel2sigma.core.model import DetectionBlock, DetectionItem, SigmaRule


def test_h001_fires_when_only_indicator_fields_present(benign_rule: SigmaRule) -> None:
    """A rule whose match blocks only reference Hashes/IPs/domains fires h-001."""
    ioc_only = benign_rule.model_copy(
        update={
            "detections": [
                DetectionBlock(
                    name="match_1",
                    is_filter=False,
                    items=[
                        DetectionItem(
                            field="sha256",
                            values=["a" * 64, "b" * 64],
                        ),
                        DetectionItem(
                            field="DestinationIp",
                            values=["8.8.8.8"],
                        ),
                    ],
                ),
            ],
        }
    )
    result = ioc_only_rule(ioc_only)
    assert result is not None
    assert result.heuristic_id == "h-001"
    assert "indicators" in result.message.lower()


def test_h001_does_not_fire_with_behavioural_field(benign_rule: SigmaRule) -> None:
    """The benign baseline (Image + CommandLine) is the canonical no-fire case."""
    assert ioc_only_rule(benign_rule) is None
