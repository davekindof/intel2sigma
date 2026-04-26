"""Tests for the lab-artifacts category (h-021, h-022)."""

from __future__ import annotations

from intel2sigma.core.heuristics.checks.lab_artifacts import (
    rfc1918_value,
    sandbox_hostname_value,
)
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


# --- h-022: sandbox hostname patterns -----------------------------------------


def test_h022_fires_on_desktop_pattern(benign_rule: SigmaRule) -> None:
    """A Hostname value of `DESKTOP-AB12CD34` fires h-022."""
    leaky = benign_rule.model_copy(
        update={
            "detections": [
                *benign_rule.detections,
                DetectionBlock(
                    name="match_host",
                    is_filter=False,
                    items=[
                        DetectionItem(
                            field="Hostname",
                            values=["DESKTOP-AB12CD34"],
                        ),
                    ],
                ),
            ],
        }
    )
    result = sandbox_hostname_value(leaky)
    assert result is not None
    assert result.heuristic_id == "h-022"
    assert "DESKTOP-AB12CD34" in result.message


def test_h022_does_not_fire_on_real_hostname(benign_rule: SigmaRule) -> None:
    """A regular corporate hostname like `CORP-PRODSRV01` must not fire."""
    real = benign_rule.model_copy(
        update={
            "detections": [
                *benign_rule.detections,
                DetectionBlock(
                    name="match_host",
                    is_filter=False,
                    items=[
                        DetectionItem(
                            field="Hostname",
                            values=["CORP-PRODSRV01"],
                        ),
                    ],
                ),
            ],
        }
    )
    assert sandbox_hostname_value(real) is None
