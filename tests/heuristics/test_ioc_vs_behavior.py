"""Tests for the IOC-vs-behavior category (h-001, h-002, h-003)."""

from __future__ import annotations

from intel2sigma.core.heuristics.checks.ioc_vs_behavior import (
    hash_only_block,
    ioc_only_rule,
    network_indicator_only_rule,
)
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


# --- h-002: hash-only block --------------------------------------------------


def test_h002_fires_on_hash_only_block_in_mixed_rule(benign_rule: SigmaRule) -> None:
    """A rule with a hash-only block fires h-002 even when other blocks are behavioural.

    This is the value-add of h-002 over h-001 — h-001 wouldn't fire here
    because the rule has behavioural blocks too, but the hash block
    itself is still brittle in isolation.
    """
    mixed = benign_rule.model_copy(
        update={
            "detections": [
                # The benign behavioural block stays.
                benign_rule.detections[0],
                # New hash-only block alongside.
                DetectionBlock(
                    name="hashes",
                    is_filter=False,
                    items=[
                        DetectionItem(field="sha256", values=["a" * 64]),
                        DetectionItem(field="MD5", values=["b" * 32]),
                    ],
                ),
                benign_rule.detections[1],  # the SYSTEM filter
            ],
        }
    )
    result = hash_only_block(mixed)
    assert result is not None
    assert result.heuristic_id == "h-002"
    assert "hash" in result.message.lower()
    assert result.location == "detections.hashes"


def test_h002_does_not_fire_when_block_mixes_hashes_and_behaviour(
    benign_rule: SigmaRule,
) -> None:
    """A block with hash + Image is fine — the behaviour grounds the hash."""
    grounded = benign_rule.model_copy(
        update={
            "detections": [
                DetectionBlock(
                    name="match_1",
                    is_filter=False,
                    items=[
                        DetectionItem(
                            field="Image",
                            modifiers=["endswith"],
                            values=["\\evil.exe"],
                        ),
                        DetectionItem(field="sha256", values=["a" * 64]),
                    ],
                ),
            ],
        }
    )
    assert hash_only_block(grounded) is None


# --- h-003: network-indicator-only rule --------------------------------------


def test_h003_fires_when_only_network_indicators_present(benign_rule: SigmaRule) -> None:
    """A rule that's all DestinationIp / QueryName fires h-003."""
    network_only = benign_rule.model_copy(
        update={
            "detections": [
                DetectionBlock(
                    name="match_1",
                    is_filter=False,
                    items=[
                        DetectionItem(field="DestinationIp", values=["1.2.3.4"]),
                        DetectionItem(field="QueryName", values=["evil.example"]),
                    ],
                ),
            ],
        }
    )
    result = network_indicator_only_rule(network_only)
    assert result is not None
    assert result.heuristic_id == "h-003"
    assert "process_creation" in result.suggestion


def test_h003_does_not_fire_when_hashes_are_present(benign_rule: SigmaRule) -> None:
    """h-003 is specifically the *network*-only pattern; mixed-IOC fires h-001 instead."""
    mixed_ioc = benign_rule.model_copy(
        update={
            "detections": [
                DetectionBlock(
                    name="match_1",
                    is_filter=False,
                    items=[
                        DetectionItem(field="DestinationIp", values=["1.2.3.4"]),
                        DetectionItem(field="sha256", values=["a" * 64]),
                    ],
                ),
            ],
        }
    )
    assert network_indicator_only_rule(mixed_ioc) is None
