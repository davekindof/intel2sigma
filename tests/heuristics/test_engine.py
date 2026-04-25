"""Tests for the heuristic engine itself — registry, config, run_all, tier3.

The per-heuristic ``test_<category>.py`` files cover the individual
checks. This file covers the wiring that runs them.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from intel2sigma.core.heuristics import (
    HeuristicConfig,
    HeuristicResult,
    load_config,
    register,
    registered_ids,
    run_all,
)
from intel2sigma.core.heuristics.config import HeuristicConfigLoadError
from intel2sigma.core.model import SigmaRule
from intel2sigma.core.validate import validate_tier3

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_includes_every_v1_mvp_heuristic() -> None:
    ids = set(registered_ids())
    expected = {"h-001", "h-021", "h-030", "h-050", "h-051", "h-060", "h-061", "h-062"}
    missing = expected - ids
    assert not missing, f"MVP heuristics missing from registry: {sorted(missing)}"


def test_register_rejects_duplicate_ids() -> None:
    with pytest.raises(ValueError, match="already registered"):

        @register("h-001", category="ioc_vs_behavior")
        def _shadow(rule: SigmaRule) -> HeuristicResult | None:
            return None


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------


def test_load_config_returns_entry_for_every_mvp_heuristic() -> None:
    cfg = load_config()
    for hid in ("h-001", "h-021", "h-030", "h-050", "h-051", "h-060", "h-061", "h-062"):
        assert hid in cfg, f"{hid} missing from heuristics.yml"


def test_load_config_raises_on_missing_file(tmp_path: Path) -> None:
    with pytest.raises(HeuristicConfigLoadError, match="not found"):
        load_config(tmp_path / "nope.yml")


def test_load_config_raises_on_schema_violation(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yml"
    bad.write_text(
        textwrap.dedent(
            """
            heuristics:
              h-001:
                severity: catastrophic
                enabled: true
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(HeuristicConfigLoadError, match="schema validation"):
        load_config(bad)


# ---------------------------------------------------------------------------
# run_all + severity propagation
# ---------------------------------------------------------------------------


def test_run_all_skips_disabled_heuristics(benign_rule: SigmaRule) -> None:
    # Disable every heuristic; benign_rule already passes them all anyway.
    cfg = {hid: HeuristicConfig(severity="warn", enabled=False) for hid in registered_ids()}
    assert run_all(benign_rule, cfg) == []


def test_run_all_applies_severity_from_config(benign_rule: SigmaRule) -> None:
    # Strip ATT&CK tags so h-062 fires; force its severity to ``critical``.
    untagged = benign_rule.model_copy(update={"tags": []})
    cfg = {"h-062": HeuristicConfig(severity="critical", enabled=True)}
    fired = run_all(untagged, cfg)
    assert len(fired) == 1
    assert fired[0].heuristic_id == "h-062"
    assert fired[0].severity == "critical"


# ---------------------------------------------------------------------------
# tier3 adapter
# ---------------------------------------------------------------------------


def test_validate_tier3_emits_validation_issues(benign_rule: SigmaRule) -> None:
    untagged = benign_rule.model_copy(update={"tags": []})
    issues = validate_tier3(untagged)
    h062 = [i for i in issues if "h-062" in i.code]
    assert h062, f"expected h-062 advisory, got {[i.code for i in issues]}"
    # Severity prefix is part of the contract.
    assert h062[0].code.startswith("H_WARN_") or h062[0].code.startswith("H_CRITICAL_")


def test_validate_tier3_clean_rule_returns_no_issues(benign_rule: SigmaRule) -> None:
    assert validate_tier3(benign_rule) == []
