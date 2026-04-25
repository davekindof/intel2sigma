"""Tests for the MITRE ATT&CK tree loader and the picker UI integration.

The build script (``scripts/build_mitre_tree.py``) is exercised
manually as part of the quarterly recalibration loop; here we test
that ``data/mitre_attack.json`` (committed) loads cleanly and that the
Stage 2 metadata page renders the picker tree without errors.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from intel2sigma.web.app import app
from intel2sigma.web.mitre import load_mitre_tree

_STATE_BLOB_RE = re.compile(r'<textarea id="rule-state"[^>]*>([^<]*)</textarea>', re.DOTALL)


def _extract_state(html: str) -> dict:
    raw = _STATE_BLOB_RE.search(html).group(1)
    return json.loads(
        raw.replace("&#34;", '"')
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
    )


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# Tree loader unit tests
# ---------------------------------------------------------------------------


def test_mitre_tree_loads_with_expected_top_level_keys() -> None:
    tree = load_mitre_tree()
    assert tree, "data/mitre_attack.json missing — run scripts/build_mitre_tree.py"
    assert "version" in tree
    assert "tactics" in tree
    assert isinstance(tree["tactics"], list)
    assert len(tree["tactics"]) >= 12  # ATT&CK Enterprise has 14 tactics


def test_mitre_tactics_have_expected_shape() -> None:
    tree = load_mitre_tree()
    for tactic in tree["tactics"]:
        assert tactic["id"].startswith("TA"), f"{tactic['id']} — expected TA-prefixed tactic id"
        assert tactic["name"]
        assert tactic["tag"].startswith("attack."), tactic["tag"]
        assert isinstance(tactic["techniques"], list)


def test_mitre_techniques_have_expected_shape() -> None:
    tree = load_mitre_tree()
    seen_techniques = 0
    seen_subtechniques = 0
    for tactic in tree["tactics"]:
        for tech in tactic["techniques"]:
            seen_techniques += 1
            assert tech["id"].startswith("T"), tech["id"]
            assert tech["tag"] == f"attack.{tech['id'].lower()}"
            for sub in tech["subtechniques"]:
                seen_subtechniques += 1
                assert sub["id"].startswith(tech["id"] + ".")
                assert sub["tag"] == f"attack.{sub['id'].lower()}"

    # Sanity: ATT&CK Enterprise has hundreds of techniques.
    assert seen_techniques > 100
    assert seen_subtechniques > 100


def test_well_known_techniques_present() -> None:
    """Smoke-check that the tree includes some load-bearing ATT&CK entries.

    If MITRE renumbers anything we depend on, this catches it.
    """
    tree = load_mitre_tree()
    all_tech_ids = {tech["id"] for tactic in tree["tactics"] for tech in tactic["techniques"]}
    all_sub_ids = {
        sub["id"]
        for tactic in tree["tactics"]
        for tech in tactic["techniques"]
        for sub in tech["subtechniques"]
    }
    # T1059 PowerShell (sub-technique T1059.001) is the canonical
    # detection-engineer reference.
    assert "T1059" in all_tech_ids
    assert "T1059.001" in all_sub_ids
    # Initial Access via supply chain (used in our motivating Axios
    # scenario).
    assert "T1195" in all_tech_ids
    assert "T1195.002" in all_sub_ids


def test_loader_returns_empty_dict_when_file_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Missing data file shouldn't blow up the composer — degrade silently."""
    monkeypatch.setattr("intel2sigma.web.mitre._TREE_PATH", tmp_path / "nope.json")
    load_mitre_tree.cache_clear()  # type: ignore[attr-defined]
    try:
        assert load_mitre_tree() == {}
    finally:
        load_mitre_tree.cache_clear()  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Stage 2 metadata renders the picker
# ---------------------------------------------------------------------------


def _draft_at_stage_2() -> str:
    """Minimal draft positioned at Stage 2 (metadata)."""
    return json.dumps(
        {
            "observation_id": "process_creation",
            "platform_id": "windows",
            "logsource": {
                "category": "process_creation",
                "product": "windows",
                "service": None,
            },
            "detections": [
                {
                    "name": "match_1",
                    "is_filter": False,
                    "combinator": "all_of",
                    "items": [
                        {
                            "field": "Image",
                            "modifiers": ["endswith"],
                            "values": ["\\powershell.exe"],
                        }
                    ],
                }
            ],
            "stage": 2,
        }
    )


def test_stage_2_renders_mitre_picker(client: TestClient) -> None:
    state = _draft_at_stage_2()
    r = client.post(
        "/composer/update",
        data={"rule_state": state, "action": "set_metadata"},
    )
    body = r.text
    assert "Browse ATT&amp;CK" in body or "Browse ATT&CK" in body
    # Tactic IDs should appear directly in the rendered HTML.
    assert "TA0002" in body  # Execution
    # And the tag used by the toggle JS:
    assert 'data-attack-tag="attack.execution"' in body
    assert 'data-attack-tag="attack.t1059.001"' in body  # PowerShell sub-tech


def test_picker_marks_already_selected_tags(client: TestClient) -> None:
    """A draft with attack.t1059.001 in its tags should render that
    technique's toggle button in the .selected state.
    """
    state_obj = json.loads(_draft_at_stage_2())
    state_obj["tags"] = ["attack.execution", "attack.t1059.001"]
    state = json.dumps(state_obj)

    r = client.post(
        "/composer/update",
        data={"rule_state": state, "action": "set_metadata"},
    )
    body = r.text

    # The button for attack.t1059.001 should have class="... selected".
    pattern = re.compile(
        r'data-attack-tag="attack\.t1059\.001"[^>]*class="[^"]*selected[^"]*"'
        r'|class="[^"]*selected[^"]*"[^>]*data-attack-tag="attack\.t1059\.001"'
    )
    assert pattern.search(body), "Selected sub-technique not marked as selected in HTML"
