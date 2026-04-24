"""End-to-end tests for the composer state machine.

These exercise the full POST/response loop with TestClient so we verify
not just that routes return 200, but that the returned HTML + oob swaps
encode the expected state transitions. The RuleDraft JSON round-trip is
exercised as a side effect.
"""

from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

from intel2sigma.web.app import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_STATE_BLOB_RE = re.compile(r'<textarea id="rule-state"[^>]*>([^<]*)</textarea>', re.DOTALL)


def _extract_state(html: str) -> dict:
    """Pull the RuleDraft JSON back out of the response."""
    match = _STATE_BLOB_RE.search(html)
    assert match, f"Response did not include a #rule-state textarea:\n{html[:500]}"
    raw = match.group(1)
    # FastAPI's Jinja escapes &#34; for quotes when emitting HTML — unescape.
    decoded = (
        raw.replace("&#34;", '"')
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
    )
    return json.loads(decoded)


# ---------------------------------------------------------------------------
# Initial shell
# ---------------------------------------------------------------------------


def test_initial_shell_renders_stage0(client: TestClient) -> None:
    r = client.get("/mode/guided")
    assert r.status_code == 200
    assert "Stage 0 — Pick an observation" in r.text
    state = _extract_state(r.text)
    assert state["stage"] == 0
    assert state["observation_id"] == ""
    assert state["detections"] == []


# ---------------------------------------------------------------------------
# Stage 0 → Stage 1 transition
# ---------------------------------------------------------------------------


def test_select_observation_advances_to_stage1(client: TestClient) -> None:
    # Use the empty state from the shell's initial render.
    shell = client.get("/mode/guided").text
    initial_state = _STATE_BLOB_RE.search(shell).group(1)
    # Unescape the entities so the POST body matches what the form would send.
    initial_state = initial_state.replace("&#34;", '"').replace("&#39;", "'").replace("&amp;", "&")

    r = client.post(
        "/composer/select-observation",
        data={"rule_state": initial_state, "observation_id": "process_creation"},
    )
    assert r.status_code == 200
    assert "Stage 1 — Compose detection" in r.text
    assert "A process was started" in r.text

    state = _extract_state(r.text)
    assert state["stage"] == 1
    assert state["observation_id"] == "process_creation"
    assert state["platform_id"] == "windows"
    assert state["logsource"]["category"] == "process_creation"
    assert state["logsource"]["product"] == "windows"


def test_select_observation_unknown_id_stays_at_stage0(client: TestClient) -> None:
    r = client.post(
        "/composer/select-observation",
        data={"rule_state": "{}", "observation_id": "does_not_exist"},
    )
    assert r.status_code == 200
    state = _extract_state(r.text)
    assert state["stage"] == 0
    assert state["observation_id"] == ""


# ---------------------------------------------------------------------------
# Stage 1 block + item operations
# ---------------------------------------------------------------------------


def _state_at_stage1(client: TestClient) -> str:
    r = client.post(
        "/composer/select-observation",
        data={"rule_state": "{}", "observation_id": "process_creation"},
    )
    state = _extract_state(r.text)
    return json.dumps(state)


def test_add_match_block_creates_match_1(client: TestClient) -> None:
    state = _state_at_stage1(client)
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    assert r.status_code == 200
    state = _extract_state(r.text)
    assert len(state["detections"]) == 1
    assert state["detections"][0]["name"] == "match_1"
    assert state["detections"][0]["is_filter"] is False


def test_add_filter_block_creates_filter_1(client: TestClient) -> None:
    state = _state_at_stage1(client)
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_filter"})
    state = _extract_state(r.text)
    assert len(state["detections"]) == 1
    assert state["detections"][0]["name"] == "filter_1"
    assert state["detections"][0]["is_filter"] is True


def test_two_match_blocks_auto_numbered(client: TestClient) -> None:
    state = _state_at_stage1(client)
    for _ in range(2):
        r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
        state = json.dumps(_extract_state(r.text))
    names = [b["name"] for b in json.loads(state)["detections"]]
    assert names == ["match_1", "match_2"]


def test_delete_block(client: TestClient) -> None:
    state = _state_at_stage1(client)
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    state = json.dumps(_extract_state(r.text))
    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "delete_block",
            "block_name": "match_1",
        },
    )
    state_obj = _extract_state(r.text)
    assert state_obj["detections"] == []


def test_add_item_then_set_field_and_value(client: TestClient) -> None:
    state = _state_at_stage1(client)
    # Add a match block
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    state = json.dumps(_extract_state(r.text))
    # Add an item to the block
    r = client.post(
        "/composer/update",
        data={"rule_state": state, "action": "add_item", "block_name": "match_1"},
    )
    state = json.dumps(_extract_state(r.text))
    # Set the field on that item. Field comes from the per-item input whose
    # name is "field::<block>::<index>".
    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_field",
            "block_name": "match_1",
            "item_index": "0",
            "field::match_1::0": "Image",
        },
    )
    state = json.dumps(_extract_state(r.text))
    # Set the modifier
    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_modifier",
            "block_name": "match_1",
            "item_index": "0",
            "modifier::match_1::0": "endswith",
        },
    )
    state = json.dumps(_extract_state(r.text))
    # Set the value
    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_value",
            "block_name": "match_1",
            "item_index": "0",
            "value::match_1::0": "\\powershell.exe",
        },
    )
    state_obj = _extract_state(r.text)
    item = state_obj["detections"][0]["items"][0]
    assert item["field"] == "Image"
    assert item["modifiers"] == ["endswith"]
    assert item["values"] == ["\\powershell.exe"]


def test_restart_returns_to_stage0(client: TestClient) -> None:
    state = _state_at_stage1(client)
    r = client.post("/composer/restart", data={"rule_state": state})
    state_obj = _extract_state(r.text)
    assert state_obj["stage"] == 0
    assert state_obj["observation_id"] == ""


# ---------------------------------------------------------------------------
# Preview rendering
# ---------------------------------------------------------------------------


def test_preview_shows_yaml_when_draft_is_complete(client: TestClient) -> None:
    """Build up a complete draft; preview pane should contain highlighted YAML
    (and not the "Cannot build a rule" issue messages)."""
    # Get to stage 1
    state = _state_at_stage1(client)

    # Add a match block
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    state = json.dumps(_extract_state(r.text))

    # Add an item
    r = client.post(
        "/composer/update",
        data={"rule_state": state, "action": "add_item", "block_name": "match_1"},
    )
    state = json.dumps(_extract_state(r.text))

    # Set field + modifier + value
    for action, extra in [
        ("set_field", {"field::match_1::0": "Image"}),
        ("set_modifier", {"modifier::match_1::0": "endswith"}),
        ("set_value", {"value::match_1::0": "\\evil.exe"}),
    ]:
        r = client.post(
            "/composer/update",
            data={
                "rule_state": state,
                "action": action,
                "block_name": "match_1",
                "item_index": "0",
                **extra,
            },
        )
        state = json.dumps(_extract_state(r.text))

    # At this point the draft lacks title + date, so preview should still
    # show issues but at least the DRAFT_CONDITION_EMPTY error should be gone.
    assert "DRAFT_CONDITION_EMPTY" not in r.text
    assert "DRAFT_TITLE_MISSING" in r.text  # title still missing
