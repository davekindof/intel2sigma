"""Tests for the long-tail freeform observation entry point.

When a user's logsource doesn't appear in our taxonomy (corpus
frequency below the threshold, or a proprietary / not-yet-supported
logsource), Stage 0 offers a "Don't see your observation type?"
disclosure with a freeform (product, category, service) form. The
resulting Stage 1 has a permissive UI: free text input for field
names, fallback modifier list, no field-catalog dropdown.

These tests cover the routing + render + edit-flow without relying
on a specific taxonomy entry being present.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from intel2sigma.web.app import app
from tests._state_blob import extract_state as _extract_state


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# Stage 0 surface: the freeform disclosure renders
# ---------------------------------------------------------------------------


def test_stage_0_includes_freeform_disclosure(client: TestClient) -> None:
    """The 'Don't see your observation type?' disclosure is on Stage 0."""
    body = client.get("/mode/guided").text
    assert "Don't see your observation type?" in body
    assert "select_freeform_observation" in body or "/composer/select-freeform-observation" in body


# ---------------------------------------------------------------------------
# /composer/select-freeform-observation — input handling
# ---------------------------------------------------------------------------


def test_freeform_with_all_three_fields_advances_to_stage_1(client: TestClient) -> None:
    """A complete freeform submission lands on Stage 1 with logsource set."""
    r = client.post(
        "/composer/select-freeform-observation",
        data={
            "rule_state": "{}",
            "freeform_product": "windows",
            "freeform_category": "powershell",
            "freeform_service": "operational",
        },
    )
    assert r.status_code == 200
    state = _extract_state(r.text)
    assert state["stage"] == 1
    assert state["observation_id"] == "_freeform"
    assert state["logsource"]["product"] == "windows"
    assert state["logsource"]["category"] == "powershell"
    assert state["logsource"]["service"] == "operational"


def test_freeform_with_just_one_field_works(client: TestClient) -> None:
    """At least one of product/category/service is required; one is enough."""
    r = client.post(
        "/composer/select-freeform-observation",
        data={
            "rule_state": "{}",
            "freeform_product": "",
            "freeform_category": "",
            "freeform_service": "okta",
        },
    )
    state = _extract_state(r.text)
    assert state["stage"] == 1
    assert state["observation_id"] == "_freeform"
    assert state["logsource"]["service"] == "okta"
    assert state["logsource"]["product"] is None
    assert state["logsource"]["category"] is None


def test_freeform_with_all_empty_stays_on_stage_0(client: TestClient) -> None:
    """An empty submit re-renders Stage 0 with no draft mutation."""
    r = client.post(
        "/composer/select-freeform-observation",
        data={
            "rule_state": "{}",
            "freeform_product": "",
            "freeform_category": "",
            "freeform_service": "",
        },
    )
    state = _extract_state(r.text)
    assert state["stage"] == 0
    assert state["observation_id"] == ""


def test_freeform_strips_whitespace(client: TestClient) -> None:
    """User pasting in fields with stray whitespace gets clean values."""
    r = client.post(
        "/composer/select-freeform-observation",
        data={
            "rule_state": "{}",
            "freeform_product": "  windows  ",
            "freeform_category": "\tregistry_event\n",
            "freeform_service": "",
        },
    )
    state = _extract_state(r.text)
    assert state["logsource"]["product"] == "windows"
    assert state["logsource"]["category"] == "registry_event"


# ---------------------------------------------------------------------------
# Stage 1 render with no taxonomy spec
# ---------------------------------------------------------------------------


def _freeform_stage_1() -> str:
    """A draft already at freeform Stage 1, ready for Stage 1 actions."""
    return json.dumps(
        {
            "observation_id": "_freeform",
            "platform_id": "okta",
            "logsource": {
                "category": None,
                "product": None,
                "service": "okta",
            },
            "detections": [],
            "match_combinator": "all_of",
            "stage": 1,
        }
    )


def test_freeform_stage_1_renders_with_text_field_input(client: TestClient) -> None:
    """The Stage 1 detection editor in freeform mode uses text inputs for
    field names, not the catalog-driven dropdown.
    """
    state = _freeform_stage_1()
    # Add a match block first so we have an item to inspect.
    r = client.post(
        "/composer/update",
        data={"rule_state": state, "action": "add_match"},
    )
    state = json.dumps(_extract_state(r.text))
    r = client.post(
        "/composer/update",
        data={"rule_state": state, "action": "add_item", "block_name": "match_1"},
    )
    body = r.text
    # The freeform field row uses ``<input class="item-field" type="text">``
    # rather than ``<select class="item-field">``.
    assert 'class="item-field"' in body
    assert '<input class="item-field"' in body
    # No "select field" dropdown placeholder for freeform.
    assert "-- select field --" not in body
    # Subtitle reflects custom-logsource framing.
    assert "Custom logsource" in body
    assert "service: okta" in body


def test_freeform_set_field_persists_typed_field_name(client: TestClient) -> None:
    """Typing a field name in the freeform path persists into the draft."""
    state = _freeform_stage_1()
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    state = json.dumps(_extract_state(r.text))
    r = client.post(
        "/composer/update",
        data={"rule_state": state, "action": "add_item", "block_name": "match_1"},
    )
    state = json.dumps(_extract_state(r.text))
    # Stage 1 freeform user types "actor.id" as the field name.
    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_field",
            "block_name": "match_1",
            "item_index": "0",
            "field::match_1::0": "actor.id",
        },
    )
    state_obj = _extract_state(r.text)
    assert state_obj["detections"][0]["items"][0]["field"] == "actor.id"


def test_freeform_yaml_preview_renders_with_typed_logsource(client: TestClient) -> None:
    """The preview pane shows the user-typed logsource in YAML form."""
    state_obj = json.loads(_freeform_stage_1())
    state_obj["detections"] = [
        {
            "name": "match_1",
            "is_filter": False,
            "combinator": "all_of",
            "items": [{"field": "actor.id", "modifiers": ["exact"], "values": ["00abc"]}],
        }
    ]
    r = client.post(
        "/composer/update",
        data={"rule_state": json.dumps(state_obj), "action": "no_op"},
    )
    body = r.text
    # Partial YAML preview reflects the freeform logsource + the user's
    # detection item.
    assert "service: okta" in body
    assert "actor.id" in body
