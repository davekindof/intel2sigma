"""Tests for the M1.6A composer routes — classify_iocs, build_from_iocs,
discard_iocs.

Reuses the state-blob extractor pattern from the other route test files.
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
# Initial render — IOC panel shows the empty paste form
# ---------------------------------------------------------------------------


def test_initial_stage_0_renders_ioc_paste_panel(client: TestClient) -> None:
    r = client.get("/mode/guided")
    body = r.text
    assert "Paste IOCs from a CTI hand-off" in body
    assert "iocs_text" in body  # the textarea name


# ---------------------------------------------------------------------------
# classify_iocs action
# ---------------------------------------------------------------------------


def test_classify_action_populates_iocs_in_state(client: TestClient) -> None:
    r = client.post(
        "/composer/update",
        data={
            "rule_state": "{}",
            "action": "classify_iocs",
            "iocs_text": "evil.example.com\n1.2.3.4:5555\n",
        },
    )
    assert r.status_code == 200
    state = _extract_state(r.text)
    assert state["iocs"], "Classifier did not populate iocs"
    cats = sorted(i["category"] for i in state["iocs"])
    assert "domain" in cats
    assert "ip" in cats


def test_classify_action_renders_per_category_summary_in_html(client: TestClient) -> None:
    """The classified panel surfaces one card per category with a Build
    button targeting the right observation.
    """
    r = client.post(
        "/composer/update",
        data={
            "rule_state": "{}",
            "action": "classify_iocs",
            "iocs_text": "evil.example.com\n1.2.3.4\nC:\\Windows\\System32\\evil.dll\n",
        },
    )
    body = r.text
    assert "Build dns_query rule" in body
    assert "Build network_connection rule" in body
    assert "Build image_load rule" in body  # .dll → image_load
    # And the Discard button.
    assert "Discard IOCs" in body


# ---------------------------------------------------------------------------
# build_from_iocs action
# ---------------------------------------------------------------------------


def test_build_from_iocs_renders_stage1_for_hashes(client: TestClient) -> None:
    """Regression: SHA-256 hashes routed to file_event used to 500 the
    Stage 1 render because file_event.yml didn't list a Hashes field.

    Drives the full classify → build → render flow and asserts a clean
    200 with Stage 1 markup. The path that broke in production was the
    Jinja modifier-dropdown lookup (``field_specs_by_name[item.field]``
    raised UndefinedError when item.field wasn't in the taxonomy);
    this test exercises that exact code path.
    """
    hashes = "\n".join(
        [
            "1b62b7c2ed7cc296ce821f977ef7b22bae59ef1dcdb9a34ae19467ee39bcf168",
            "4ebfe8f66ca7e9751060b3301b5e8838d6017593cdae748541de83bfa28183bd",
            "97c275e3406ad6576529f41604ad138c5bdc4297d195bf61b049e14f6b30adfd",
        ]
    )
    r = client.post(
        "/composer/update",
        data={"rule_state": "{}", "action": "classify_iocs", "iocs_text": hashes},
    )
    state = json.dumps(_extract_state(r.text))

    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "build_from_iocs",
            "observation_id": "file_event",
        },
    )
    assert r.status_code == 200, (
        "Build file_event rule from hashes 500'd — see the file_event Hashes-field fix commit."
    )
    state_obj = _extract_state(r.text)
    assert state_obj["stage"] == 1
    assert state_obj["observation_id"] == "file_event"
    block = state_obj["detections"][0]
    fields = [item["field"] for item in block["items"]]
    assert all(f == "Hashes" for f in fields)
    assert "Stage 1 — Compose detection" in r.text


def test_build_from_iocs_advances_to_stage_1_with_detection_items(client: TestClient) -> None:
    # First, classify.
    r = client.post(
        "/composer/update",
        data={
            "rule_state": "{}",
            "action": "classify_iocs",
            "iocs_text": "1.2.3.4:9999\n5.6.7.8\n",
        },
    )
    state = json.dumps(_extract_state(r.text))

    # Now build a network_connection rule from the IPs.
    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "build_from_iocs",
            "observation_id": "network_connection",
        },
    )
    state_obj = _extract_state(r.text)
    assert state_obj["stage"] == 1
    assert state_obj["observation_id"] == "network_connection"
    assert state_obj["logsource"]["category"] == "network_connection"

    # Detection blocks: one match block with combinator=any_of holding the
    # routed items.
    detections = state_obj["detections"]
    assert len(detections) == 1
    block = detections[0]
    assert block["name"] == "match_1"
    assert block["combinator"] == "any_of"
    fields = sorted({i["field"] for i in block["items"]})
    assert "DestinationIp" in fields
    assert "DestinationPort" in fields  # split out from 1.2.3.4:9999


def test_build_from_iocs_marks_consumed_iocs_as_used(client: TestClient) -> None:
    r = client.post(
        "/composer/update",
        data={
            "rule_state": "{}",
            "action": "classify_iocs",
            "iocs_text": "1.2.3.4\nevil.example.com\n",
        },
    )
    state = json.dumps(_extract_state(r.text))

    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "build_from_iocs",
            "observation_id": "network_connection",
        },
    )
    state_obj = _extract_state(r.text)
    by_cat = {i["category"]: i["used"] for i in state_obj["iocs"]}
    assert by_cat["ip"] is True  # was used
    assert by_cat["domain"] is False  # untouched


def test_build_from_iocs_unknown_observation_no_op(client: TestClient) -> None:
    r = client.post(
        "/composer/update",
        data={
            "rule_state": "{}",
            "action": "classify_iocs",
            "iocs_text": "1.2.3.4\n",
        },
    )
    state = json.dumps(_extract_state(r.text))

    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "build_from_iocs",
            "observation_id": "definitely_not_real",
        },
    )
    state_obj = _extract_state(r.text)
    # Stayed at stage 0; no detection blocks were created.
    assert state_obj["stage"] == 0
    assert state_obj["detections"] == []


def test_build_from_iocs_no_unused_iocs_in_category_no_op(client: TestClient) -> None:
    """If all IOCs for the requested observation are already used, the
    action quietly does nothing — no NEW match block is created.

    Concretely: invoking ``build_from_iocs`` against a category whose
    IOCs are all marked used must not change the rule state. We simulate
    by manually constructing a draft where the only IP IOC is already
    used and then attempting to build.
    """
    # Manually construct a draft with one used IOC.
    draft_state = json.dumps(
        {
            "iocs": [
                {
                    "raw": "1.2.3.4",
                    "value": "1.2.3.4",
                    "category": "ip",
                    "observation": "network_connection",
                    "used": True,
                }
            ],
        }
    )

    r = client.post(
        "/composer/update",
        data={
            "rule_state": draft_state,
            "action": "build_from_iocs",
            "observation_id": "network_connection",
        },
    )
    state_obj = _extract_state(r.text)
    # No new rule was started.
    assert state_obj["stage"] == 0
    assert state_obj["detections"] == []


# ---------------------------------------------------------------------------
# discard_iocs action
# ---------------------------------------------------------------------------


def test_discard_iocs_clears_session(client: TestClient) -> None:
    r = client.post(
        "/composer/update",
        data={
            "rule_state": "{}",
            "action": "classify_iocs",
            "iocs_text": "1.2.3.4\n",
        },
    )
    state = json.dumps(_extract_state(r.text))
    r = client.post(
        "/composer/update",
        data={"rule_state": state, "action": "discard_iocs"},
    )
    state_obj = _extract_state(r.text)
    assert state_obj["iocs"] == []
    # And the empty paste form is back in the panel.
    assert "Paste IOCs from a CTI hand-off" in r.text
