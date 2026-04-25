"""Tests for /composer/new and the buttons that call it.

The route is the "discard everything" reset that the header New rule
button and Stage 4's Build-another-rule button both wire to. Distinct
from /composer/restart (Stage 1 back), which preserves metadata so
users can switch observations without re-typing shared fields.
"""

from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

from intel2sigma.web.app import app
from tests._state_blob import extract_state as _extract_state


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _populated_draft_at_stage_4() -> str:
    """A draft as if a user just finished a rule.

    Carries metadata, an observation, detection blocks, IOCs — exactly the
    state we want /composer/new to wipe.
    """
    return json.dumps(
        {
            "title": "Encoded PowerShell from non-SYSTEM",
            "description": "Detects encoded PowerShell from non-SYSTEM context.",
            "references": ["https://example.invalid/ref"],
            "author": "alice",
            "date": "2026-04-25",
            "tags": ["attack.execution", "attack.t1059.001"],
            "level": "high",
            "falsepositives": ["Administrative scripts"],
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
            "match_combinator": "all_of",
            "iocs": [
                {
                    "raw": "1.2.3.4",
                    "value": "1.2.3.4",
                    "category": "ip",
                    "observation": "network_connection",
                    "used": False,
                }
            ],
            "stage": 4,
        }
    )


# ---------------------------------------------------------------------------
# /composer/new behaviour
# ---------------------------------------------------------------------------


def test_composer_new_returns_stage_0(client: TestClient) -> None:
    """Hitting /composer/new always lands at Stage 0."""
    r = client.post("/composer/new")
    assert r.status_code == 200
    assert "Stage 0" in r.text


def test_composer_new_discards_metadata_and_iocs(client: TestClient) -> None:
    """A populated draft sent in is ignored — the response carries an empty draft.

    /composer/new doesn't even read its rule_state form param; the test
    confirms by sending a fully populated draft and asserting the
    response state is empty.
    """
    r = client.post(
        "/composer/new",
        # /composer/new doesn't consume rule_state, but a real htmx call
        # may still include it. Verify we ignore it cleanly.
        data={"rule_state": _populated_draft_at_stage_4()},
    )
    state = _extract_state(r.text)
    assert state["title"] == ""
    assert state["description"] == ""
    assert state["tags"] == []
    assert state["references"] == []
    assert state["author"] == ""
    assert state["falsepositives"] == []
    assert state["observation_id"] == ""
    assert state["detections"] == []
    assert state["iocs"] == []
    assert state["stage"] == 0


def test_composer_restart_still_preserves_metadata(client: TestClient) -> None:
    """Sanity check: /composer/restart keeps its preserve-metadata semantic.

    The whole point of the new endpoint is that /composer/restart had
    one job (Stage 1 back button, preserve metadata) and was being
    misused as the "fully reset" path. Make sure we didn't break the
    Stage 1 back behaviour while fixing the misuse.
    """
    r = client.post("/composer/restart", data={"rule_state": _populated_draft_at_stage_4()})
    state = _extract_state(r.text)
    # Observation cleared (back from Stage 1 should let user pick anew).
    assert state["observation_id"] == ""
    assert state["detections"] == []
    assert state["stage"] == 0
    # But metadata preserved — that's the contract.
    assert state["title"] == "Encoded PowerShell from non-SYSTEM"
    assert state["tags"] == ["attack.execution", "attack.t1059.001"]
    assert state["author"] == "alice"


# ---------------------------------------------------------------------------
# Header "New rule" button is wired (not disabled, points at /composer/new)
# ---------------------------------------------------------------------------


def test_header_new_rule_button_is_enabled_and_wired(client: TestClient) -> None:
    """The header New rule button is no longer ``disabled`` and posts to /composer/new."""
    body = client.get("/mode/guided").text
    # Find the New rule button. The label uniquely identifies the row.
    match = re.search(
        r"<button[^>]*>\s*New rule\s*</button>",
        body,
        re.DOTALL,
    )
    assert match, "New rule button not found in header"
    button_html = match.group(0)
    assert "disabled" not in button_html, "New rule button is still disabled"
    assert "/composer/new" in button_html, "New rule button does not target /composer/new"
    # The hx-confirm guards against accidental clicks on a populated draft.
    assert "hx-confirm" in button_html, "Missing hx-confirm on destructive New rule button"


# ---------------------------------------------------------------------------
# Stage 4 "Build another rule" points at /composer/new (regression guard)
# ---------------------------------------------------------------------------


def test_stage_4_build_another_rule_targets_new_endpoint(client: TestClient) -> None:
    """The Stage 4 Build-another-rule button now uses /composer/new.

    Previously it pointed at /composer/restart, which preserved metadata
    despite the button's label promising a fresh rule. Regression-guard
    that we don't slip back to the old wiring.
    """
    # Drive a draft into Stage 4 by posting it directly.
    r = client.post(
        "/composer/back",  # Stage 4 → Stage 3, also re-renders given a stage-4 state
        data={"rule_state": _populated_draft_at_stage_4()},
    )
    # Now advance forward to the actual Stage 4 render.
    state = json.dumps(_extract_state(r.text))
    r = client.post("/composer/advance", data={"rule_state": state})
    body = r.text
    assert "Build another rule" in body
    assert "/composer/new" in body
    # And the old route should not appear in the Build-another-rule anchor.
    # (composer_restart is still referenced elsewhere — Stage 1's back
    # button — so we check a tighter window around the anchor.)
    anchor = re.search(
        r"<a[^>]*>\s*Build another rule\s*</a>",
        body,
        re.DOTALL,
    )
    assert anchor, "Build another rule anchor not found"
    assert "/composer/restart" not in anchor.group(0), (
        "Stage 4 'Build another rule' is still wired to /composer/restart instead of /composer/new"
    )
