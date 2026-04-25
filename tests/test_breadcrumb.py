"""Stage breadcrumb + /composer/jump endpoint tests.

The breadcrumb lets users navigate freely between stages without going
through Back/Next clicks. Backward jumps are non-destructive (the
draft data is preserved). Forward jumps walk the can_advance gates and
land at the highest reachable stage.
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


def _stage_2_complete_draft() -> str:
    """A draft with a populated detection + complete metadata.

    Reaches Stage 4 cleanly when ``can_advance_to_stage(4)`` runs. We
    use it as the base for "fully reachable" navigation tests.
    """
    return json.dumps(
        {
            "title": "Encoded PowerShell",
            "description": "Detects encoded PowerShell from non-SYSTEM.",
            "author": "tester",
            "date": "2026-04-25",
            "tags": ["attack.execution"],
            "level": "high",
            "status": "experimental",
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
            "stage": 2,
        }
    )


# ---------------------------------------------------------------------------
# Breadcrumb renders on every stage
# ---------------------------------------------------------------------------


def test_breadcrumb_renders_on_stage_0(client: TestClient) -> None:
    """The initial shell should show the breadcrumb with stage 0 current."""
    body = client.get("/mode/guided").text
    assert 'class="stage-breadcrumb"' in body
    assert "Observation" in body
    assert "Detection" in body
    assert "Output" in body


def test_breadcrumb_renders_on_stage_2(client: TestClient) -> None:
    """A draft sent at Stage 2 should produce a breadcrumb with stage 2 current."""
    r = client.post(
        "/composer/update",
        data={"rule_state": _stage_2_complete_draft(), "action": "no_op"},
    )
    body = r.text
    assert 'class="stage-breadcrumb"' in body
    # Current-stage pill carries the accent class.
    assert "stage-step-current" in body


# ---------------------------------------------------------------------------
# /composer/jump — forward navigation gated by can_advance
# ---------------------------------------------------------------------------


def test_jump_backward_is_always_allowed(client: TestClient) -> None:
    """A user at Stage 2 jumping to Stage 0 lands cleanly there."""
    r = client.post(
        "/composer/jump",
        data={"rule_state": _stage_2_complete_draft(), "target": "0"},
    )
    state = _extract_state(r.text)
    assert state["stage"] == 0
    # Detection blocks survive the navigation — purely visual move.
    assert state["detections"], "Detection blocks lost on backward jump"


def test_jump_forward_to_reachable_stage(client: TestClient) -> None:
    """A complete-enough draft can jump from Stage 2 to Stage 4."""
    r = client.post(
        "/composer/jump",
        data={"rule_state": _stage_2_complete_draft(), "target": "4"},
    )
    state = _extract_state(r.text)
    assert state["stage"] == 4


def test_jump_forward_clamps_at_highest_reachable(client: TestClient) -> None:
    """Trying to jump past your current readiness lands at the highest
    you can actually reach, not at the requested stage.
    """
    # A Stage 2 draft missing title — can advance to 2 but not to 3+.
    state_obj = json.loads(_stage_2_complete_draft())
    state_obj["title"] = ""
    state_obj["stage"] = 1  # actually start from 1 to make the forward jump real
    r = client.post(
        "/composer/jump",
        data={"rule_state": json.dumps(state_obj), "target": "4"},
    )
    state = _extract_state(r.text)
    # Can advance to 2 (detection populated). Cannot advance to 3 (no title).
    # So forward-jump from 1 → 2 succeeds; → 3 fails; lands at 2.
    assert state["stage"] == 2


def test_jump_invalid_target_is_silent_noop(client: TestClient) -> None:
    """A non-numeric ``target`` form value re-renders the current stage
    instead of crashing or jumping.
    """
    r = client.post(
        "/composer/jump",
        data={"rule_state": _stage_2_complete_draft(), "target": "garbage"},
    )
    state = _extract_state(r.text)
    assert state["stage"] == 2
