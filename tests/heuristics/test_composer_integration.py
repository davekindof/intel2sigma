"""Tier-3 advisories show up on the Stage 3 review page.

Per-heuristic logic is covered by the sibling test files; this one
verifies the composer route is actually wired to ``validate_tier3``
and the template renders an advisory section when the rule has issues.
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


def _draft_at_stage_3_with_no_attack_tags() -> str:
    """A complete, parseable rule that fires h-062 (no ATT&CK tags).

    Built directly as a Stage-3 RuleDraft JSON blob so we don't have to
    walk the full composer click-through to get to review.
    """
    return json.dumps(
        {
            "title": "Encoded PowerShell from non-SYSTEM context",
            "description": (
                "Detects encoded PowerShell command lines launched from "
                "non-SYSTEM accounts; common in initial-access loaders."
            ),
            "author": "tester",
            "date": "2026-04-25",
            "tags": [],
            "level": "high",
            "status": "experimental",
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
                        },
                        {
                            "field": "CommandLine",
                            "modifiers": ["contains"],
                            "values": ["-encodedcommand"],
                        },
                    ],
                },
            ],
            "match_combinator": "all_of",
            "stage": 3,
        }
    )


def test_stage_3_renders_advisory_for_missing_attack_tags(client: TestClient) -> None:
    state = _draft_at_stage_3_with_no_attack_tags()
    r = client.post(
        "/composer/update",
        data={"rule_state": state, "action": "set_metadata"},
    )
    assert r.status_code == 200
    body = r.text
    assert "Quality advisories" in body
    assert "H_WARN_h-062" in body or "h-062" in body
    # The advisory text should reference ATT&CK tagging.
    assert "ATT&amp;CK" in body or "ATT&CK" in body


def test_stage_3_clean_rule_shows_no_advisories(client: TestClient) -> None:
    """A rule with full metadata + ATT&CK tags shouldn't trigger any of
    the v1.0 MVP heuristics, so the 'No quality advisories' marker
    appears.
    """
    state_obj = json.loads(_draft_at_stage_3_with_no_attack_tags())
    state_obj["tags"] = ["attack.execution", "attack.t1059.001"]
    r = client.post(
        "/composer/update",
        data={"rule_state": json.dumps(state_obj), "action": "set_metadata"},
    )
    assert r.status_code == 200
    body = r.text
    # State blob should reach Stage 3 cleanly.
    state = _extract_state(body)
    assert state["stage"] == 3
    # And Stage 3 should claim the rule is clean.
    assert "No quality advisories" in body
