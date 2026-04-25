"""Tests for the M1.6B "Build similar rule" route.

Asserts the carryover/reset boundary: shared metadata persists across
the jump, observation + detection blocks are cleared, IOC session
travels with the user.
"""

from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

from intel2sigma.web.app import app

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


def _populated_draft() -> str:
    """A draft as if a user just finished building rule 1.

    Has metadata, an observation, detection blocks, and an IOC session
    with one used and one unused entry — so we can verify the IOC list
    survives the build-similar jump intact (with used flags preserved).
    """
    return json.dumps(
        {
            "title": "Encoded PowerShell",
            "description": "Detects encoded PowerShell from non-SYSTEM.",
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
                    "combinator": "any_of",
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
                    "raw": "abc",
                    "value": "abc",
                    "category": "hash_sha256",
                    "observation": "file_event",
                    "used": True,
                },
                {
                    "raw": "1.2.3.4",
                    "value": "1.2.3.4",
                    "category": "ip",
                    "observation": "network_connection",
                    "used": False,
                },
            ],
            "stage": 4,
        }
    )


def test_build_similar_returns_to_stage_0(client: TestClient) -> None:
    r = client.post("/composer/build-similar", data={"rule_state": _populated_draft()})
    state = _extract_state(r.text)
    assert state["stage"] == 0


def test_build_similar_preserves_metadata(client: TestClient) -> None:
    r = client.post("/composer/build-similar", data={"rule_state": _populated_draft()})
    state = _extract_state(r.text)
    # Title got the (related) marker.
    assert state["title"] == "Encoded PowerShell (related)"
    # Other metadata fields persist verbatim.
    assert state["description"] == "Detects encoded PowerShell from non-SYSTEM."
    assert state["references"] == ["https://example.invalid/ref"]
    assert state["author"] == "alice"
    assert state["date"] == "2026-04-25"
    assert state["tags"] == ["attack.execution", "attack.t1059.001"]
    assert state["level"] == "high"
    assert state["falsepositives"] == ["Administrative scripts"]


def test_build_similar_clears_observation_and_detections(client: TestClient) -> None:
    r = client.post("/composer/build-similar", data={"rule_state": _populated_draft()})
    state = _extract_state(r.text)
    assert state["observation_id"] == ""
    assert state["platform_id"] == ""
    assert state["logsource"]["category"] is None
    assert state["logsource"]["product"] is None
    assert state["detections"] == []
    assert state["condition_tree"] is None
    assert state["match_combinator"] == "all_of"


def test_build_similar_preserves_ioc_session(client: TestClient) -> None:
    """IOC session carries forward so the user can pick the next category
    without re-pasting. ``used`` flags survive intact so already-consumed
    IOCs don't reappear as available.
    """
    r = client.post("/composer/build-similar", data={"rule_state": _populated_draft()})
    state = _extract_state(r.text)
    assert len(state["iocs"]) == 2
    by_category = {i["category"]: i for i in state["iocs"]}
    assert by_category["hash_sha256"]["used"] is True
    assert by_category["ip"]["used"] is False


def test_build_similar_does_not_re_append_marker(client: TestClient) -> None:
    """Calling Build similar twice in a row shouldn't pile up
    ``(related) (related)`` on the title.
    """
    state = _populated_draft()
    r = client.post("/composer/build-similar", data={"rule_state": state})
    state = json.dumps(_extract_state(r.text))

    r = client.post("/composer/build-similar", data={"rule_state": state})
    state_obj = _extract_state(r.text)
    # Title still has exactly one (related) marker.
    assert state_obj["title"].count("(related)") == 1


def test_build_similar_button_appears_on_stage_4(client: TestClient) -> None:
    """The Stage 4 output template references the build_similar route."""
    # Need a draft that's at stage 4 — easier to drive via the existing
    # advance routes, but for a small test we just re-use the JSON shape.
    state = _populated_draft()
    r = client.post(
        "/composer/back",  # stage 4 -> stage 3
        data={"rule_state": state},
    )
    # Stage 3 doesn't show Build similar; navigate forward to stage 4.
    state = json.dumps(_extract_state(r.text))
    r = client.post("/composer/advance", data={"rule_state": state})
    body = r.text
    assert "Build similar rule" in body
    assert "build-similar" in body  # the route URL
