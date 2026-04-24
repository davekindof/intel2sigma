"""Composer-route coverage for the AND/OR combinators added in M1.4.

The state-blob extractor mirrors what the other composer-route tests use.
Each test walks the draft to stage 1 with a known-good observation, then
exercises the new ``set_block_combinator`` and ``set_match_combinator``
actions.
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


def _stage1(client: TestClient) -> str:
    r = client.post(
        "/composer/select-observation",
        data={"rule_state": "{}", "observation_id": "process_creation"},
    )
    return json.dumps(_extract_state(r.text))


# ---------------------------------------------------------------------------
# Per-block combinator
# ---------------------------------------------------------------------------


def test_new_match_block_defaults_to_all_of(client: TestClient) -> None:
    state = _stage1(client)
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    state_obj = _extract_state(r.text)
    assert state_obj["detections"][0]["combinator"] == "all_of"


def test_set_block_combinator_to_any_of(client: TestClient) -> None:
    state = _stage1(client)
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    state = json.dumps(_extract_state(r.text))

    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_block_combinator",
            "block_name": "match_1",
            "combinator": "any_of",
        },
    )
    state_obj = _extract_state(r.text)
    assert state_obj["detections"][0]["combinator"] == "any_of"


def test_set_block_combinator_rejects_unknown_value(client: TestClient) -> None:
    state = _stage1(client)
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    state = json.dumps(_extract_state(r.text))

    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_block_combinator",
            "block_name": "match_1",
            "combinator": "wishful_thinking",
        },
    )
    state_obj = _extract_state(r.text)
    assert state_obj["detections"][0]["combinator"] == "all_of"  # unchanged


def test_set_block_combinator_unknown_block_no_op(client: TestClient) -> None:
    """Posting against a block that doesn't exist quietly does nothing."""
    state = _stage1(client)
    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_block_combinator",
            "block_name": "ghost_block",
            "combinator": "any_of",
        },
    )
    # No detections, no error.
    assert _extract_state(r.text)["detections"] == []


# ---------------------------------------------------------------------------
# Match-blocks combinator (across blocks)
# ---------------------------------------------------------------------------


def test_match_combinator_defaults_to_all_of(client: TestClient) -> None:
    state = _stage1(client)
    state_obj = json.loads(state)
    assert state_obj["match_combinator"] == "all_of"


def test_set_match_combinator_to_any_of(client: TestClient) -> None:
    state = _stage1(client)
    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_match_combinator",
            "match_combinator": "any_of",
        },
    )
    state_obj = _extract_state(r.text)
    assert state_obj["match_combinator"] == "any_of"


def test_match_combinator_toggle_appears_only_with_multiple_blocks(client: TestClient) -> None:
    """The match-combinator toggle is hidden until there are 2+ match blocks
    — a single match block has nothing to combine across, so the toggle
    would be confusing.
    """
    state = _stage1(client)
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    body = r.text
    # One block — toggle should NOT appear in the rendered HTML.
    assert "set_match_combinator" not in body

    state = json.dumps(_extract_state(body))
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    body = r.text
    # Two blocks — toggle now visible.
    assert "set_match_combinator" in body
