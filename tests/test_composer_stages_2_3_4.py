"""M1.4 tests — stage-nav routes, metadata action, conversion tabs, download.

Reuses the regex-based state extractor from the M1.3 route tests. A fixture
helper walks the draft all the way to stage 3 / 4 so individual test cases
don't repeat the full click-through sequence.
"""

from __future__ import annotations

import json
import re
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from intel2sigma.web.app import app
from tests._state_blob import extract_state as _extract_state


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# Helpers: walk a draft into various stages
# ---------------------------------------------------------------------------


def _stage1_with_filled_item(client: TestClient) -> str:
    """Get a draft to stage 1 with one complete match block."""
    r = client.post(
        "/composer/select-observation",
        data={"rule_state": "{}", "observation_id": "process_creation"},
    )
    state = json.dumps(_extract_state(r.text))

    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    state = json.dumps(_extract_state(r.text))

    r = client.post(
        "/composer/update",
        data={"rule_state": state, "action": "add_item", "block_name": "match_1"},
    )
    state = json.dumps(_extract_state(r.text))

    for action, extra in [
        ("set_field", {"field::match_1::0": "Image"}),
        ("set_modifier", {"modifier::match_1::0": "endswith"}),
        ("set_value", {"value::match_1::0": "\\powershell.exe"}),
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
    return state


def _stage2_with_metadata(client: TestClient) -> str:
    """Advance to stage 2 and fill in the required metadata."""
    state = _stage1_with_filled_item(client)
    r = client.post("/composer/advance", data={"rule_state": state})
    state = json.dumps(_extract_state(r.text))

    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_metadata",
            "meta_title": "Test rule: encoded PowerShell",
            "meta_description": "A test rule for the composer test suite.",
            "meta_author": "test suite",
            "meta_date": "2026-04-24",
            "meta_level": "high",
            "meta_status": "experimental",
            "meta_tags": "attack.execution, attack.t1059.001",
            "meta_falsepositives": "Administrative scripts",
            "meta_references": "https://example.invalid/ref",
        },
    )
    return json.dumps(_extract_state(r.text))


# ---------------------------------------------------------------------------
# Stage advance gating
# ---------------------------------------------------------------------------


def test_advance_from_stage1_blocked_without_match_items(client: TestClient) -> None:
    """Stage 1 → 2 requires at least one populated match item."""
    r = client.post(
        "/composer/select-observation",
        data={"rule_state": "{}", "observation_id": "process_creation"},
    )
    state = json.dumps(_extract_state(r.text))

    r = client.post("/composer/advance", data={"rule_state": state})
    # Should stay at stage 1 because no match block has a field+value.
    state_obj = _extract_state(r.text)
    assert state_obj["stage"] == 1


def test_advance_from_stage1_succeeds_with_filled_item(client: TestClient) -> None:
    state = _stage1_with_filled_item(client)
    r = client.post("/composer/advance", data={"rule_state": state})
    state_obj = _extract_state(r.text)
    assert state_obj["stage"] == 2
    assert "Stage 2 — Metadata" in r.text


def test_back_from_stage2_returns_to_stage1(client: TestClient) -> None:
    state = _stage1_with_filled_item(client)
    r = client.post("/composer/advance", data={"rule_state": state})
    state = json.dumps(_extract_state(r.text))

    r = client.post("/composer/back", data={"rule_state": state})
    state_obj = _extract_state(r.text)
    assert state_obj["stage"] == 1
    # Going back from stage 1 keeps the observation (we only clear on stage 0).
    assert state_obj["observation_id"] == "process_creation"


# ---------------------------------------------------------------------------
# Stage 2 — metadata action
# ---------------------------------------------------------------------------


def test_set_metadata_persists_fields_into_draft(client: TestClient) -> None:
    state = _stage1_with_filled_item(client)
    r = client.post("/composer/advance", data={"rule_state": state})
    state = json.dumps(_extract_state(r.text))

    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_metadata",
            "meta_title": "Encoded PowerShell",
            "meta_description": "Detects encoded PowerShell",
            "meta_author": "alice",
            "meta_date": "2026-04-24",
            "meta_level": "high",
            "meta_status": "test",
            "meta_tags": "attack.execution, attack.t1059.001",
            "meta_falsepositives": "Admins\nSCCM",
            "meta_references": "https://example.invalid/1\nhttps://example.invalid/2",
        },
    )
    state_obj = _extract_state(r.text)
    assert state_obj["title"] == "Encoded PowerShell"
    assert state_obj["description"] == "Detects encoded PowerShell"
    assert state_obj["author"] == "alice"
    assert state_obj["date"] == "2026-04-24"
    assert state_obj["level"] == "high"
    assert state_obj["status"] == "test"
    assert state_obj["tags"] == ["attack.execution", "attack.t1059.001"]
    assert state_obj["falsepositives"] == ["Admins", "SCCM"]
    assert state_obj["references"] == [
        "https://example.invalid/1",
        "https://example.invalid/2",
    ]


def test_set_metadata_rejects_unknown_enum_values(client: TestClient) -> None:
    """An invalid ``meta_level`` leaves the draft's level at its previous value."""
    state = _stage1_with_filled_item(client)
    r = client.post("/composer/advance", data={"rule_state": state})
    state = json.dumps(_extract_state(r.text))

    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_metadata",
            "meta_level": "nightmare",  # not a valid RuleLevel
        },
    )
    state_obj = _extract_state(r.text)
    assert state_obj["level"] == "medium"  # default, unchanged


# ---------------------------------------------------------------------------
# Stage 3 — review
# ---------------------------------------------------------------------------


def test_review_stage_shows_prose_summary(client: TestClient) -> None:
    state = _stage2_with_metadata(client)
    r = client.post("/composer/advance", data={"rule_state": state})
    state_obj = _extract_state(r.text)
    assert state_obj["stage"] == 3
    assert "Stage 3 — Review" in r.text
    # The prose summary weaves in logsource + field details.
    assert "process_creation" in r.text
    assert "Image" in r.text
    assert "powershell.exe" in r.text


def test_review_stage_can_advance_to_output(client: TestClient) -> None:
    state = _stage2_with_metadata(client)
    r = client.post("/composer/advance", data={"rule_state": state})  # → stage 3
    state = json.dumps(_extract_state(r.text))

    r = client.post("/composer/advance", data={"rule_state": state})  # → stage 4
    state_obj = _extract_state(r.text)
    assert state_obj["stage"] == 4
    assert "Stage 4 — Output" in r.text


# ---------------------------------------------------------------------------
# Stage 4 — output and conversion tabs
# ---------------------------------------------------------------------------


def test_stage4_renders_conversion_query_for_every_backend(client: TestClient) -> None:
    """Every declared backend should surface either a query or a typed error.

    The stage-4 response includes an oob swap of the conversion-tabs region
    with one ``conversion-output`` div per backend.
    """
    state = _stage2_with_metadata(client)
    r = client.post("/composer/advance", data={"rule_state": state})  # → stage 3
    state = json.dumps(_extract_state(r.text))
    r = client.post("/composer/advance", data={"rule_state": state})  # → stage 4
    body = r.text

    # One <div class="conversion-output" data-backend="..."> per backend.
    backends = re.findall(
        r'data-backend="([^"]+)"[^>]*>\s*(?:<p class="field-error-message">|<pre)',
        body,
    )
    assert set(backends) >= {
        "kusto_sentinel",
        "kusto_mde",
        "splunk",
        "elasticsearch",
        "crowdstrike",
    }


# ---------------------------------------------------------------------------
# Rule download
# ---------------------------------------------------------------------------


def test_download_returns_yaml_for_complete_draft(client: TestClient) -> None:
    state = _stage2_with_metadata(client)
    r = client.get(f"/rule/download?rule_state={quote(state)}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/yaml")
    assert "attachment" in r.headers["content-disposition"]
    assert "title: Encoded PowerShell" in r.text or "title:" in r.text
    assert "logsource:" in r.text
    assert "detection:" in r.text


def test_download_returns_400_for_incomplete_draft(client: TestClient) -> None:
    r = client.get("/rule/download?rule_state=%7B%7D")  # {} — empty draft
    assert r.status_code == 400
    assert "Draft is not a valid rule" in r.text


def test_download_filename_is_slug_of_title(client: TestClient) -> None:
    state = _stage2_with_metadata(client)
    r = client.get(f"/rule/download?rule_state={quote(state)}")
    disposition = r.headers.get("content-disposition", "")
    # Filename should be a slug derived from the title, ending in .yml.
    assert ".yml" in disposition
    assert "test_rule" in disposition or "encoded_powershell" in disposition.lower()
