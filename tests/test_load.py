"""Tests for the rule-loading translator and the composer load routes."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from intel2sigma.web.app import app
from intel2sigma.web.load import (
    ExampleEntry,
    draft_from_yaml,
    list_examples,
    load_example,
)
from tests._state_blob import extract_state as _extract_state


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


VALID_YAML = """
title: Encoded PowerShell from non-SYSTEM
id: 12345678-1234-5678-1234-567812345678
status: experimental
description: Detects encoded PowerShell command lines launched outside SYSTEM.
references:
  - https://example.invalid/ref
author: alice
date: 2026-04-23
tags:
  - attack.execution
  - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-encodedcommand'
    filter_admin:
        User|contains: SYSTEM
    condition: selection and not filter_admin
falsepositives:
  - Administrative scripts
level: high
"""


# ---------------------------------------------------------------------------
# draft_from_yaml — unit tests
# ---------------------------------------------------------------------------


def test_draft_from_yaml_translates_a_well_formed_rule() -> None:
    draft, issues = draft_from_yaml(VALID_YAML)
    assert draft is not None
    assert issues == []
    assert draft.title == "Encoded PowerShell from non-SYSTEM"
    assert draft.observation_id == "process_creation"
    assert draft.platform_id == "windows"
    assert draft.tags == ["attack.execution", "attack.t1059.001"]
    assert draft.level == "high"
    assert draft.status == "experimental"
    # Detection blocks: one match (selection), one filter (filter_admin).
    names = sorted(b.name for b in draft.detections)
    assert names == ["filter_admin", "selection"]
    is_filter = {b.name: b.is_filter for b in draft.detections}
    assert is_filter == {"selection": False, "filter_admin": True}


def test_draft_from_yaml_lands_at_stage3_when_complete() -> None:
    draft, _issues = draft_from_yaml(VALID_YAML)
    # A fully-validating draft jumps to review.
    assert draft is not None
    assert draft.stage == 3


def test_draft_from_yaml_returns_issue_on_garbage_input() -> None:
    draft, issues = draft_from_yaml("not: valid sigma\n  detection: nope")
    assert draft is None
    assert issues
    assert all(i.code.startswith("LOAD_") for i in issues)


def test_draft_from_yaml_flags_unknown_observation() -> None:
    """A rule with a logsource we don't have catalogued still loads but
    surfaces a LOAD_OBSERVATION_UNKNOWN warning so the user knows the
    field dropdown won't help them.
    """
    yaml = """
title: Unknown logsource example
id: 12345678-1234-5678-1234-567812345678
status: experimental
date: 2026-04-23
logsource:
    category: definitely_not_a_real_category
    product: windows
detection:
    selection:
        SomeField: value
    condition: selection
"""
    draft, issues = draft_from_yaml(yaml)
    assert draft is not None
    codes = [i.code for i in issues]
    assert "LOAD_OBSERVATION_UNKNOWN" in codes


def test_draft_from_yaml_recognizes_any_of_block_combinator() -> None:
    """A list-of-mappings detection block translates to combinator=any_of."""
    yaml = """
title: any_of block round-trip test
id: 12345678-1234-5678-1234-567812345678
status: experimental
date: 2026-04-23
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\\foo.exe'
        - CommandLine|contains: '-bar'
    condition: selection
"""
    draft, _issues = draft_from_yaml(yaml)
    assert draft is not None
    block = next(b for b in draft.detections if b.name == "selection")
    assert block.combinator == "any_of"
    assert len(block.items) == 2


# ---------------------------------------------------------------------------
# Examples listing
# ---------------------------------------------------------------------------


def test_list_examples_returns_curated_set() -> None:
    examples = list_examples()
    assert examples, "Expected at least one curated example under data/examples/"
    # Every entry should have a non-empty title pulled from the underlying rule.
    for entry in examples:
        assert isinstance(entry, ExampleEntry)
        assert entry.title
        assert entry.id


def test_load_example_round_trips_a_curated_rule() -> None:
    examples = list_examples()
    if not examples:
        pytest.skip("No curated examples on disk — run scripts/curate_examples.py")
    entry = examples[0]
    draft, _issues = load_example(entry.id)
    assert draft is not None
    assert draft.title == entry.title


def test_load_example_unknown_id_returns_issue() -> None:
    draft, issues = load_example("definitely-not-an-example")
    assert draft is None
    assert any(i.code == "LOAD_EXAMPLE_UNKNOWN" for i in issues)


# ---------------------------------------------------------------------------
# Composer routes
# ---------------------------------------------------------------------------


def test_load_modal_route_renders(client: TestClient) -> None:
    r = client.get("/composer/load")
    assert r.status_code == 200
    assert "Load an existing rule" in r.text
    assert "Paste YAML" in r.text
    assert "Examples" in r.text


def test_load_paste_with_valid_yaml_advances_to_stage3(client: TestClient) -> None:
    """A valid pasted rule lands the user at Stage 3 review with the
    composer-panel updated and the load modal closed.

    Tester regression: the previous wiring rendered Stage 3 markup as
    the response's *main* body, which htmx swapped into the load modal
    target — so the composer-panel never updated and the user stayed
    visually on Stage 0. Fix: composer-panel is an oob swap, the main
    body is empty (which closes the modal cleanly).
    """
    r = client.post("/composer/load-paste", data={"yaml_text": VALID_YAML})
    assert r.status_code == 200
    state = _extract_state(r.text)
    assert state["stage"] == 3
    assert state["title"] == "Encoded PowerShell from non-SYSTEM"
    # Composer panel swapped via oob — Stage 3 markup goes there, not
    # to the modal target.
    assert '<div id="composer-panel" hx-swap-oob="true">' in r.text
    assert "Stage 3 — Review" in r.text
    # Modal title text should NOT appear (modal closed via empty
    # main-body swap to the #load-modal-region target).
    assert "Load an existing rule" not in r.text


def test_load_lands_user_on_stage_3_in_composer_panel(client: TestClient) -> None:
    """Regression for the load-rule UX bug: after loading a fully-valid
    rule, the LEFT pane (composer panel) shows Stage 3 review markup,
    not the Stage 0 observation picker.

    The bug was that ``_render_stage_with_load_clear`` returned the
    Stage 3 HTML as the response body and let htmx swap it into the
    modal target — so the composer-panel stayed on Stage 0.
    """
    r = client.post("/composer/load-paste", data={"yaml_text": VALID_YAML})
    body = r.text
    # The composer-panel oob wrapper carries the Stage 3 review markup.
    assert '<div id="composer-panel" hx-swap-oob="true">' in body
    # Stage 3-specific text appears, Stage 0-specific text doesn't.
    assert "Stage 3 — Review" in body
    assert "Stage 0 — Pick an observation" not in body


def test_load_paste_with_garbage_re_renders_modal_with_issues(client: TestClient) -> None:
    r = client.post("/composer/load-paste", data={"yaml_text": "not a rule"})
    assert r.status_code == 200
    # Stays in modal context — no rule-state textarea pop.
    assert "Load an existing rule" in r.text
    assert "LOAD_PARSE_FAILED" in r.text


def test_load_example_route_loads_a_curated_rule(client: TestClient) -> None:
    examples = list_examples()
    if not examples:
        pytest.skip("No curated examples")
    entry = examples[0]
    r = client.post("/composer/load-example", data={"example_id": entry.id})
    assert r.status_code == 200
    state = _extract_state(r.text)
    # Loaded successfully; we shouldn't be back at stage 0.
    assert state["stage"] in {1, 3}
    assert state["title"] == entry.title


def test_load_close_route_returns_empty_body(client: TestClient) -> None:
    r = client.post("/composer/load-close")
    assert r.status_code == 200
    assert r.text == ""
