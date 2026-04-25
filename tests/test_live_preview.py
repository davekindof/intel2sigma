"""Live YAML preview tests.

The preview pane used to stay blank (just placeholder text) until the
draft fully passed tier-1 validation. Now it renders a best-effort
YAML of whatever's currently in the draft, alongside the existing
tier-1 issue list. Conversion tabs remain gated on a fully-valid rule.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from intel2sigma.web.app import app
from intel2sigma.web.draft import RuleDraft


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# RuleDraft.to_partial_yaml unit tests
# ---------------------------------------------------------------------------


def test_partial_yaml_renders_what_is_filled_in() -> None:
    """A Stage 1 draft with a populated detection but no title/date
    should produce YAML for the populated fields and skip the rest.
    """
    draft = RuleDraft.from_json(
        json.dumps(
            {
                "observation_id": "pipe_created",
                "logsource": {
                    "category": "pipe_created",
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
                                "field": "PipeName",
                                "modifiers": ["startswith"],
                                "values": ["evil"],
                            }
                        ],
                    }
                ],
                "match_combinator": "all_of",
                "stage": 1,
            }
        )
    )
    yaml = draft.to_partial_yaml()
    assert "PipeName|startswith: evil" in yaml
    assert "category: pipe_created" in yaml
    assert "condition: match_1" in yaml
    # No title was set — it shouldn't show up at all (better than a
    # placeholder; the issue list already names what's missing).
    assert "title:" not in yaml


def test_partial_yaml_for_completely_empty_draft_returns_empty_string() -> None:
    """A bare draft (initial shell, no user input) should render as an
    empty string so the preview pane falls back to the placeholder.

    Emitting ``status: experimental / level: medium`` for an empty draft
    would imply the user picked those defaults, when they're really just
    Pydantic field defaults the user hasn't seen.
    """
    assert RuleDraft().to_partial_yaml() == ""


def test_partial_yaml_after_a_single_field_typed_renders_yaml() -> None:
    """As soon as the user touches *anything* — title, description,
    observation, etc. — the partial preview kicks in.
    """
    draft = RuleDraft()
    draft.title = "My rule"
    yaml = draft.to_partial_yaml()
    assert "title: My rule" in yaml
    # Defaults that ride along once the user has started.
    assert "status: experimental" in yaml
    assert "level: medium" in yaml


def test_partial_yaml_skips_empty_placeholder_items() -> None:
    """A blank in-progress row in a detection block should not appear in
    the YAML output at all (even though it's stored in the draft).
    """
    draft = RuleDraft.from_json(
        json.dumps(
            {
                "observation_id": "process_creation",
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
                                "values": ["\\evil.exe"],
                            },
                            # Placeholder row — should be skipped.
                            {"field": "", "modifiers": [], "values": []},
                        ],
                    }
                ],
                "match_combinator": "all_of",
                "stage": 1,
            }
        )
    )
    yaml = draft.to_partial_yaml()
    # The populated item shows.
    assert "Image|endswith: \\evil.exe" in yaml
    # The placeholder doesn't add a stray entry.
    assert yaml.count("match_1:") == 1


def test_partial_yaml_emits_any_of_blocks_as_list() -> None:
    """An ``any_of`` combinator on a block emits the list-of-mappings shape.

    Mirrors the strict serializer; the IOC-pack rule path (which sets
    combinator=any_of) should look identical in the partial preview.
    """
    draft = RuleDraft.from_json(
        json.dumps(
            {
                "observation_id": "dns_query",
                "logsource": {
                    "category": "dns_query",
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
                                "field": "QueryName",
                                "modifiers": ["endswith"],
                                "values": ["a.example.com"],
                            },
                            {
                                "field": "QueryName",
                                "modifiers": ["endswith"],
                                "values": ["b.example.com"],
                            },
                        ],
                    }
                ],
                "match_combinator": "all_of",
                "stage": 1,
            }
        )
    )
    yaml = draft.to_partial_yaml()
    # List-of-mappings shape: each item gets its own ``-`` entry.
    assert "- QueryName|endswith: a.example.com" in yaml
    assert "- QueryName|endswith: b.example.com" in yaml


# ---------------------------------------------------------------------------
# Composer-route integration: the preview pane uses partial YAML
# ---------------------------------------------------------------------------


def _stage_1_draft_no_metadata() -> str:
    return json.dumps(
        {
            "observation_id": "pipe_created",
            "logsource": {
                "category": "pipe_created",
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
                            "field": "PipeName",
                            "modifiers": ["startswith"],
                            "values": ["evil"],
                        }
                    ],
                }
            ],
            "match_combinator": "all_of",
            "stage": 1,
        }
    )


def test_stage_1_preview_pane_includes_partial_yaml(client: TestClient) -> None:
    """The preview-pane oob swap on Stage 1 should now contain a YAML
    block when the rule is partially built.
    """
    r = client.post(
        "/composer/update",
        data={"rule_state": _stage_1_draft_no_metadata(), "action": "no_op"},
    )
    body = r.text
    # Preview pane oob region.
    assert 'id="preview-pane"' in body
    # The partial YAML should be inline (Pygments wraps the keys/values
    # in classed spans, so check for the unique substrings that survive).
    assert "PipeName" in body
    assert "pipe_created" in body
    # Tier-1 issues for missing title/date should still be visible.
    assert "DRAFT_TITLE_MISSING" in body
    assert "DRAFT_DATE_MISSING" in body
    # The conversion tabs should still NOT have populated outputs (rule
    # isn't valid yet — conversion is gated on tier-1).
    assert "conversion-tabs-region" in body


def test_stage_1_preview_pane_does_not_render_yaml_when_completely_empty(
    client: TestClient,
) -> None:
    """A bare initial shell with nothing in the draft should fall back
    to the placeholder text — no point showing 'status: experimental\\nlevel: medium'
    on its own.
    """
    r = client.get("/mode/guided")
    body = r.text
    # Empty-draft rendering: the placeholder text is what users see first.
    assert "Canonical Sigma YAML appears here as the composer produces it" in body
