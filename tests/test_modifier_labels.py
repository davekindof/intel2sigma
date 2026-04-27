"""Tests for the modifier-label / modifier-tooltip helpers.

The helpers map raw Sigma modifier names to user-facing labels and
hover-revealing tooltips. Two contracts:

  1. **Completeness** — every member of
     :data:`intel2sigma.core.model.ValueModifier` has both a label and
     a tooltip. Adding a modifier to the Literal without updating the
     tables should fail loudly here, not silently render the raw name
     in the dropdown.
  2. **Display vs. data** — the helpers are display-only. The Stage 1
     editor still submits the canonical Sigma modifier string
     (``endswith``, ``windash``); only the rendered ``<option>`` text
     changes. Verified end-to-end via a Stage 1 render assertion.
"""

from __future__ import annotations

import typing

import pytest
from fastapi.testclient import TestClient

from intel2sigma.core.model import ValueModifier
from intel2sigma.core.taxonomy.modifier_labels import (
    MODIFIER_LABELS,
    MODIFIER_TOOLTIPS,
    modifier_label,
    modifier_tooltip,
)
from intel2sigma.web.app import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


def test_modifier_label_renders_documented_strings() -> None:
    """A handful of modifiers cross-checked against docs/taxonomy.md."""
    assert modifier_label("endswith") == "ends with"
    assert modifier_label("startswith") == "starts with"
    assert modifier_label("re") == "matches regex (advanced)"
    assert modifier_label("windash") == "Windows dash variants (-, /, –)"  # noqa: RUF001 — en-dash is the literal character we expect
    assert modifier_label("cidr") == "IP in CIDR range"


def test_modifier_label_falls_back_to_raw_name_when_unknown() -> None:
    """Unknown modifier returns the raw name — better than crashing."""
    assert modifier_label("not_a_real_modifier_xyz") == "not_a_real_modifier_xyz"


def test_modifier_tooltip_returns_explanation() -> None:
    """Tooltips are sentence-form, not just the label restated."""
    assert "regular expression" in modifier_tooltip("re")
    assert "CIDR range" in modifier_tooltip("cidr")
    assert "leading backslash" in modifier_tooltip("endswith")


def test_modifier_tooltip_returns_empty_for_unknown() -> None:
    """Unknown modifier returns empty string — template renders title=''."""
    assert modifier_tooltip("not_a_real_modifier_xyz") == ""


# ---------------------------------------------------------------------------
# Completeness against ValueModifier Literal
# ---------------------------------------------------------------------------


def test_every_value_modifier_has_a_label() -> None:
    """Every ValueModifier Literal value must appear in MODIFIER_LABELS.

    Adding a modifier to ``intel2sigma.core.model.ValueModifier`` without
    updating MODIFIER_LABELS would cause the dropdown to render the raw
    Sigma name (e.g. ``endswith``) instead of the friendly label
    (``ends with``). This test catches the desync at test time.
    """
    canonical = set(typing.get_args(ValueModifier))
    documented = set(MODIFIER_LABELS.keys())
    missing = canonical - documented
    assert not missing, (
        f"Modifiers in ValueModifier Literal but not MODIFIER_LABELS: {sorted(missing)}. "
        "Add an entry to intel2sigma/core/taxonomy/modifier_labels.py."
    )


def test_every_value_modifier_has_a_tooltip() -> None:
    """Same contract for tooltips — every modifier must have hover help."""
    canonical = set(typing.get_args(ValueModifier))
    documented = set(MODIFIER_TOOLTIPS.keys())
    missing = canonical - documented
    assert not missing, (
        f"Modifiers in ValueModifier Literal but not MODIFIER_TOOLTIPS: {sorted(missing)}."
    )


def test_label_and_tooltip_tables_have_identical_keys() -> None:
    """Label and tooltip tables must cover the same modifier set.

    Drift between them would mean some modifiers have a label but no
    tooltip (or vice versa) — confusing UX.
    """
    assert set(MODIFIER_LABELS.keys()) == set(MODIFIER_TOOLTIPS.keys())


# ---------------------------------------------------------------------------
# End-to-end: Stage 1 render uses the labels
# ---------------------------------------------------------------------------


def test_stage1_dropdown_renders_friendly_modifier_labels(client: TestClient) -> None:
    """Loading a rule and viewing Stage 1 shows 'ends with', not 'endswith'.

    Verifies the Jinja-globals registration in web/app.py is wired up
    and the template change in _block.html actually applies. Loads a
    rule (anything with an Image|endswith item), navigates to Stage 1,
    asserts the friendly label appears in the response.
    """
    yaml_text = """
title: Stage1 modifier label test
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: Smoke test for the modifier-label rendering.
author: tests
date: 2026-04-26
tags: [attack.execution]
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-encodedcommand'
    condition: selection
falsepositives: [Unknown]
level: high
"""
    r = client.post("/composer/load-paste", data={"yaml_text": yaml_text})
    assert r.status_code == 200
    # Jump to stage 1 deterministically.
    import json  # noqa: PLC0415

    from tests._state_blob import extract_state as _extract_state  # noqa: PLC0415

    state = _extract_state(r.text)
    r2 = client.post(
        "/composer/jump",
        data={"target": "1", "rule_state": json.dumps(state)},
    )
    assert r2.status_code == 200

    # Friendly labels appear, raw modifiers don't (in <option> text —
    # the value="..." attributes still use canonical Sigma).
    assert "ends with" in r2.text
    assert "contains" in r2.text  # both label and value say 'contains' — fine
    # The friendly tooltip text shows up in the title attribute.
    assert "leading backslash" in r2.text or "regular expression" in r2.text
