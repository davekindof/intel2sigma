"""End-to-end tests for the composer state machine.

These exercise the full POST/response loop with TestClient so we verify
not just that routes return 200, but that the returned HTML + oob swaps
encode the expected state transitions. The RuleDraft JSON round-trip is
exercised as a side effect.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from intel2sigma.web.app import app
from tests._state_blob import STATE_BLOB_RE as _STATE_BLOB_RE
from tests._state_blob import extract_state as _extract_state


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# Initial shell
# ---------------------------------------------------------------------------


def test_initial_shell_renders_stage0(client: TestClient) -> None:
    r = client.get("/mode/guided")
    assert r.status_code == 200
    assert "Stage 0 — Pick an observation" in r.text
    state = _extract_state(r.text)
    assert state["stage"] == 0
    assert state["observation_id"] == ""
    assert state["detections"] == []


# ---------------------------------------------------------------------------
# Stage 0 → Stage 1 transition
# ---------------------------------------------------------------------------


def test_select_observation_advances_to_stage1(client: TestClient) -> None:
    # Use the empty state from the shell's initial render.
    shell = client.get("/mode/guided").text
    initial_state = _STATE_BLOB_RE.search(shell).group(1)
    # Unescape the entities so the POST body matches what the form would send.
    initial_state = initial_state.replace("&#34;", '"').replace("&#39;", "'").replace("&amp;", "&")

    r = client.post(
        "/composer/select-observation",
        data={"rule_state": initial_state, "observation_id": "process_creation"},
    )
    assert r.status_code == 200
    assert "Stage 1 — Compose detection" in r.text
    assert "A process was started" in r.text

    state = _extract_state(r.text)
    assert state["stage"] == 1
    assert state["observation_id"] == "process_creation"
    assert state["platform_id"] == "windows"
    assert state["logsource"]["category"] == "process_creation"
    assert state["logsource"]["product"] == "windows"


def test_select_observation_unknown_id_stays_at_stage0(client: TestClient) -> None:
    r = client.post(
        "/composer/select-observation",
        data={"rule_state": "{}", "observation_id": "does_not_exist"},
    )
    assert r.status_code == 200
    state = _extract_state(r.text)
    assert state["stage"] == 0
    assert state["observation_id"] == ""


# ---------------------------------------------------------------------------
# Stage 1 block + item operations
# ---------------------------------------------------------------------------


def _state_at_stage1(client: TestClient) -> str:
    r = client.post(
        "/composer/select-observation",
        data={"rule_state": "{}", "observation_id": "process_creation"},
    )
    state = _extract_state(r.text)
    return json.dumps(state)


def test_add_match_block_creates_match_1(client: TestClient) -> None:
    state = _state_at_stage1(client)
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    assert r.status_code == 200
    state = _extract_state(r.text)
    assert len(state["detections"]) == 1
    assert state["detections"][0]["name"] == "match_1"
    assert state["detections"][0]["is_filter"] is False


def test_add_filter_block_creates_filter_1(client: TestClient) -> None:
    state = _state_at_stage1(client)
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_filter"})
    state = _extract_state(r.text)
    assert len(state["detections"]) == 1
    assert state["detections"][0]["name"] == "filter_1"
    assert state["detections"][0]["is_filter"] is True


def test_two_match_blocks_auto_numbered(client: TestClient) -> None:
    state = _state_at_stage1(client)
    for _ in range(2):
        r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
        state = json.dumps(_extract_state(r.text))
    names = [b["name"] for b in json.loads(state)["detections"]]
    assert names == ["match_1", "match_2"]


def test_delete_block(client: TestClient) -> None:
    state = _state_at_stage1(client)
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    state = json.dumps(_extract_state(r.text))
    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "delete_block",
            "block_name": "match_1",
        },
    )
    state_obj = _extract_state(r.text)
    assert state_obj["detections"] == []


def test_add_item_then_set_field_and_value(client: TestClient) -> None:
    state = _state_at_stage1(client)
    # Add a match block
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    state = json.dumps(_extract_state(r.text))
    # Add an item to the block
    r = client.post(
        "/composer/update",
        data={"rule_state": state, "action": "add_item", "block_name": "match_1"},
    )
    state = json.dumps(_extract_state(r.text))
    # Set the field on that item. Field comes from the per-item input whose
    # name is "field::<block>::<index>".
    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_field",
            "block_name": "match_1",
            "item_index": "0",
            "field::match_1::0": "Image",
        },
    )
    state = json.dumps(_extract_state(r.text))
    # Set the modifier
    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_modifier",
            "block_name": "match_1",
            "item_index": "0",
            "modifier::match_1::0": "endswith",
        },
    )
    state = json.dumps(_extract_state(r.text))
    # Set the value
    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_value",
            "block_name": "match_1",
            "item_index": "0",
            "value::match_1::0": "\\powershell.exe",
        },
    )
    state_obj = _extract_state(r.text)
    item = state_obj["detections"][0]["items"][0]
    assert item["field"] == "Image"
    assert item["modifiers"] == ["endswith"]
    assert item["values"] == ["\\powershell.exe"]


def _add_match_item(client: TestClient, state: str) -> str:
    """Helper: add a match block + one empty item, return the JSON state."""
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    state = json.dumps(_extract_state(r.text))
    r = client.post(
        "/composer/update",
        data={"rule_state": state, "action": "add_item", "block_name": "match_1"},
    )
    return json.dumps(_extract_state(r.text))


def _post(client: TestClient, state: str, action: str, **fields: str) -> str:
    """Helper: post a single composer/update action and return the new state."""
    data = {"rule_state": state, "action": action, **fields}
    r = client.post("/composer/update", data=data)
    return json.dumps(_extract_state(r.text))


def test_set_field_preserves_modifier_when_allowed_list_includes_it(
    client: TestClient,
) -> None:
    """Picking a modifier and *then* editing the field name must not drop the modifier.

    B1 regression (filed during 0.3.0 testing). The pre-0.3.1
    implementation reset ``item.modifiers = []`` unconditionally on
    every ``set_field`` call. The field-name input fires htmx
    ``change, keyup delay:300ms``, so any keystroke landing after the
    user picked a modifier silently dropped that modifier — the
    emitted YAML lost ``|contains`` and the rule became a silent
    no-op (looks deployed, fires on no events).

    Repro shape:
      add item → set_modifier "contains" → set_field "Image"
      → modifiers MUST still be ["contains"]
    """
    state = _state_at_stage1(client)
    state = _add_match_item(client, state)
    state = _post(
        client,
        state,
        "set_modifier",
        block_name="match_1",
        item_index="0",
        **{"modifier::match_1::0": "contains"},
    )
    state = _post(
        client,
        state,
        "set_field",
        block_name="match_1",
        item_index="0",
        **{"field::match_1::0": "Image"},
    )
    state_obj = json.loads(state)
    item = state_obj["detections"][0]["items"][0]
    assert item["field"] == "Image"
    assert item["modifiers"] == ["contains"], (
        f"Modifier dropped on set_field: {item}. The handler reset "
        f"modifiers when it shouldn't have — Image's allowed_modifiers "
        f"in process_creation.yml include 'contains', so the user's "
        f"selection must survive."
    )


def test_set_field_preserves_modifier_in_freeform_observation(
    client: TestClient,
) -> None:
    """Freeform observations have no taxonomy spec — modifier is always preserved.

    B1 regression (freeform branch). When the user picks the
    "Custom logsource" path in Stage 0, ``observation_id =
    _freeform`` and there's no catalog to validate against. The
    user's modifier choice IS the source of truth. The handler
    must not erase it on any subsequent set_field call.

    Repro shape (the literal flow that surfaced the bug — auditd
    via custom logsource, saddr field, contains modifier):
      select-freeform → add item → set_modifier "contains"
      → set_field "saddr" → modifiers MUST still be ["contains"]
    """
    r = client.post(
        "/composer/select-freeform-observation",
        data={
            "rule_state": "{}",
            "logsource_product": "linux",
            "logsource_service": "auditd",
        },
    )
    state = json.dumps(_extract_state(r.text))
    state = _add_match_item(client, state)
    state = _post(
        client,
        state,
        "set_modifier",
        block_name="match_1",
        item_index="0",
        **{"modifier::match_1::0": "contains"},
    )
    state = _post(
        client,
        state,
        "set_field",
        block_name="match_1",
        item_index="0",
        **{"field::match_1::0": "saddr"},
    )
    state_obj = json.loads(state)
    item = state_obj["detections"][0]["items"][0]
    assert item["field"] == "saddr"
    assert item["modifiers"] == ["contains"]


def test_set_field_no_op_when_field_unchanged_preserves_modifier(
    client: TestClient,
) -> None:
    """Re-posting the same field name doesn't reset the modifier.

    The most direct B1 repro: htmx fires ``keyup delay:300ms`` on
    the field-name input even when the user hasn't changed the
    field — clicking out of the input or hitting Enter triggers a
    redundant set_field POST. Pre-0.3.1 these no-op posts still
    reset modifiers to []. The fix early-returns when
    ``new_field == item.field``.
    """
    state = _state_at_stage1(client)
    state = _add_match_item(client, state)
    state = _post(
        client,
        state,
        "set_field",
        block_name="match_1",
        item_index="0",
        **{"field::match_1::0": "Image"},
    )
    state = _post(
        client,
        state,
        "set_modifier",
        block_name="match_1",
        item_index="0",
        **{"modifier::match_1::0": "endswith"},
    )
    # Re-post the same field name — simulates a redundant keyup.
    state = _post(
        client,
        state,
        "set_field",
        block_name="match_1",
        item_index="0",
        **{"field::match_1::0": "Image"},
    )
    state_obj = json.loads(state)
    item = state_obj["detections"][0]["items"][0]
    assert item["modifiers"] == ["endswith"]


def test_modifier_dropdown_shows_sentinel_dash_when_modifier_unset(
    client: TestClient,
) -> None:
    """An item with ``modifiers=[]`` must render with the ``—`` sentinel
    option SELECTED — not silently default-display the first allowed
    modifier as if the user had picked it.

    B4 regression. Without the sentinel, HTML ``<select>`` defaults to
    the first ``<option>`` whenever nothing is ``selected``, so an item
    whose state is ``modifiers=[]`` displays as if the first allowed
    modifier (typically "contains") were picked. That made B1's
    silent modifier-drop invisible — the dropdown said "contains" so
    the user trusted it; the YAML emitted without ``|contains`` so
    the rule became a silent no-op.

    Contract: when ``item.modifiers == []`` AND a field is set, the
    rendered ``<option value="">—</option>`` must carry ``selected``.
    """
    state = _state_at_stage1(client)
    state = _add_match_item(client, state)
    # Set a field but don't touch the modifier — state stays
    # `modifiers=[]`, the case where the bug surfaced.
    r = client.post(
        "/composer/update",
        data={
            "rule_state": state,
            "action": "set_field",
            "block_name": "match_1",
            "item_index": "0",
            "field::match_1::0": "Image",
        },
    )
    body = r.text

    # Dash option is rendered AND has the ``selected`` attribute. Use
    # multi-line regex because the option's attributes may wrap.
    import re  # noqa: PLC0415

    sentinel_re = re.compile(
        r'<option\s+value=""\s+selected[^>]*>\s*—\s*</option>',
        re.DOTALL,
    )
    assert sentinel_re.search(body), (
        "Modifier dropdown is missing the selected ``—`` sentinel option "
        "for an item with empty modifiers. The dropdown will visually "
        "default to the first allowed modifier and lie about user intent."
    )

    # And the actual modifier options (e.g. "ends with") must NOT be
    # selected — only the sentinel.
    options_after_sentinel = body.split('<option value=""', 1)[-1]
    real_modifier_selected = re.search(
        r'<option value="(contains|endswith|startswith|all|re)"[^>]*selected',
        options_after_sentinel,
    )
    assert real_modifier_selected is None, (
        f"A real modifier option carries 'selected' alongside the "
        f"sentinel: {real_modifier_selected.group(0) if real_modifier_selected else ''}"
    )


def test_modifier_dropdown_marks_picked_modifier_selected_not_sentinel(
    client: TestClient,
) -> None:
    """When the user picks a real modifier, that option carries
    ``selected``, not the sentinel.
    """
    state = _state_at_stage1(client)
    state = _add_match_item(client, state)
    state = _post(
        client,
        state,
        "set_field",
        block_name="match_1",
        item_index="0",
        **{"field::match_1::0": "Image"},
    )
    r = client.post(
        "/composer/update",
        data={
            "rule_state": json.dumps(json.loads(state)),
            "action": "set_modifier",
            "block_name": "match_1",
            "item_index": "0",
            "modifier::match_1::0": "endswith",
        },
    )
    body = r.text

    import re  # noqa: PLC0415

    # Sentinel must NOT carry selected now.
    sentinel_unselected = re.search(
        r'<option\s+value=""(?![^>]*selected)[^>]*>\s*—\s*</option>',
        body,
    )
    assert sentinel_unselected is not None, (
        "Sentinel ``—`` option is still selected even though the user "
        "picked ``endswith`` — only one option can be selected at a time."
    )
    # The endswith option must carry selected.
    endswith_selected = re.search(
        r'<option\s+value="endswith"[^>]*selected',
        body,
    )
    assert endswith_selected is not None, (
        "User-picked modifier ``endswith`` is missing the ``selected`` attribute on render."
    )


def test_set_field_resets_modifier_when_new_field_disallows_it(
    client: TestClient,
) -> None:
    """When the new field's allowed-modifier list excludes the current
    modifier, the reset is justified — that's the original 'changing
    the field invalidates the modifier' intent, just narrowed.

    process_creation's ``IntegrityLevel`` field is type=enum with
    allowed_modifiers=[exact] only. Switching from a string field
    that had ``contains`` over to ``IntegrityLevel`` must reset
    because ``contains`` is genuinely illegal there.
    """
    state = _state_at_stage1(client)
    state = _add_match_item(client, state)
    state = _post(
        client,
        state,
        "set_field",
        block_name="match_1",
        item_index="0",
        **{"field::match_1::0": "CommandLine"},
    )
    state = _post(
        client,
        state,
        "set_modifier",
        block_name="match_1",
        item_index="0",
        **{"modifier::match_1::0": "contains"},
    )
    state = _post(
        client,
        state,
        "set_field",
        block_name="match_1",
        item_index="0",
        **{"field::match_1::0": "IntegrityLevel"},
    )
    state_obj = json.loads(state)
    item = state_obj["detections"][0]["items"][0]
    assert item["field"] == "IntegrityLevel"
    # IntegrityLevel.allowed_modifiers = [exact]; "contains" is illegal,
    # so the reset is correct here.
    assert item["modifiers"] == []


def test_restart_returns_to_stage0(client: TestClient) -> None:
    state = _state_at_stage1(client)
    r = client.post("/composer/restart", data={"rule_state": state})
    state_obj = _extract_state(r.text)
    assert state_obj["stage"] == 0
    assert state_obj["observation_id"] == ""


# ---------------------------------------------------------------------------
# Preview rendering
# ---------------------------------------------------------------------------


def test_preview_shows_yaml_when_draft_is_complete(client: TestClient) -> None:
    """Build up a complete draft; preview pane should contain highlighted YAML
    (and not the "Cannot build a rule" issue messages)."""
    # Get to stage 1
    state = _state_at_stage1(client)

    # Add a match block
    r = client.post("/composer/update", data={"rule_state": state, "action": "add_match"})
    state = json.dumps(_extract_state(r.text))

    # Add an item
    r = client.post(
        "/composer/update",
        data={"rule_state": state, "action": "add_item", "block_name": "match_1"},
    )
    state = json.dumps(_extract_state(r.text))

    # Set field + modifier + value
    for action, extra in [
        ("set_field", {"field::match_1::0": "Image"}),
        ("set_modifier", {"modifier::match_1::0": "endswith"}),
        ("set_value", {"value::match_1::0": "\\evil.exe"}),
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

    # At this point the draft lacks title + date, so preview should still
    # show issues but at least the DRAFT_CONDITION_EMPTY error should be gone.
    assert "DRAFT_CONDITION_EMPTY" not in r.text
    assert "DRAFT_TITLE_MISSING" in r.text  # title still missing
