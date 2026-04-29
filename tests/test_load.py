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
    # to the modal target. Wrapper must carry id + class (the class is
    # what makes the panel actually scrollable; the dogfood-2026-04-26
    # bug was a class-less wrapper that stripped overflow:auto on swap).
    assert 'id="composer-panel"' in r.text
    assert 'class="composer-panel"' in r.text
    assert 'hx-swap-oob="true"' in r.text
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
    # Tag, id, and class all matter — see test_load_response_preserves_
    # pane_classes_for_oob_swap below for the full contract.
    assert 'id="composer-panel"' in body
    assert 'class="composer-panel"' in body
    assert 'hx-swap-oob="true"' in body
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


# ---------------------------------------------------------------------------
# Regression: P1 — multi-selection rules use actual block names, not globs
# ---------------------------------------------------------------------------
#
# The exact shape of the APT27 Emissary Panda rule from screenshot 1 of the
# load-bug dogfood report. Two ``selection_*`` match blocks, condition
# ``all of selection_*``. Before the fix, our ``_compose_condition`` emitted
# ``all of match_*`` (a glob that doesn't resolve against ``selection_*``
# blocks) when the loader didn't repopulate ``condition_tree``. That broke
# pySigma conversion and false-fired h-050.

APT27_STYLE_YAML = """
title: APT27 - Emissary Panda Activity
id: 9aa01d62-7667-4d3b-acb8-8cb5103e2014
status: test
description: Detects DLL side-loading malware used by APT27 (Emissary Panda).
author: Florian Roth (Nextron Systems)
date: 2018-09-03
tags:
  - attack.privilege-escalation
  - attack.t1574.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_sllauncher:
        ParentImage|endswith: '\\sllauncher.exe'
        Image|endswith: '\\svchost.exe'
    selection_svchost:
        ParentImage|contains: '\\AppData\\Roaming\\'
        Image|endswith: '\\svchost.exe'
        CommandLine|contains: '-k'
    condition: all of selection_*
falsepositives:
  - Unlikely
level: critical
"""


def test_load_multiselection_rule_emits_actual_block_names_in_condition() -> None:
    """The composed condition must reference actual block names, not match_*.

    Regression for the APT27 dogfood case: load a rule whose blocks are
    named ``selection_*``, serialize back to canonical YAML, assert the
    condition references the loaded names — the auto-composer was
    emitting ``all of match_*`` regardless, which doesn't resolve.
    """
    from intel2sigma.core.serialize import to_yaml  # noqa: PLC0415

    draft, issues = draft_from_yaml(APT27_STYLE_YAML)
    assert draft is not None
    # Loader-level issues are fine (e.g. taxonomy match is informational);
    # what's not fine is condition desync.
    assert all(i.code != "LOAD_PARSE_FAILED" for i in issues)

    # Block names preserved verbatim from the source rule.
    names = sorted(b.name for b in draft.detections)
    assert names == ["selection_sllauncher", "selection_svchost"]

    # Convert draft → strict SigmaRule → YAML and inspect the condition.
    sigma = draft.to_sigma_rule()
    assert not isinstance(sigma, list), f"Draft should validate; got issues: {sigma}"
    yaml_text = to_yaml(sigma)
    # Condition must reference the actual block names. Either form is
    # acceptable: enumerated ``selection_a and selection_b`` (current
    # synthesis) or a future glob-aware form like ``all of selection_*``.
    # What's NOT acceptable is ``match_*`` — the regression we're locking.
    assert "match_*" not in yaml_text, (
        f"Condition still references hardcoded match_* glob; expected "
        f"actual block names. YAML:\n{yaml_text}"
    )
    assert "selection_sllauncher" in yaml_text
    assert "selection_svchost" in yaml_text


def test_load_multiselection_rule_does_not_false_fire_h050() -> None:
    """h-050 (undefined selection) must not fire on a loaded multi-selection rule.

    Before the fix, loading the APT27-style rule produced a condition
    referencing ``match_*`` while the rule's blocks were named
    ``selection_*`` — h-050 correctly flagged the broken reference, but
    the rule was authored fine; the loader created the bug.
    """
    from intel2sigma.core.heuristics.checks.condition_integrity import (  # noqa: PLC0415
        condition_references_undefined,
    )

    draft, _issues = draft_from_yaml(APT27_STYLE_YAML)
    assert draft is not None
    sigma = draft.to_sigma_rule()
    assert not isinstance(sigma, list)
    assert condition_references_undefined(sigma) is None


def test_load_two_match_two_filter_rule_enumerates_both_sides() -> None:
    """A 2-match + 2-filter rule should enumerate names on both sides.

    Locks in that the synthesis emits ``(m1 and m2) and not (f1 or f2)``-
    shaped conditions for the multi-each case. Pre-fix this would have
    been ``all of match_* and not 1 of filter_*`` with hardcoded globs.
    """
    yaml_text = """
title: Two-of-each test rule
id: 11111111-2222-3333-4444-555555555555
status: test
description: Test fixture for the multi-each condition synthesis path.
author: intel2sigma tests
date: 2026-04-26
tags: [attack.execution]
logsource:
    category: process_creation
    product: windows
detection:
    selection_a:
        Image|endswith: '\\evil.exe'
    selection_b:
        CommandLine|contains: '-bad'
    filter_admin:
        User|contains: SYSTEM
    filter_sccm:
        ParentImage|contains: '\\ccmexec.exe'
    condition: all of selection_* and not 1 of filter_*
falsepositives: [Unlikely]
level: high
"""
    from intel2sigma.core.serialize import to_yaml  # noqa: PLC0415

    draft, _issues = draft_from_yaml(yaml_text)
    assert draft is not None
    sigma = draft.to_sigma_rule()
    assert not isinstance(sigma, list)
    rendered = to_yaml(sigma)

    # Neither glob form should leak through.
    assert "match_*" not in rendered
    assert "filter_*" not in rendered
    # All four block names must appear in the condition.
    for name in ("selection_a", "selection_b", "filter_admin", "filter_sccm"):
        assert name in rendered


# ---------------------------------------------------------------------------
# Regression: P2 — unknown logsource routes to freeform, not Stage 0 fallback
# ---------------------------------------------------------------------------


ANTIVIRUS_RULE_YAML = """
title: Antivirus Exploitation Framework Detection
id: 238527ad-3c2c-4e4f-a1f6-92fd63adb864
status: stable
description: Detects a relevant Antivirus alert that reports an exploitation framework.
references:
  - https://example.invalid/ref
author: Florian Roth (Nextron Systems)
date: 2018-09-09
tags:
  - attack.execution
  - attack.t1203
logsource:
    category: antivirus
detection:
    selection:
        Signature|contains:
          - CobaltStrike
          - Meterpreter
          - PowerSploit
    condition: selection
falsepositives:
  - Unlikely
level: high
"""


def test_load_unknown_category_routes_to_freeform_observation() -> None:
    """An ``antivirus`` logsource isn't in our taxonomy — must use _freeform.

    Regression for the dogfood case where loading the antivirus rule
    left ``observation_id=""`` and the render fallback dropped to
    Stage 0 with a stale breadcrumb. The fix routes to ``_freeform``
    instead, so the breadcrumb / stage stay consistent.
    """
    draft, issues = draft_from_yaml(ANTIVIRUS_RULE_YAML)
    assert draft is not None

    assert draft.observation_id == "_freeform"
    assert draft.logsource.category == "antivirus"
    # The informational issue stays — user should know the field
    # catalogue isn't validating their inputs.
    codes = {i.code for i in issues}
    assert "LOAD_OBSERVATION_UNKNOWN" in codes


def test_load_unknown_category_breadcrumb_stays_consistent(client: TestClient) -> None:
    """Loading an unknown-category rule must not desync breadcrumb from content.

    Before the fix, the antivirus rule landed with ``stage=3,
    observation_id=""`` — render dropped to Stage 0 markup while the
    breadcrumb still reported Stage 3. With the fix, the same rule
    lands with ``observation_id=_freeform`` and the rendered Stage 3
    review markup matches the breadcrumb.
    """
    r = client.post("/composer/load-paste", data={"yaml_text": ANTIVIRUS_RULE_YAML})
    assert r.status_code == 200
    state = _extract_state(r.text)
    assert state["observation_id"] == "_freeform"
    # Stage advanced past 0; breadcrumb and rendered content should agree.
    assert state["stage"] >= 1
    # When a rule lands in review, the response html should contain the
    # Stage 3 / Stage 1 markup, not Stage 0's "Pick an observation" header.
    if state["stage"] == 3:
        assert "Stage 3 — Review" in r.text
        assert "Pick an observation" not in r.text
    elif state["stage"] == 1:
        assert "Stage 1" in r.text
        assert "Pick an observation" not in r.text


# ---------------------------------------------------------------------------
# Regression: Stage 1 detection editor renders ALL values, not just values[0]
# ---------------------------------------------------------------------------


def test_stage1_renders_every_value_of_a_multivalue_item(client: TestClient) -> None:
    """A loaded rule with ``Field|contains: [a, b, c]`` must show all values.

    Regression for the dogfood symptom on the antivirus rule: the
    detection editor at Stage 1 only showed the first value of a
    multi-value item (``Backdoor.Cobalt``) because ``_block.html``
    rendered ``<input value="{{ values[0] }}">``. The remaining 20+
    values were stored in the draft (the prose summary listed them
    all, the right-pane YAML rendered them all) but were neither
    visible nor editable in the Stage 1 editor. Fixed by rendering
    a textarea with one value per line.
    """
    # Load + jump to Stage 1 so the detection editor runs.
    r = client.post("/composer/load-paste", data={"yaml_text": ANTIVIRUS_RULE_YAML})
    assert r.status_code == 200
    state_blob = _extract_state(r.text)

    # Re-post with action=jump to land on stage 1 deterministically.
    import json  # noqa: PLC0415

    r2 = client.post(
        "/composer/jump",
        data={"target": "1", "rule_state": json.dumps(state_blob)},
    )
    assert r2.status_code == 200

    # Every value from the antivirus fixture must appear in the
    # rendered Stage 1 HTML — they're inside the textarea body, one per
    # line. The contains check is sufficient because the textarea wraps
    # them in a single element rather than splitting across attributes.
    for expected_value in ("CobaltStrike", "Meterpreter", "PowerSploit"):
        assert expected_value in r2.text, (
            f"Expected value {expected_value!r} missing from Stage 1 render. "
            f"Was the multi-value textarea-rendering regressed?"
        )

    # Defence-in-depth: the textarea element itself should be present
    # (not the old <input>). Catches a future revert that switches back
    # to single-value rendering.
    assert 'class="item-value"' in r2.text
    assert "<textarea" in r2.text


def test_load_response_preserves_pane_classes_for_oob_swap(client: TestClient) -> None:
    """OOB-swap wrappers must keep ``composer-panel`` + ``preview-pane-primary``.

    Regression for the dogfood symptom: loading a long SigmaHQ rule
    (e.g. the antivirus rule with 30+ Signature|contains values) broke
    scrolling on BOTH panes. Root cause: htmx oob-swap replaces the
    whole outer element, and the pre-fix wrappers were:

        <div id="composer-panel" hx-swap-oob="true">...</div>
        <div id="preview-pane" hx-swap-oob="true">...</div>

    No class attribute. After swap, the elements lost
    ``class="composer-panel"`` / ``class="preview-pane-primary"`` and
    therefore lost their CSS sizing rules (overflow: auto; flex; min-
    height: 0). Long loaded rules then expanded the element to content
    height, defeating per-pane scroll on both sides. Composed rules
    rarely hit the overflow threshold during normal use, masking the
    bug for everything but the load path.

    Fix: wrappers carry the same class + tag as the element they
    replace. This test asserts that contract on the load-paste path;
    same contract holds for ``_render_stage`` per inline comment.
    """
    r = client.post("/composer/load-paste", data={"yaml_text": ANTIVIRUS_RULE_YAML})
    assert r.status_code == 200

    # The oob wrapper for composer-panel: must be a <section> with the
    # composer-panel class so its overflow-y: auto applies.
    assert 'id="composer-panel"' in r.text
    assert 'class="composer-panel"' in r.text
    # The oob wrapper for preview-pane: must carry preview-pane-primary
    # so its flex/overflow/min-height rules apply.
    assert 'id="preview-pane"' in r.text
    assert 'class="preview-pane-primary"' in r.text


def test_stage1_set_value_splits_textarea_lines(client: TestClient) -> None:
    """Server-side set_value must split textarea content into list[str].

    The textarea submits multi-line content as a single string with
    newlines. ``_set_item_value`` splits on newlines and drops empty
    lines so a trailing newline doesn't produce a phantom empty value.
    """
    # Load the antivirus rule so we have a multi-value item to mutate.
    r = client.post("/composer/load-paste", data={"yaml_text": ANTIVIRUS_RULE_YAML})
    state_blob = _extract_state(r.text)

    # Find the loaded block + item shape from the state blob.
    block = state_blob["detections"][0]
    block_name = block["name"]

    # Submit a textarea-shaped value with three values + trailing newline.
    import json  # noqa: PLC0415

    new_values = "Mimikatz\nCobaltStrike\nEmpire\n"
    r2 = client.post(
        "/composer/update",
        data={
            "action": "set_value",
            "block_name": block_name,
            "item_index": "0",
            f"value::{block_name}::0": new_values,
            "rule_state": json.dumps(state_blob),
        },
    )
    assert r2.status_code == 200

    new_state = _extract_state(r2.text)
    new_block = next(b for b in new_state["detections"] if b["name"] == block_name)
    new_item = new_block["items"][0]
    # Three real values, no phantom empty entry from the trailing newline.
    assert new_item["values"] == ["Mimikatz", "CobaltStrike", "Empire"]


# ---------------------------------------------------------------------------
# L2-P1a regression: literal whitespace values survive load
# ---------------------------------------------------------------------------


def test_load_preserves_literal_whitespace_value() -> None:
    """A SigmaHQ rule with ``CommandLine|endswith: ' '`` round-trips intact.

    The macOS masquerading-via-trailing-space pattern at SigmaHQ
    rule b6e2a2e3-2d30-43b1-a4ea-071e36595690 ("Space After Filename")
    intentionally matches values that end with a literal space. The
    original draft model had ``str_strip_whitespace=True`` from the
    project-wide _Model config, which silently nuked the space before
    it reached the strict SigmaRule. Tier-1 then fired
    DRAFT_ITEM_VALUES_MISSING because the values list was effectively
    empty.

    The L1 corpus audit (e9a040b) found 55+ corpus rules failing
    this way. L2-P1a fixed it by overriding str_strip_whitespace to
    False on DetectionItem and DetectionItemDraft, plus relaxing the
    tier-1 ``values_set`` check from ``v.strip() != ""`` to
    ``v != ""`` so genuine empty strings still trip but meaningful
    whitespace doesn't.

    This test loads the literal Sigma corpus rule shape and asserts
    the value survives all the way to to_sigma_rule().
    """
    yaml_text = """
title: Space After Filename - macOS
id: b6e2a2e3-2d30-43b1-a4ea-071e36595690
status: test
description: Detects masquerade-by-trailing-space.
author: tests
date: 2021-11-20
tags: [attack.defense-evasion, attack.t1036.006]
logsource:
    category: process_creation
    product: macos
detection:
    selection1:
        CommandLine|endswith: ' '
    selection2:
        Image|endswith: ' '
    condition: 1 of selection*
falsepositives: [Mistyped commands]
level: low
"""
    draft, _issues = draft_from_yaml(yaml_text)
    assert draft is not None
    # Literal space preserved at the draft level.
    assert draft.detections[0].items[0].values == [" "]
    assert draft.detections[1].items[0].values == [" "]
    # And survives the round-trip through to_sigma_rule strict coercion.
    sigma = draft.to_sigma_rule()
    assert not isinstance(sigma, list), f"to_sigma_rule failed: {sigma}"
    assert sigma.detections[0].items[0].values == [" "]
    assert sigma.detections[1].items[0].values == [" "]


# ---------------------------------------------------------------------------
# L2-P1c regression: filter-only rules ("fire on everything except…")
# ---------------------------------------------------------------------------


def test_load_filter_only_rule_composes_negation_only_condition() -> None:
    """A Sigma rule with only filter blocks composes to ``not (f1 or f2)``.

    SigmaHQ rule db809f10-56ce-4420-8c86-d6a7d793c79c ("Potential
    Defense Evasion Via Raw Disk Access By Uncommon Tools") has 13
    filter_main_* / filter_optional_* blocks and zero match blocks.
    The Sigma idiom is "fire on every event from this logsource
    unless any filter matches" — the rule's exclusionary intent IS
    its detection logic.

    Pre-L2-P1c, ``_compose_condition`` returned ``None`` when there
    were no match blocks, which tripped DRAFT_CONDITION_EMPTY at
    tier-1 and made Stage 2 (Metadata) inaccessible from a loaded
    rule of this shape. The dogfood report on 2026-04-26 surfaced
    this as a real Stage-navigation bug; the L1 audit (e9a040b)
    confirmed it as the lone DRAFT_CONDITION_EMPTY exception in the
    full 3,708-rule corpus.

    L2-P1c adds the filter-only branch: emit ``not filter_a``
    (single) or ``not (filter_a or filter_b)`` (multiple), mirroring
    the filter-side handling for match-bearing rules.
    """
    yaml_text = """
title: Filter-only rule fixture
id: 11111111-9999-aaaa-bbbb-cccccccccccc
status: test
description: Fixture for the filter-only-rule branch of _compose_condition.
author: tests
date: 2026-04-26
tags: [attack.defense-evasion]
logsource:
    category: raw_access_thread
    product: windows
detection:
    filter_main_floppy:
        Device|contains: floppy
    filter_main_servicing:
        Image|startswith: 'C:\\Windows\\servicing\\'
    condition: not 1 of filter_main_*
falsepositives: [Likely]
level: low
"""
    draft, _issues = draft_from_yaml(yaml_text)
    assert draft is not None
    # All blocks are filters (loader's is_filter heuristic on
    # name.startswith("filter") catches all the filter_main_* shapes).
    assert all(b.is_filter for b in draft.detections)
    # to_sigma_rule must succeed — no DRAFT_CONDITION_EMPTY any more.
    sigma = draft.to_sigma_rule()
    assert not isinstance(sigma, list), f"to_sigma_rule failed: {sigma}"
    # The composed condition is "not (filter_a or filter_b)" shape.
    # Render to YAML and assert the negation-only string.
    from intel2sigma.core.serialize import to_yaml  # noqa: PLC0415

    yaml_out = to_yaml(sigma)
    assert "filter_main_floppy" in yaml_out
    assert "filter_main_servicing" in yaml_out
    assert "not (" in yaml_out  # the negation-of-OR shape


def test_load_preserves_null_filter_value() -> None:
    """``Field: null`` round-trips through the loader as ``None`` on values.

    SigmaHQ rule 0250638a-… ("Suspicious Browser Child Process —
    MacOS") and 26 other corpus rules use ``CommandLine: null`` to
    skip events whose command line is null/absent. pySigma exposes
    these as ``SigmaNull`` instances; the L2-P1d loader translates
    them to Python ``None``, which the strict ``DetectionItem`` now
    accepts and the serializer emits back as YAML null.

    Pre-L2-P1d, ``str(SigmaNull())`` produced a ``<sigma.types.
    SigmaNull object at 0x…>`` repr that got stored as a literal
    value, breaking 27+ corpus rules at the round-trip boundary.
    """
    yaml_text = """
title: Null-filter fixture
id: 22222222-9999-aaaa-bbbb-dddddddddddd
status: test
date: 2026-04-27
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/sh'
    filter_optional_null:
        CommandLine: null
    condition: selection and not filter_optional_null
"""
    draft, issues = draft_from_yaml(yaml_text)
    assert draft is not None
    # No translator warnings — null is supported, not a fidelity loss.
    surprising = [i for i in issues if i.code != "LOAD_OBSERVATION_UNKNOWN"]
    assert surprising == [], f"unexpected load issues: {surprising}"
    # Loader stored None for the null value.
    null_block = next(b for b in draft.detections if b.name == "filter_optional_null")
    assert null_block.items[0].values == [None]
    # Round-trips to a strict rule and emits as YAML null.
    sigma = draft.to_sigma_rule()
    assert not isinstance(sigma, list), f"to_sigma_rule failed: {sigma}"

    from intel2sigma.core.serialize import to_yaml  # noqa: PLC0415

    yaml_out = to_yaml(sigma)
    # ruamel emits None as bare-colon (``CommandLine:``) — both that
    # and ``CommandLine: null`` parse back to SigmaNull in pySigma.
    assert "CommandLine:" in yaml_out
    assert "<sigma.types" not in yaml_out  # the broken pre-P1d shape


def test_load_preserves_empty_string_filter_value() -> None:
    """``Field: ''`` round-trips as the literal empty string.

    Companion to the null case: same SigmaHQ rule pattern uses
    ``CommandLine: ''`` to skip events whose command line is the
    literal empty string. Distinct semantics from null (the Sigma
    spec treats them differently); both must round-trip.

    Pre-L2-P1d, the tier-1 ``values_set`` check filtered out
    zero-length strings, so the rule failed validation with
    DRAFT_ITEM_VALUES_MISSING despite carrying explicit user intent
    in the source YAML.
    """
    yaml_text = """
title: Empty-string-filter fixture
id: 33333333-9999-aaaa-bbbb-eeeeeeeeeeee
status: test
date: 2026-04-27
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/sh'
    filter_optional_empty:
        CommandLine: ''
    condition: selection and not filter_optional_empty
"""
    draft, _issues = draft_from_yaml(yaml_text)
    assert draft is not None
    empty_block = next(b for b in draft.detections if b.name == "filter_optional_empty")
    assert empty_block.items[0].values == [""]
    sigma = draft.to_sigma_rule()
    assert not isinstance(sigma, list), f"to_sigma_rule failed: {sigma}"

    from intel2sigma.core.serialize import to_yaml  # noqa: PLC0415

    yaml_out = to_yaml(sigma)
    # The canonical emission uses single-quoted empty string.
    assert "CommandLine: ''" in yaml_out
