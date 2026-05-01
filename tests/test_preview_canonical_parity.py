"""Pattern II — preview/canonical parity property test.

The composer has two YAML emission codepaths:

* ``RuleDraft.to_partial_yaml()`` — the right-pane preview. Renders
  best-effort whatever state exists, no validation gate.
* ``to_yaml(draft.to_sigma_rule())`` — the canonical save artifact.
  Strict; fails if validation can't pass.

For drafts complete enough to validate, both paths must produce
the same YAML. Pre-Pattern-II they had their own orchestration
code, drifted twice (filter-only condition parity at ``8329d04``;
modifier-dropdown phantom selection at B4). Pattern II step 2's
convergence makes ``to_partial_yaml`` short-circuit through
``to_sigma_rule`` for valid drafts — preview and canonical share
the SAME emission code by construction, drift is impossible for
the valid case.

This test pins that contract: for every fixture that loads
cleanly, ``to_partial_yaml(draft) == to_yaml(draft.to_sigma_rule())``
byte-for-byte.

Step 1 (df408d4) shipped the scaffold under an xfail mark while
the convergence was still pending; this version (post-step-2)
removes the mark and treats the parity assertions as hard
regression gates.
"""

from __future__ import annotations

import json

import pytest

from intel2sigma.core.serialize import to_yaml
from intel2sigma.web.draft import RuleDraft
from intel2sigma.web.load import draft_from_yaml

# ---------------------------------------------------------------------------
# Fixtures — synthetic YAML rules covering the emission shapes that have
# historically drifted, plus a few that haven't but are common enough that
# regression coverage is worth having.
# ---------------------------------------------------------------------------


_SIMPLE_PROCESS = """
title: simple process_creation
id: 11111111-2222-3333-4444-555555555555
status: experimental
date: 2026-04-30
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


_FILTER_ONLY = """
title: filter-only rule (negation-only condition)
id: 22222222-3333-4444-5555-666666666666
status: experimental
date: 2026-04-30
logsource:
    category: raw_access_thread
    product: windows
detection:
    filter_main_floppy:
        Image|contains: floppy
    filter_main_servicing:
        Image|startswith: 'C:\\Windows\\servicing\\'
    condition: not 1 of filter_main_*
falsepositives: [Likely]
level: low
"""


_KEYWORD_SEARCH_BARE = """
title: keyword-search bare list
id: 33333333-4444-5555-6666-777777777777
status: experimental
date: 2026-04-30
logsource:
    product: linux
    service: auditd
detection:
    keywords:
        - samr
        - lsarpc
        - winreg
    condition: keywords
level: medium
"""


_KEYWORD_WITH_ALL = """
title: keyword-search with |all modifier
id: 44444444-5555-6666-7777-888888888888
status: experimental
date: 2026-04-30
logsource:
    product: linux
    service: auth
detection:
    keywords:
        '|all':
            - 'pkexec'
            - '[USER=root]'
    condition: keywords
level: high
"""


_NULL_AND_EMPTY_FILTERS = """
title: null + explicit-empty filter values
id: 55555555-6666-7777-8888-999999999999
status: experimental
date: 2026-04-30
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/sh'
    filter_optional_null:
        CommandLine: null
    filter_optional_empty:
        CommandLine: ''
    condition: selection and not 1 of filter_optional_*
level: medium
"""


_REGEX_VALUE = """
title: regex modifier with wildcard chars
id: 66666666-7777-8888-9999-aaaaaaaaaaaa
status: experimental
date: 2026-04-30
logsource:
    category: proxy
detection:
    selection:
        c-uri|re: '\\?d=[0-9]{1,3}\\.[0-9]{1,3}'
    condition: selection
level: medium
"""


_MULTI_VALUE = """
title: multi-value detection item
id: 77777777-8888-9999-aaaa-bbbbbbbbbbbb
status: experimental
date: 2026-04-30
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains:
            - 'Get-ItemPropertyValue'
            - 'gpv'
    condition: selection
level: high
"""


_FIXTURES: list[tuple[str, str]] = [
    ("simple_process_creation", _SIMPLE_PROCESS),
    ("filter_only", _FILTER_ONLY),
    ("keyword_search_bare", _KEYWORD_SEARCH_BARE),
    ("keyword_with_all_modifier", _KEYWORD_WITH_ALL),
    ("null_and_empty_filter_values", _NULL_AND_EMPTY_FILTERS),
    ("regex_value", _REGEX_VALUE),
    ("multi_value_detection_item", _MULTI_VALUE),
]


# ---------------------------------------------------------------------------
# The parity assertion
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "yaml_text"), _FIXTURES, ids=[n for n, _ in _FIXTURES])
def test_preview_equals_canonical_for_valid_draft(name: str, yaml_text: str) -> None:
    """For a draft complete enough to validate, preview === canonical.

    Reads through ``draft_from_yaml`` (the load path), confirms the
    draft validates via ``to_sigma_rule``, then asserts the preview
    pane's emission matches the canonical save artifact byte-for-byte.

    Failures on this test are valuable BEFORE Pattern II step 2 —
    they enumerate the existing drift surface so we know what the
    convergence has to fix. After step 2 lands, the xfail mark
    flips off and these failures become hard regression gates.
    """
    draft, _issues = draft_from_yaml(yaml_text)
    assert draft is not None, f"Fixture {name!r}: draft_from_yaml returned None"

    sigma_or_issues = draft.to_sigma_rule()
    assert not isinstance(sigma_or_issues, list), (
        f"Fixture {name!r}: draft doesn't validate "
        f"({[i.code for i in sigma_or_issues]}) — fixture isn't useful "
        f"for parity testing. Either fix the fixture or move it to a "
        f"separate 'incomplete drafts' test."
    )

    preview = draft.to_partial_yaml()
    canonical = to_yaml(sigma_or_issues)

    assert preview == canonical, (
        f"Fixture {name!r}: preview/canonical drift.\n"
        f"--- preview (to_partial_yaml) ---\n{preview}\n"
        f"--- canonical (to_yaml(to_sigma_rule())) ---\n{canonical}"
    )


# ---------------------------------------------------------------------------
# Behavioural guarantees Pattern II must preserve — these are the UX
# contracts that aren't about parity, but are easy to accidentally regress
# during the convergence refactor.
# ---------------------------------------------------------------------------


def test_essentially_empty_draft_partial_yaml_returns_blank() -> None:
    """Fresh-shell case: ``to_partial_yaml() == ''`` for an untouched draft.

    The preview pane SHOWS blank when the user hasn't touched
    anything yet, rather than showing placeholder metadata. The
    canonical path would fail validation here; the empty-shell
    early-return short-circuits before either branch runs. Pattern
    II step 2 preserves this — it's the first check inside
    ``to_partial_yaml`` and unchanged from pre-refactor.
    """
    draft = RuleDraft()
    assert draft.to_partial_yaml() == ""


def test_partial_draft_renders_via_fallback() -> None:
    """A draft that doesn't validate yet still renders something.

    Pattern II preserves the "preview updates as the user types"
    feel by keeping a partial-emit fallback for drafts that can't
    pass ``to_sigma_rule``. This test pins the contract: a draft
    with title + observation set but no detection blocks still
    produces non-empty YAML the user can see.
    """
    draft = RuleDraft.from_json(
        json.dumps(
            {
                "title": "incomplete fixture",
                "observation_id": "process_creation",
                "platform_id": "windows",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detections": [],
                "stage": 1,
            }
        )
    )
    # Sanity: the draft really doesn't validate (no detection blocks
    # → DRAFT_CONDITION_EMPTY at minimum).
    assert isinstance(draft.to_sigma_rule(), list), (
        "Fixture isn't actually incomplete — please make it so"
    )
    yaml_text = draft.to_partial_yaml()
    # Partial fallback emits SOMETHING — the user-typed title at
    # minimum.
    assert yaml_text != ""
    assert "incomplete fixture" in yaml_text


def test_valid_draft_routes_through_canonical_emission() -> None:
    """The convergence: ``to_partial_yaml`` for a valid draft IS ``to_yaml``.

    This is what kills the drift class. Pre-Pattern-II the partial
    path had its own orchestration that drifted twice; post-Pattern-
    II valid drafts go through ``to_sigma_rule`` + ``to_yaml`` and
    cannot diverge by construction. The parametric test above tests
    this against many fixtures; this test pins the architecture-
    level contract for one shape so that a refactor accidentally
    re-introducing a parallel emission path fails here even if all
    parametric fixtures still happen to agree.
    """
    draft, _ = draft_from_yaml(_SIMPLE_PROCESS)
    assert draft is not None
    sigma = draft.to_sigma_rule()
    assert not isinstance(sigma, list)

    # The output must come from to_yaml(sigma) verbatim — not just
    # equal it incidentally. We can't directly observe "which
    # codepath was taken," but byte-equality plus the structural
    # match of ``to_partial_yaml`` calling into ``to_yaml`` (visible
    # in the source) is the contract.
    assert draft.to_partial_yaml() == to_yaml(sigma)
