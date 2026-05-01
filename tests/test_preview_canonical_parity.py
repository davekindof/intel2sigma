"""Pattern II step 1 — preview/canonical parity property test.

The composer has two YAML emission codepaths:

* ``RuleDraft.to_partial_yaml()`` — the right-pane preview. Renders
  best-effort whatever state exists, no validation gate.
* ``to_yaml(draft.to_sigma_rule())`` — the canonical save artifact.
  Strict; fails if validation can't pass.

For drafts complete enough to validate, both paths SHOULD produce
the same YAML. They have not, twice now (filter-only condition
parity, ``8329d04``; modifier-dropdown phantom selection, B4) —
each bug a manifestation of the same underlying duplicate-
implementation problem.

This module is the property test that pins the contract. For every
fixture rule that loads cleanly:

    to_partial_yaml(draft) == to_yaml(draft.to_sigma_rule())

Pattern II step 1 (this commit): test scaffold + initial fixtures.
The whole module is marked ``xfail(strict=False)`` because we know
existing drifts will fail it — the test's job RIGHT NOW is to
surface those drifts, not to gate CI. Run the file locally to see
what currently disagrees.

Pattern II step 2 (the refactor): ``to_partial_yaml`` short-
circuits through ``to_sigma_rule`` for valid drafts so emission
goes through the same code as save. The xfail mark gets removed
in that commit; all parity assertions become hard gates.

Pattern II step 3 (cleanup): trim the partial fallback to use
canonical helpers exclusively for the incomplete-draft tail.
"""

from __future__ import annotations

import pytest

from intel2sigma.core.serialize import to_yaml
from intel2sigma.web.load import draft_from_yaml

# Whole-module xfail — see top-of-module note. Becomes a hard gate
# in Pattern II step 2.
pytestmark = pytest.mark.xfail(
    reason=(
        "Pattern II step 1 — measurement scaffold only. Existing drifts "
        "between to_partial_yaml and to_yaml(to_sigma_rule()) are expected "
        "to fail here until step 2's convergence refactor lands."
    ),
    strict=False,
)


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
# Sanity: the empty-draft early-return UX is preserved (separate concern
# from parity — partial path SHOULD differ from canonical when the draft
# is essentially empty, because canonical can't render anything at all).
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason="N/A — handled by separate test once xfail is lifted", strict=False)
def test_essentially_empty_draft_partial_yaml_returns_blank() -> None:
    """The fresh-shell case: ``to_partial_yaml() == ''`` for an untouched draft.

    This is the one behavioral guarantee Pattern II must explicitly
    preserve — the preview pane SHOWS blank when the user hasn't
    touched anything yet, rather than showing placeholder
    metadata. The canonical path would fail validation here; we
    don't compare against it. The fallback handles this case.

    Stub for now; concrete assertion lands when xfail is lifted in
    Pattern II step 2.
    """
    raise NotImplementedError("placeholder — replace in step 2")
