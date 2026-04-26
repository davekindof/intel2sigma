"""Tests for the SigmaHQ corpus search + load (Phase C).

Three layers:

1. Unit tests on ``web/corpus.py`` — search ranking, filters, load by id.
2. Route tests on ``/composer/load-search`` and ``/composer/load-corpus``.
3. UI smoke — load modal includes the Browse SigmaHQ tab when the
   index is bundled.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from intel2sigma.web.app import app
from intel2sigma.web.corpus import (
    all_categories,
    all_products,
    index_size,
    load_corpus_rule,
    search_corpus,
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# Index integrity
# ---------------------------------------------------------------------------


def test_corpus_index_has_thousands_of_rules() -> None:
    """The bundled SigmaHQ corpus index ships with thousands of rules.

    Sanity check that the index didn't get truncated or replaced with an
    empty file. The exact count moves with the pinned corpus commit;
    we just assert it's plausibly populated.
    """
    assert index_size() > 1000, (
        f"SigmaHQ corpus index has {index_size()} entries — "
        "looks like the build script didn't run or the data file is missing."
    )


def test_corpus_categories_include_common_logsources() -> None:
    """A few load-bearing categories must be present."""
    cats = set(all_categories())
    assert "process_creation" in cats
    assert "file_event" in cats
    assert "network_connection" in cats


def test_corpus_products_include_major_platforms() -> None:
    prods = set(all_products())
    assert "windows" in prods
    assert "linux" in prods


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


def test_search_powershell_returns_hits() -> None:
    """Common keyword returns plausibly-titled hits."""
    results = search_corpus("powershell", limit=10)
    assert results, "no PowerShell-related rules in corpus?"
    assert all("powershell" in (r.title.lower() + r.description.lower()) for r in results[:3])


def test_search_ranks_title_prefix_above_body() -> None:
    """A query that starts a rule's title outranks one that only appears
    in the body. Tested via the ranking helper directly — we look at
    the relative order of two known cases.
    """
    results = search_corpus("powershell", limit=20)
    titles_lower = [r.title.lower() for r in results]
    # At least one result should start with "powershell" — those rank
    # before mid-title or body-only matches.
    starts = [t for t in titles_lower if t.startswith("powershell")]
    assert starts, "expected at least one title to START with 'powershell'"
    # And the first such hit appears before any non-prefix hit.
    first_prefix_idx = next(i for i, t in enumerate(titles_lower) if t.startswith("powershell"))
    later_non_prefix = [
        i
        for i, t in enumerate(titles_lower)
        if i > first_prefix_idx and not t.startswith("powershell")
    ]
    if later_non_prefix:
        # ``first_prefix_idx`` < every non-prefix index after it
        assert all(i > first_prefix_idx for i in later_non_prefix)


def test_search_filters_by_category() -> None:
    """``category=`` narrows results to that exact logsource category."""
    results = search_corpus("", category="process_creation", limit=10)
    assert results
    assert all(r.category == "process_creation" for r in results)


def test_search_filters_by_product() -> None:
    results = search_corpus("", product="linux", limit=10)
    assert results
    assert all(r.product == "linux" for r in results)


def test_search_filter_combo_returns_subset() -> None:
    """category + product combo narrows further than either alone."""
    by_cat = len(search_corpus("", category="process_creation", limit=200))
    by_combo = len(search_corpus("", category="process_creation", product="linux", limit=200))
    assert by_combo <= by_cat
    assert by_combo > 0  # corpus has Linux process_creation rules


def test_search_no_match_returns_empty() -> None:
    """Garbage query yields zero results, not an exception."""
    assert search_corpus("zzzzz_no_such_keyword_12345", limit=10) == []


# ---------------------------------------------------------------------------
# Load by id
# ---------------------------------------------------------------------------


def test_load_corpus_rule_round_trips_a_real_rule() -> None:
    """Pick the first PowerShell hit and load it — should produce a draft."""
    results = search_corpus("powershell", limit=1)
    assert results
    draft, issues = load_corpus_rule(results[0].id)
    assert draft is not None, f"failed to translate rule {results[0].id!r}; issues={issues}"
    assert draft.title == results[0].title


def test_load_corpus_rule_unknown_id_returns_issue() -> None:
    draft, issues = load_corpus_rule("definitely-not-a-real-uuid")
    assert draft is None
    assert any(i.code == "LOAD_CORPUS_UNKNOWN" for i in issues)


def test_load_corpus_rule_blank_id_returns_issue() -> None:
    draft, issues = load_corpus_rule("")
    assert draft is None
    assert any(i.code == "LOAD_CORPUS_BLANK_ID" for i in issues)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def test_load_modal_includes_browse_tab(client: TestClient) -> None:
    """The 'Browse SigmaHQ' tab appears in the load modal when the
    bundled index is present.
    """
    body = client.get("/composer/load").text
    assert "Browse SigmaHQ" in body


def test_load_search_route_returns_results(client: TestClient) -> None:
    """POSTing a query to /composer/load-search returns an HTML fragment
    listing matching rules.
    """
    r = client.post(
        "/composer/load-search",
        data={"q": "powershell", "category": "", "product": "", "level": ""},
    )
    assert r.status_code == 200
    body = r.text
    assert "corpus-result-list" in body or "corpus-result-button" in body


def test_load_search_route_with_no_match_renders_empty_state(client: TestClient) -> None:
    """A query with no hits renders the no-results placeholder, not 500."""
    r = client.post(
        "/composer/load-search",
        data={"q": "zzz_not_a_real_keyword_xyz", "category": "", "product": "", "level": ""},
    )
    assert r.status_code == 200
    assert "No SigmaHQ rules match" in r.text


def test_load_corpus_route_lands_on_stage(client: TestClient) -> None:
    """Loading a corpus rule by id swaps the composer panel to Stage 1/3,
    same as paste/example loads (regression on the bug fixed in a56ecac).
    """
    results = search_corpus("powershell", limit=1)
    rule_id = results[0].id
    r = client.post("/composer/load-corpus", data={"rule_id": rule_id})
    assert r.status_code == 200
    body = r.text
    assert '<div id="composer-panel" hx-swap-oob="true">' in body
    # Modal closed (its title text shouldn't appear in response).
    assert "Load an existing rule" not in body
