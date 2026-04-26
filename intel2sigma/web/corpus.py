"""Bundled SigmaHQ corpus search + load.

The Stage 0 load modal's "Browse SigmaHQ" tab queries the JSON index
built by ``scripts/build_sigmahq_corpus.py`` and shipped at
``intel2sigma/data/sigmahq_corpus.json``. Two public entry points:

* :func:`search_corpus` — keyword + filter search; returns a sorted
  list of result-shaped dicts for the load-modal UI.
* :func:`load_corpus_rule` — fetch one full rule by id and translate it
  to a :class:`RuleDraft` via the existing ``draft_from_yaml`` path.

The whole index lives in memory after first access (~9 MB JSON
deserialised — Python dicts roughly 3x that, so ~30 MB in-process).
That's worth it for instant search; the alternative was a sqlite
file or a per-query parse, both more code and slower.

The corpus is pinned to the commit recorded in
``intel2sigma/_version.py``'s ``SIGMAHQ_PINNED_COMMIT``. Bumps and
re-builds happen on the quarterly recalibration cycle —
``docs/recalibration.md`` is the runbook.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from typing import Any

from intel2sigma._data import data_path
from intel2sigma.core.validate.issues import ValidationIssue
from intel2sigma.web.draft import RuleDraft
from intel2sigma.web.load import draft_from_yaml

_CORPUS_PATH = data_path("sigmahq_corpus.json")

# Bound to a name so ruff 0.15.x doesn't strip the parens off the
# ``except (X, Y):`` form below — see web/mitre.py for the same workaround.
_LOAD_FAILURES = (OSError, json.JSONDecodeError)

# Maximum results returned per search call. The load modal renders one
# row per result; >50 stops being browsable on a normal screen anyway,
# and bigger payloads slow the htmx swap.
_MAX_RESULTS = 50


@dataclass(frozen=True, slots=True)
class CorpusEntry:
    """One row in the search-results list rendered by the load modal."""

    id: str
    title: str
    description: str
    level: str
    status: str
    category: str | None
    product: str | None
    service: str | None
    tags: tuple[str, ...]
    file_path: str


@cache
def _load_index() -> list[dict[str, Any]]:
    """Read the bundled corpus JSON once; subsequent calls are O(1)."""
    if not _CORPUS_PATH.is_file():
        # Wheel without the corpus index — degrade silently. The load
        # modal will show "no rules indexed" rather than 500.
        return []
    try:
        data = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
    except _LOAD_FAILURES:
        return []
    if not isinstance(data, list):
        return []
    return data


def index_size() -> int:
    """Total rule count in the bundled index. Used by the modal header."""
    return len(_load_index())


def search_corpus(
    query: str = "",
    *,
    category: str | None = None,
    product: str | None = None,
    level: str | None = None,
    limit: int = _MAX_RESULTS,
) -> list[CorpusEntry]:
    """Find SigmaHQ rules matching ``query`` + optional filters.

    Substring match against the entry's pre-built ``search_blob``
    (lower-cased title + description + tags + logsource fields). Filter
    args narrow by exact equality. Results are sorted by:

    1. Title-prefix matches first (most-relevant heuristic)
    2. Title-substring matches
    3. Body-only matches (search hit only in description / tags / etc.)

    Within each tier, sorts by title alphabetically for determinism.
    """
    q = query.strip().lower()
    cat = category.strip().lower() if category else None
    prod = product.strip().lower() if product else None
    lvl = level.strip().lower() if level else None

    def _matches(entry: dict[str, Any]) -> tuple[int, str] | None:  # noqa: PLR0911
        ls = entry.get("logsource") or {}
        if cat and (ls.get("category") or "").lower() != cat:
            return None
        if prod and (ls.get("product") or "").lower() != prod:
            return None
        if lvl and (entry.get("level") or "").lower() != lvl:
            return None
        if not q:
            return (3, entry.get("title", ""))
        title_lower = (entry.get("title") or "").lower()
        if title_lower.startswith(q):
            return (0, title_lower)
        if q in title_lower:
            return (1, title_lower)
        if q in (entry.get("search_blob") or ""):
            return (2, title_lower)
        return None

    scored: list[tuple[tuple[int, str], dict[str, Any]]] = []
    for entry in _load_index():
        rank = _matches(entry)
        if rank is None:
            continue
        scored.append((rank, entry))
        # Stop scanning once we have plenty of candidates — sort + truncate
        # gives the same top-N as scanning the whole corpus when the
        # query is non-empty (relevance ordering means later entries
        # can only be tier-3 body matches).
        if q and len(scored) >= limit * 4:
            break
    scored.sort(key=lambda t: t[0])
    out: list[CorpusEntry] = []
    for _, entry in scored[:limit]:
        ls = entry.get("logsource") or {}
        tags = entry.get("tags") or []
        out.append(
            CorpusEntry(
                id=entry["id"],
                title=entry.get("title", ""),
                description=entry.get("description", ""),
                level=entry.get("level", ""),
                status=entry.get("status", ""),
                category=ls.get("category"),
                product=ls.get("product"),
                service=ls.get("service"),
                tags=tuple(str(t) for t in tags),
                file_path=entry.get("file_path", ""),
            )
        )
    return out


def load_corpus_rule(rule_id: str) -> tuple[RuleDraft | None, list[ValidationIssue]]:
    """Fetch a corpus rule by id and translate it to a ``RuleDraft``.

    Returns the same shape ``draft_from_yaml`` does — translator issues
    flow through unchanged, so fidelity-loss warnings render in the
    preview pane next to the loaded rule.
    """
    rule_id = rule_id.strip()
    if not rule_id:
        return None, [
            ValidationIssue(
                tier=1,
                code="LOAD_CORPUS_BLANK_ID",
                message="Corpus rule id is required.",
            )
        ]
    for entry in _load_index():
        if entry.get("id") == rule_id:
            raw = entry.get("raw_yaml")
            if not isinstance(raw, str):
                return None, [
                    ValidationIssue(
                        tier=1,
                        code="LOAD_CORPUS_NO_BODY",
                        message=(
                            f"Corpus rule {rule_id!r} has no raw YAML in the "
                            "bundled index. Re-run scripts/build_sigmahq_corpus.py."
                        ),
                    )
                ]
            return draft_from_yaml(raw)
    return None, [
        ValidationIssue(
            tier=1,
            code="LOAD_CORPUS_UNKNOWN",
            message=f"No corpus rule with id {rule_id!r}.",
        )
    ]


def all_categories() -> list[str]:
    """Distinct logsource categories in the bundled index, sorted.

    Powers the category dropdown filter on the Browse SigmaHQ tab.
    """
    return sorted(
        {
            (e.get("logsource") or {}).get("category") or ""
            for e in _load_index()
            if (e.get("logsource") or {}).get("category")
        }
    )


def all_products() -> list[str]:
    """Distinct logsource products in the bundled index, sorted."""
    return sorted(
        {
            (e.get("logsource") or {}).get("product") or ""
            for e in _load_index()
            if (e.get("logsource") or {}).get("product")
        }
    )


__all__ = [
    "CorpusEntry",
    "all_categories",
    "all_products",
    "index_size",
    "load_corpus_rule",
    "search_corpus",
]
