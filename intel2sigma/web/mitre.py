"""MITRE ATT&CK tree loader for Stage 2's hierarchical tag picker.

Reads the tree built by ``scripts/build_mitre_tree.py`` once at first
access and caches it. The tree shape is documented in that script.

The loader is the only Python touch-point for the MITRE data. The
picker UI consumes the tree via Jinja2 — no separate JSON endpoint —
so the data is rendered inline in the modal markup. ~128 KB of HTML
is fine on the modern web; we'd revisit if it ever became a concern.
"""

from __future__ import annotations

import json
from functools import cache
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from intel2sigma._data import data_path

_TREE_PATH = data_path("mitre_attack.json")

# Bound to a name to avoid ruff 0.15.x's auto-removal of the parentheses
# in ``except (X, Y):``. The bare comma form Python 3.14 accepts looks
# like a Python 2 bug to readers; the alias keeps intent explicit.
_LOAD_FAILURES = (OSError, json.JSONDecodeError)
_SUGGESTION_LOAD_FAILURES = (OSError, YAMLError)


@cache
def load_mitre_tree() -> dict[str, Any]:
    """Return the bundled ATT&CK tree.

    ``{}`` if the data file is missing — the picker UI degrades to "no
    techniques to browse, free-text input still works" rather than
    blowing up the composer.
    """
    if not _TREE_PATH.is_file():
        return {}
    try:
        # mypy can't narrow ``json.loads`` past Any; the runtime shape
        # comes from scripts/build_mitre_tree.py which always emits a dict.
        return json.loads(_TREE_PATH.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
    except _LOAD_FAILURES:
        return {}


@cache
def attack_tag_suggestions() -> tuple[str, ...]:
    """Datalist entries for the Stage 2 ATT&CK tag input.

    Tactics are derived from the pinned tree rather than listed, so they
    cannot drift from it. They did drift: the suggestion list carried
    ``attack.defense-evasion`` for months after ATT&CK v18 retired it,
    because it was a hand-maintained tuple in ``web/routes/composer.py``.
    Deriving removes the failure mode instead of correcting one instance
    of it.

    Techniques come from ``data/attack_tag_suggestions.yml`` — editorial,
    not derivable, since a datalist of all 858 helps nobody. Both halves
    are now data (CLAUDE.md I-5).

    Degrades to the techniques alone if the tree is unreadable, matching
    how :func:`load_mitre_tree` degrades rather than raising.
    """
    tactics = tuple(
        str(t["tag"])
        for t in load_mitre_tree().get("tactics", [])
        if isinstance(t, dict) and t.get("tag")
    )

    path = data_path("attack_tag_suggestions.yml")
    techniques: tuple[str, ...] = ()
    if path.is_file():
        try:
            loaded = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
        except _SUGGESTION_LOAD_FAILURES:
            loaded = None
        if isinstance(loaded, dict):
            raw = loaded.get("techniques") or []
            if isinstance(raw, list):
                techniques = tuple(str(t) for t in raw if t)

    return tactics + techniques


__all__ = ["attack_tag_suggestions", "load_mitre_tree"]
