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
from pathlib import Path
from typing import Any

_TREE_PATH = Path(__file__).resolve().parents[2] / "data" / "mitre_attack.json"


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
        return json.loads(_TREE_PATH.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
    except OSError, json.JSONDecodeError:
        return {}


__all__ = ["load_mitre_tree"]
