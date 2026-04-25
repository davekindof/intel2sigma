"""Resolve paths to bundled data files (taxonomy YAMLs, MITRE tree, etc.).

Data lives in two places depending on how the package is being run:

* **Wheel install** (``pip install intel2sigma``) — the wheel ships ``data/``
  inside the package as ``<site-packages>/intel2sigma/data/``. Configured in
  ``pyproject.toml``'s ``[tool.hatch.build.targets.wheel.force-include]``.
* **In-repo development** — ``data/`` lives at the repo root, sibling to the
  ``intel2sigma/`` package directory.

This helper looks in the wheel location first, falls back to the dev location.
Same single API for both, so the four path-resolution sites
(``web/load.py``, ``web/mitre.py``, ``core/convert/pipelines.py``,
``core/taxonomy/loader.py``) stop hardcoding ``parents[N]`` math.
"""

from __future__ import annotations

from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent
_BUNDLED_DATA = _PACKAGE_DIR / "data"
_REPO_DATA = _PACKAGE_DIR.parent / "data"


def data_path(*parts: str) -> Path:
    """Return an absolute path to ``data/<parts>``.

    Resolution order:

    1. ``<package>/data/<parts>`` — the location used in wheel installs and
       in our Docker image (where ``data/`` is copied into the package).
    2. ``<repo>/data/<parts>`` — the location used during in-repo development
       where the working tree's ``data/`` is sibling to the package.

    The path is returned even if it doesn't exist (consumers handle missing
    files themselves — ``load_mitre_tree()`` for example degrades to ``{}``
    when its file is gone).
    """
    if _BUNDLED_DATA.is_dir():
        return _BUNDLED_DATA.joinpath(*parts)
    return _REPO_DATA.joinpath(*parts)


__all__ = ["data_path"]
