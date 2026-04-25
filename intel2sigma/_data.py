"""Resolve paths to bundled data files (taxonomy YAMLs, MITRE tree, etc.).

The data directory lives inside the package at ``intel2sigma/data/`` so it
ships with the wheel automatically. Same physical layout in-repo and after
``pip install``, no special hatch ``force-include`` config required.

Single API for the four path-resolution sites (``web/load.py``,
``web/mitre.py``, ``core/convert/pipelines.py``,
``core/taxonomy/loader.py``); they call :func:`data_path` instead of doing
``parents[N]`` arithmetic.
"""

from __future__ import annotations

from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent
_DATA_DIR = _PACKAGE_DIR / "data"


def data_path(*parts: str) -> Path:
    """Return an absolute path to ``intel2sigma/data/<parts>``.

    The path is returned even if it doesn't exist (consumers handle missing
    files themselves — ``load_mitre_tree()`` for example degrades to ``{}``
    when its file is gone).
    """
    return _DATA_DIR.joinpath(*parts)


__all__ = ["data_path"]
