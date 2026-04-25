"""Loader for ``intel2sigma/data/heuristics.yml``.

Per CLAUDE.md I-5 the per-heuristic severity and enablement live in
data, not code. This module reads the YAML, validates the shape, and
returns a ``dict[str, HeuristicConfig]`` keyed by heuristic id.

The loader is pure (per CLAUDE.md I-8): given the same file contents it
returns the same registry. Bundled by default at the package data path;
tests can supply an alternate path.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from intel2sigma._data import data_path
from intel2sigma.core.heuristics.base import HeuristicConfig, Severity


class HeuristicConfigLoadError(Exception):
    """Raised when ``heuristics.yml`` is missing, malformed, or schema-invalid."""


class _Entry(BaseModel):
    """Schema for one row of ``heuristics.yml``."""

    model_config = ConfigDict(extra="forbid")

    severity: Severity
    enabled: bool = True


class _Schema(BaseModel):
    """Top-level shape of ``heuristics.yml``.

    The file is a single mapping under the ``heuristics:`` key. Keys are
    heuristic ids (e.g. ``h-001``); values are :class:`_Entry`.
    """

    model_config = ConfigDict(extra="forbid")

    heuristics: dict[str, _Entry]


def load_config(path: Path | None = None) -> dict[str, HeuristicConfig]:
    """Read and validate ``heuristics.yml``; return a config dict.

    The default path comes from :func:`intel2sigma._data.data_path`;
    callers can override for tests. Errors raise
    :exc:`HeuristicConfigLoadError` rather than returning empty —
    silent fallback to "no heuristics enabled" would be a footgun in
    production.
    """
    target = path if path is not None else data_path("heuristics.yml")
    if not target.is_file():
        raise HeuristicConfigLoadError(
            f"Heuristics config file not found at {target}. "
            f"This file ships in the package; missing in dev usually "
            f"means the working tree is out of sync.",
        )
    try:
        yaml = YAML(typ="safe")
        raw: Any = yaml.load(target.read_text(encoding="utf-8"))
    except (OSError, YAMLError) as exc:
        raise HeuristicConfigLoadError(
            f"Could not parse {target} as YAML: {exc}",
        ) from exc
    try:
        parsed = _Schema.model_validate(raw)
    except ValidationError as exc:
        raise HeuristicConfigLoadError(
            f"{target} failed schema validation: {exc}",
        ) from exc
    return {
        hid: HeuristicConfig(severity=entry.severity, enabled=entry.enabled)
        for hid, entry in parsed.heuristics.items()
    }


@cache
def cached_config() -> dict[str, HeuristicConfig]:
    """Memoized config lookup for the bundled file.

    Heuristic config doesn't change at runtime, so a single read at first
    use covers every subsequent call. Tests that monkey-patch the path
    should pass the alternative path explicitly to :func:`load_config`
    rather than going through this cache.
    """
    return load_config()


__all__ = [
    "HeuristicConfigLoadError",
    "cached_config",
    "load_config",
]
