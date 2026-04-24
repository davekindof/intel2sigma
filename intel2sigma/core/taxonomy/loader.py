"""Fail-fast loader for the observation-type catalog.

Reads every ``*.yml`` file under a taxonomy data directory, validates each
against :mod:`.schema`, and returns an immutable :class:`TaxonomyRegistry`.
Any schema violation, cross-file collision, or filename/id mismatch raises a
:class:`TaxonomyLoadError` with a specific message.

The loader is pure: given the same directory contents, it always returns the
same registry. No module-level mutable state. Callers can supply an explicit
``data_dir`` for tests or rely on the default which points at the bundled
``data/taxonomy/`` directory inside the repo.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from pydantic import ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from intel2sigma.core.taxonomy.schema import CategoryGroup, ObservationTypeSpec

# Default bundled taxonomy location, resolved relative to the installed package
# so this works whether intel2sigma is imported from source or from a wheel.
_DEFAULT_DATA_DIR = Path(__file__).resolve().parents[3] / "data" / "taxonomy"


class TaxonomyLoadError(Exception):
    """Raised when a taxonomy data file violates schema or cross-file invariants.

    Per CLAUDE.md "Exceptions are typed", a domain-specific exception is
    preferable to a generic ``ValueError`` here — consumers catch it to show a
    startup error instead of propagating a raw stack trace.
    """


@dataclass(frozen=True)
class TaxonomyRegistry:
    """Immutable collection of observation-type specs keyed by ``id``.

    Exposes read-only views so callers cannot mutate the registry after load
    (the ``types.MappingProxyType`` wrapper prevents accidental writes even
    through the internal dict).
    """

    _by_id: Mapping[str, ObservationTypeSpec] = field(default_factory=dict)

    def get(self, observation_id: str) -> ObservationTypeSpec:
        """Return the spec for ``observation_id`` or raise ``KeyError``."""
        try:
            return self._by_id[observation_id]
        except KeyError as exc:
            raise KeyError(
                f"Unknown observation type {observation_id!r}. Known types: {sorted(self._by_id)}"
            ) from exc

    def all_ids(self) -> list[str]:
        """Return all observation-type ids in deterministic (sorted) order."""
        return sorted(self._by_id)

    def by_group(self) -> Mapping[CategoryGroup, list[str]]:
        """Return observation-type ids grouped by UI ``category_group``.

        Groups appear only if at least one observation type belongs to them.
        Ids within each group are sorted deterministically.
        """
        grouped: dict[CategoryGroup, list[str]] = {}
        for obs_id, spec in self._by_id.items():
            grouped.setdefault(spec.category_group, []).append(obs_id)
        for ids in grouped.values():
            ids.sort()
        return MappingProxyType(grouped)


def load_taxonomy(data_dir: Path | None = None) -> TaxonomyRegistry:
    """Load every ``*.yml`` file under ``data_dir`` into a frozen registry.

    Args:
        data_dir: Directory containing the taxonomy YAML files. Defaults to
            the bundled ``data/taxonomy/`` directory.

    Returns:
        A :class:`TaxonomyRegistry` populated with every validated spec.

    Raises:
        TaxonomyLoadError: On any of:
          * directory missing
          * directory contains no ``*.yml`` files
          * YAML parse failure in any file
          * schema validation failure
          * file id does not match the filename stem

    Duplicate ids across files cannot occur: the filename-stem check ensures
    each file's id matches its filename, and a filesystem cannot hold two
    files with the same name in the same directory.
    """
    resolved = (data_dir or _DEFAULT_DATA_DIR).resolve()

    if not resolved.is_dir():
        raise TaxonomyLoadError(f"Taxonomy data directory not found: {resolved}")

    yaml_files = sorted(resolved.glob("*.yml"))
    if not yaml_files:
        raise TaxonomyLoadError(f"No *.yml files found in taxonomy directory: {resolved}")

    by_id: dict[str, ObservationTypeSpec] = {}
    yaml = YAML(typ="safe")

    for path in yaml_files:
        spec = _load_one(path, yaml)
        if spec.id != path.stem:
            raise TaxonomyLoadError(
                f"{path.name}: file id {spec.id!r} does not match filename stem {path.stem!r}"
            )
        by_id[spec.id] = spec

    return TaxonomyRegistry(_by_id=MappingProxyType(by_id))


def _load_one(path: Path, yaml: YAML) -> ObservationTypeSpec:
    """Parse and validate a single taxonomy file.

    YAML parse errors and Pydantic validation errors are both wrapped as
    :class:`TaxonomyLoadError` with the filename in the message so a stack
    trace immediately points to the offending file.
    """
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TaxonomyLoadError(f"{path.name}: cannot read file: {exc}") from exc

    try:
        data: Any = yaml.load(raw_text)
    except YAMLError as exc:
        raise TaxonomyLoadError(f"{path.name}: YAML parse error: {exc}") from exc

    if not isinstance(data, dict):
        raise TaxonomyLoadError(
            f"{path.name}: top-level document must be a mapping, got {type(data).__name__}"
        )

    try:
        return ObservationTypeSpec.model_validate(data)
    except ValidationError as exc:
        raise TaxonomyLoadError(f"{path.name}: schema validation failed:\n{exc}") from exc
