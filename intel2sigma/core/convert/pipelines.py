"""Pipeline matrix loader and resolver.

Reads ``data/pipelines.yml`` once at first access, validates it against a
Pydantic schema, and resolves ``(rule.logsource, backend_id) →
(backend_identifier, [pipeline_name, ...])``.

Design and resolution algorithm: see ``docs/pipeline-matrix.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from intel2sigma._data import data_path
from intel2sigma.core.model import LogSource

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PipelineMatrixError(Exception):
    """Raised when the pipeline matrix file is missing, malformed, or
    inconsistent. Typed per CLAUDE.md so callers can catch without snooping
    message text.
    """


class UnknownBackendError(PipelineMatrixError):
    """Raised when a caller requests a backend id not declared in
    ``data/pipelines.yml``.
    """


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class CategoryOverride(_Model):
    """One ``category_overrides`` entry under a backend.

    Closes coverage gaps in the upstream pipeline's category-to-table
    mapping. ``table`` is the SIEM-specific table name (e.g. Defender's
    ``DeviceEvents``); ``filter`` is an optional set of field=value
    constraints added to the rule via Sigma's ``AddConditionTransformation``
    so the resulting query targets the right slice of a multi-purpose
    table (e.g. ``DeviceEvents`` covers many ActionType values, and we
    want to filter to ``CreateRemoteThreadApiCall`` for the
    ``create_remote_thread`` category).

    Set the override at the backend level so retiring it once the
    upstream catches up is a one-line YAML edit.
    """

    table: str = Field(min_length=1)
    filter: dict[str, str] = Field(default_factory=dict)


class BackendSpec(_Model):
    """One entry under ``backends:`` in the YAML.

    ``sigma_backend`` is the pySigma short name from
    ``InstalledSigmaPlugins.autodiscover().backends`` (e.g. ``kusto``,
    ``splunk``, ``lucene``, ``log_scale``).

    ``category_overrides`` plugs gaps in the upstream pipeline's
    category-to-table dictionary. Any rule whose logsource category
    matches a key here gets its ``query_table`` (and optional
    ActionType filter) injected via a Sigma processing pipeline that
    runs at higher priority than the upstream — so the upstream sees a
    state that's already been set, no "Unable to determine table name"
    error fires.
    """

    sigma_backend: str = Field(min_length=1)
    format: str = "default"
    baseline_pipelines: list[str] = Field(default_factory=list)
    label: str = Field(min_length=1)
    category_overrides: dict[str, CategoryOverride] = Field(default_factory=dict)


class LogsourceMatch(_Model):
    """A partial-match filter on a rule's logsource.

    Any absent key is a wildcard — the match succeeds if the keys present in
    ``match:`` all equal the rule's corresponding logsource fields.
    """

    category: str | None = None
    product: str | None = None
    service: str | None = None


class LogsourceMatrixEntry(_Model):
    match: LogsourceMatch
    backends: dict[str, list[str]]  # backend_id -> extra pipelines

    @property
    def is_empty_match(self) -> bool:
        """Match-all entry. Would shadow every later entry; guarded against."""
        m = self.match
        return m.category is None and m.product is None and m.service is None


class PipelineMatrix(_Model):
    backends: dict[str, BackendSpec]
    logsource_matrix: list[LogsourceMatrixEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_DEFAULT_PATH = data_path("pipelines.yml")


@cache
def _default_matrix() -> PipelineMatrix:
    """Lazy-load + cache the bundled matrix for default callers."""
    return load_pipeline_matrix()


def build_category_override_pipeline(
    overrides: tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...],
) -> Any | None:
    """Build a Sigma ``ProcessingPipeline`` from category-override data.

    Takes the tuple-frozen form carried on :class:`ResolvedConversion`
    (so this stays hashable / cacheable). Each override produces up to
    two ``ProcessingItem`` entries:

    1. A :class:`SetStateTransformation` that sets ``query_table`` in the
       pipeline state. The upstream pipeline's
       :class:`SetQueryTableStateTransformation` checks ``pipeline.state``
       BEFORE its category_to_table_mappings dict, so a state set first
       short-circuits the lookup that would otherwise raise "Unable to
       determine table name from rule".

    2. An optional :class:`AddConditionTransformation` that ANDs in a
       ``ActionType: <value>`` filter (or whatever the override's filter
       map specifies). Used when the SIEM table is multi-purpose and
       needs a discriminator to target the right slice.

    Both items are gated on a :class:`LogsourceCondition` so they only
    apply to rules whose category matches the override key. The pipeline
    runs at priority 5 — lower (earlier) than the upstream microsoft_xdr
    pipeline's priority 10 — so our state-set fires first.

    Returns ``None`` when there are no overrides; callers should skip
    composition rather than ship an empty pipeline.
    """
    if not overrides:
        return None

    # Local imports — pySigma is a heavy import surface and only callers
    # actually building pipelines should pay for it.
    from sigma.processing.conditions import LogsourceCondition  # noqa: PLC0415
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline  # noqa: PLC0415
    from sigma.processing.transformations import (  # noqa: PLC0415
        AddConditionTransformation,
        SetStateTransformation,
    )

    items: list[ProcessingItem] = []
    for category, table, filter_items in overrides:
        items.append(
            ProcessingItem(
                identifier=f"i2s_override_{category}_table",
                transformation=SetStateTransformation(key="query_table", val=table),
                rule_conditions=[LogsourceCondition(category=category)],
            )
        )
        if filter_items:
            items.append(
                ProcessingItem(
                    identifier=f"i2s_override_{category}_filter",
                    transformation=AddConditionTransformation(dict(filter_items)),
                    rule_conditions=[LogsourceCondition(category=category)],
                )
            )

    return ProcessingPipeline(
        name="intel2sigma category overrides",
        priority=5,
        items=items,
    )


def load_pipeline_matrix(path: Path | None = None) -> PipelineMatrix:
    """Read and validate ``data/pipelines.yml``.

    Raises:
        PipelineMatrixError: if the file is missing, unreadable, malformed,
            schema-invalid, or contains a match-all entry that would shadow
            every subsequent entry.
    """
    resolved = (path or _DEFAULT_PATH).resolve()
    if not resolved.is_file():
        raise PipelineMatrixError(f"Pipeline matrix file not found: {resolved}")

    try:
        raw = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise PipelineMatrixError(f"Cannot read {resolved}: {exc}") from exc

    yaml = YAML(typ="safe")
    try:
        data: Any = yaml.load(raw)
    except YAMLError as exc:
        raise PipelineMatrixError(f"{resolved}: YAML parse error: {exc}") from exc

    if not isinstance(data, dict):
        raise PipelineMatrixError(
            f"{resolved}: top-level document must be a mapping, got {type(data).__name__}"
        )

    try:
        matrix = PipelineMatrix.model_validate(data)
    except ValidationError as exc:
        raise PipelineMatrixError(f"{resolved}: schema validation failed:\n{exc}") from exc

    # Cross-field invariant: a match-all entry would consume every rule
    # regardless of what comes after it. Almost certainly a misconfiguration.
    for idx, entry in enumerate(matrix.logsource_matrix):
        if entry.is_empty_match:
            raise PipelineMatrixError(
                f"{resolved}: logsource_matrix entry {idx} has an empty match, "
                f"which would shadow every subsequent entry. Add at least one "
                f"of product/category/service or remove the entry."
            )

    # Every backend referenced in the matrix must be declared above.
    declared = set(matrix.backends)
    for idx, entry in enumerate(matrix.logsource_matrix):
        unknown = set(entry.backends) - declared
        if unknown:
            raise PipelineMatrixError(
                f"{resolved}: logsource_matrix entry {idx} references unknown "
                f"backend(s) {sorted(unknown)}. Known: {sorted(declared)}."
            )

    return matrix


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResolvedConversion:
    """Immutable result of matching a rule's logsource against the matrix.

    Hashable — callers use this as part of the conversion-cache key.

    ``category_overrides`` carries the (category → table[, filter])
    map from the backend spec, frozen into a tuple-of-tuples so the
    dataclass remains hashable. Lets the convert engine assemble the
    override pipeline without re-loading the matrix per call.
    """

    backend_id: str
    sigma_backend: str  # pySigma plugin name
    format: str
    pipelines: tuple[str, ...]  # ordered; first element has highest priority
    label: str
    # Tuple of (category, table_name, frozen filter-items) so this stays
    # hashable for the lru_cache. Empty if no overrides.
    category_overrides: tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...] = ()


def resolve(
    logsource: LogSource,
    backend_id: str,
    matrix: PipelineMatrix | None = None,
) -> ResolvedConversion:
    """Pick a pySigma backend + pipeline list for the given rule logsource.

    Args:
        logsource: The rule's ``LogSource``. Unspecified fields match
            anything in the matrix.
        backend_id: One of the declared intel2sigma backend ids.
        matrix: Optional injected matrix for tests; defaults to the bundled
            ``data/pipelines.yml``.

    Raises:
        UnknownBackendError: if ``backend_id`` isn't declared.
    """
    m = matrix if matrix is not None else _default_matrix()

    try:
        spec = m.backends[backend_id]
    except KeyError as exc:
        raise UnknownBackendError(
            f"Unknown backend id {backend_id!r}. Known: {sorted(m.backends)}."
        ) from exc

    pipelines: list[str] = list(spec.baseline_pipelines)
    for entry in m.logsource_matrix:
        if _match(logsource, entry.match):
            extras = entry.backends.get(backend_id)
            if extras:
                pipelines.extend(extras)
            break  # first match wins

    overrides_frozen: tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...] = tuple(
        (cat, ov.table, tuple(sorted(ov.filter.items())))
        for cat, ov in spec.category_overrides.items()
    )
    return ResolvedConversion(
        backend_id=backend_id,
        sigma_backend=spec.sigma_backend,
        format=spec.format,
        pipelines=tuple(pipelines),
        label=spec.label,
        category_overrides=overrides_frozen,
    )


def _match(logsource: LogSource, match: LogsourceMatch) -> bool:
    """A ``LogsourceMatch`` matches a ``LogSource`` when every non-None field
    in the match equals the corresponding logsource field.

    Missing logsource fields are treated as the empty string; a match that
    requires ``product: windows`` won't succeed against a rule whose
    logsource has no product set.
    """
    if match.category is not None and match.category != (logsource.category or ""):
        return False
    if match.product is not None and match.product != (logsource.product or ""):
        return False
    return not (match.service is not None and match.service != (logsource.service or ""))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def all_backend_ids(matrix: PipelineMatrix | None = None) -> list[str]:
    """Sorted list of declared intel2sigma backend ids. Useful for CLI help
    text and UI conversion-tab enumeration.
    """
    m = matrix if matrix is not None else _default_matrix()
    return sorted(m.backends)


def backend_label(backend_id: str, matrix: PipelineMatrix | None = None) -> str:
    """Human-readable label for a backend id (UI display)."""
    m = matrix if matrix is not None else _default_matrix()
    try:
        return m.backends[backend_id].label
    except KeyError as exc:
        raise UnknownBackendError(
            f"Unknown backend id {backend_id!r}. Known: {sorted(m.backends)}."
        ) from exc


__all__ = [
    "BackendSpec",
    "LogsourceMatch",
    "LogsourceMatrixEntry",
    "PipelineMatrix",
    "PipelineMatrixError",
    "ResolvedConversion",
    "UnknownBackendError",
    "all_backend_ids",
    "backend_label",
    "load_pipeline_matrix",
    "resolve",
]
