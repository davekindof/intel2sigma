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


class BackendSpec(_Model):
    """One entry under ``backends:`` in the YAML.

    ``sigma_backend`` is the pySigma short name from
    ``InstalledSigmaPlugins.autodiscover().backends`` (e.g. ``kusto``,
    ``splunk``, ``lucene``, ``log_scale``).
    """

    sigma_backend: str = Field(min_length=1)
    format: str = "default"
    baseline_pipelines: list[str] = Field(default_factory=list)
    label: str = Field(min_length=1)


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

_DEFAULT_PATH = Path(__file__).resolve().parents[3] / "data" / "pipelines.yml"


@cache
def _default_matrix() -> PipelineMatrix:
    """Lazy-load + cache the bundled matrix for default callers."""
    return load_pipeline_matrix()


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
    """

    backend_id: str
    sigma_backend: str  # pySigma plugin name
    format: str
    pipelines: tuple[str, ...]  # ordered; first element has highest priority
    label: str


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

    return ResolvedConversion(
        backend_id=backend_id,
        sigma_backend=spec.sigma_backend,
        format=spec.format,
        pipelines=tuple(pipelines),
        label=spec.label,
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
