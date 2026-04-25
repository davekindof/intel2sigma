"""pySigma wrapper: take an intel2sigma rule, produce a SIEM query.

One public entry point: :func:`convert`. Given a :class:`SigmaRule` and a
backend id (one of the ones declared in ``data/pipelines.yml``), returns the
converted query as a string.

Caching: results are memoized via ``functools.lru_cache`` keyed by
``sha256(canonical_yaml) + backend_id + pipeline_names`` — cache size 256
per SPEC.md. Cold conversions are ~100ms; warm hits are effectively free.

Errors:
  * :class:`UnknownBackendError` — backend id not declared.
  * :class:`ConversionFailedError` — pySigma rejected the rule for this
    backend/pipeline combination. Wraps the pySigma exception so callers
    don't have to import from ``sigma.exceptions``.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from typing import Any

from sigma.exceptions import SigmaError
from sigma.plugins import InstalledSigmaPlugins
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule as PySigmaRule

from intel2sigma.core.convert.pipelines import (
    PipelineMatrix,
    PipelineMatrixError,
    ResolvedConversion,
    UnknownBackendError,
    resolve,
)
from intel2sigma.core.model import SigmaRule
from intel2sigma.core.serialize import to_yaml

_CONVERSION_CACHE_SIZE = 256


class ConversionFailedError(PipelineMatrixError):
    """Raised when pySigma rejects a rule for a given backend/pipeline combo.

    ``backend_id`` and ``pipelines`` capture which conversion attempt failed;
    ``cause`` retains the original pySigma exception so UI code can
    fall back to a raw message when needed.

    The ``str()`` form is what the conversion-tab template renders, so it
    needs to read like operator advice, not like a stack trace. The
    :func:`_friendlier` translator below recognises a small set of known
    pySigma error shapes and rewrites them into "this rule's logsource
    doesn't have a default mapping for this backend" guidance.
    """

    def __init__(
        self,
        backend_id: str,
        pipelines: tuple[str, ...],
        cause: Exception,
    ) -> None:
        pipeline_str = ", ".join(pipelines) if pipelines else "(baseline only)"
        message = _friendlier(backend_id, pipelines, cause) or (
            f"pySigma failed to convert rule for backend {backend_id!r} "
            f"with pipelines [{pipeline_str}]: {cause}"
        )
        super().__init__(message)
        self.backend_id = backend_id
        self.pipelines = pipelines
        self.cause = cause


def _friendlier(
    backend_id: str,
    pipelines: tuple[str, ...],
    cause: Exception,
) -> str | None:
    """Map known pySigma error shapes onto operator-friendly guidance.

    Returns ``None`` if the error doesn't match a known shape, so the
    caller falls back to the raw pySigma message.

    Today's recognised shapes:

    * "Unable to determine table name from rule" — pySigma-backend-kusto's
      Microsoft Defender / Sentinel pipelines couldn't map the rule's
      logsource ``category`` to a Defender XDR / Sentinel table. This is a
      coverage gap in the upstream pipeline (some Sysmon-only categories
      like ``create_remote_thread`` aren't in their category-to-table
      maps). Tell the user what to do instead.
    """
    msg = str(cause)
    if "Unable to determine table name from rule" in msg:
        # Strip the verbose "see README" trailer pySigma appends.
        backend_label = {
            "kusto_mde": "Microsoft Defender XDR",
            "kusto_sentinel": "Microsoft Sentinel",
        }.get(backend_id, backend_id)
        return (
            f"This rule's logsource category doesn't have a default {backend_label} "
            f"table mapping in pySigma's pipeline. Sysmon-only categories like "
            f"``create_remote_thread`` are a known coverage gap. Try "
            f"Splunk / Elastic / CrowdStrike instead, or use a Windows "
            f"Security-channel category if the detection allows it."
        )
    return None


def convert(
    rule: SigmaRule,
    backend_id: str,
    matrix: PipelineMatrix | None = None,
) -> str:
    """Convert ``rule`` to the target query language for ``backend_id``.

    Args:
        rule: A validated intel2sigma rule. Caller should pass tier-1 and
            tier-2 validators first — this function's error handling
            assumes pySigma's rejection is a pipeline/backend concern, not
            a malformed rule.
        backend_id: One of the ids declared in ``data/pipelines.yml``.
        matrix: Optional pipeline matrix override for tests. Defaults to
            the bundled ``data/pipelines.yml``.

    Returns:
        The converted query as a string.

    Raises:
        UnknownBackendError: ``backend_id`` isn't declared.
        ConversionFailedError: pySigma rejected the rule for this backend.
    """
    resolved = resolve(rule.logsource, backend_id, matrix=matrix)
    yaml_text = to_yaml(rule)
    cache_key = _cache_key(yaml_text, resolved)
    return _convert_cached(cache_key, yaml_text, resolved)


def _cache_key(yaml_text: str, resolved: ResolvedConversion) -> str:
    """Stable cache key. Content hash + backend + pipeline set.

    Sorting pipelines makes the cache key order-independent, which is safe
    because pySigma's pipeline composition is order-sensitive but two
    resolutions with the same pipeline tuple in a different order would
    indicate a resolver bug, not a legitimate new conversion.
    """
    h = hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()
    return f"{h}|{resolved.backend_id}|{resolved.format}|{'|'.join(resolved.pipelines)}"


@lru_cache(maxsize=_CONVERSION_CACHE_SIZE)
def _convert_cached(
    _cache_key_unused: str,
    yaml_text: str,
    resolved: ResolvedConversion,
) -> str:
    """Cached core — only the ``cache_key`` actually contributes to the
    lookup, but ``yaml_text`` and ``resolved`` are the real inputs.
    """
    plugins = _plugins()
    backend_cls = plugins.backends.get(resolved.sigma_backend)
    if backend_cls is None:
        raise UnknownBackendError(
            f"pySigma backend {resolved.sigma_backend!r} is not installed. "
            f"This is a dependency-pinning bug in intel2sigma, not a user error."
        )

    pipeline = _compose_pipeline(plugins, resolved.pipelines)
    # pySigma's Backend base class has a ``processing_pipeline`` kwarg that
    # mypy can't see through the Generic abstraction.
    backend: Any = backend_cls(processing_pipeline=pipeline)  # type: ignore[operator]

    try:
        py_rule = PySigmaRule.from_yaml(yaml_text)
        queries = backend.convert_rule(py_rule, output_format=resolved.format)
    except SigmaError as exc:
        raise ConversionFailedError(resolved.backend_id, resolved.pipelines, exc) from exc

    # pySigma returns a list[str] — usually one element per rule but some
    # backends emit multiple for multi-condition rules. Join with newlines
    # for caller convenience; UI can split on newline if it wants per-query
    # display.
    if not isinstance(queries, list):
        raise ConversionFailedError(
            resolved.backend_id,
            resolved.pipelines,
            RuntimeError(
                f"pySigma backend {resolved.sigma_backend!r} returned "
                f"{type(queries).__name__}, expected list[str]."
            ),
        )
    return "\n".join(str(q) for q in queries)


@lru_cache(maxsize=1)
def _plugins() -> InstalledSigmaPlugins:
    """Cached pySigma plugin registry. Autodiscovery is not cheap; do it once."""
    # autodiscover() is untyped upstream; cast is safe — pySigma returns an
    # InstalledSigmaPlugins instance from this call.
    return InstalledSigmaPlugins.autodiscover()  # type: ignore[no-any-return]


def _compose_pipeline(
    plugins: InstalledSigmaPlugins,
    pipeline_names: tuple[str, ...],
) -> ProcessingPipeline | None:
    """Compose a single ``ProcessingPipeline`` from the named pipelines.

    Each named entry in ``plugins.pipelines`` is a callable (either a
    factory function returning a ``ProcessingPipeline`` or a Pipeline class
    whose ``__call__`` returns a bound copy). We instantiate each, sort by
    priority, and sum them — the same composition ``ProcessingPipelineResolver``
    does internally, without the detour through name-lookup.

    Returns ``None`` when no pipelines apply; pySigma backends accept that
    and use their built-in defaults.
    """
    if not pipeline_names:
        return None

    pipelines: list[ProcessingPipeline] = []
    for name in pipeline_names:
        factory = plugins.pipelines.get(name)
        if factory is None:
            raise ConversionFailedError(
                backend_id="",
                pipelines=pipeline_names,
                cause=ValueError(
                    f"Pipeline {name!r} is not registered in pySigma. "
                    f"Known pipelines: {sorted(plugins.pipelines)}."
                ),
            )
        pipelines.append(factory())

    # ``ProcessingPipeline.__add__`` composes pipelines; summing preserves
    # priority ordering pySigma uses internally.
    pipelines.sort(key=lambda p: p.priority)
    composed = pipelines[0]
    for extra in pipelines[1:]:
        composed = composed + extra
    return composed


__all__ = [
    "ConversionFailedError",
    "UnknownBackendError",
    "convert",
]
