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
from copy import deepcopy
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
    build_category_override_pipeline,
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
        resolved: ResolvedConversion | None = None,
    ) -> None:
        pipeline_str = ", ".join(pipelines) if pipelines else "(baseline only)"
        message = _friendlier(backend_id, pipelines, cause, resolved) or (
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
    resolved: ResolvedConversion | None = None,
) -> str | None:
    """Map known pySigma error shapes onto operator-friendly guidance.

    Returns ``None`` if the error doesn't match a known shape, so the
    caller falls back to the raw pySigma message.

    Today's recognised shape is "Unable to determine table name from
    rule" — the Kusto pipelines could not map the rule's logsource to a
    table. That single error covers two situations users need told
    apart:

    * **The platform has no such telemetry.** Okta, Zeek, AWS and the
      like are simply not in the Defender XDR schema. No mapping will
      ever exist, and saying "coverage gap" implies someone is coming
      to fix it. Recognised via ``resolved.unsupported_reason``, which
      is data-driven from ``pipelines.yml``.
    * **The telemetry exists but is unmapped.** A genuine gap, closable
      with a ``category_overrides`` entry.

    Before this split, every one of these rendered as the second — so a
    user converting an Okta rule was told about Sysmon categories and
    invited to wait for a fix that is not coming.

    Returns ``None`` when the error isn't a recognised shape, so the
    caller falls back to the raw pySigma message.
    """
    msg = str(cause)
    if "Unable to determine table name from rule" not in msg:
        return None

    if resolved is not None and resolved.unsupported_reason:
        return resolved.unsupported_reason

    label = resolved.label if resolved is not None else backend_id
    return (
        f"{label} has no table mapping for this rule's logsource. The "
        f"telemetry may well exist in this platform, in which case this "
        f"is a gap that can be closed with a pipeline mapping rather "
        f"than a limitation of the rule. The Splunk, Elastic and "
        f"CrowdStrike tabs will usually convert it in the meantime."
    )


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

    pipeline = _compose_pipeline(plugins, resolved.pipelines, resolved.category_overrides)
    # pySigma's Backend base class has a ``processing_pipeline`` kwarg that
    # mypy can't see through the Generic abstraction.
    backend: Any = backend_cls(processing_pipeline=pipeline)  # type: ignore[operator]

    try:
        py_rule = PySigmaRule.from_yaml(yaml_text)
        queries = backend.convert_rule(py_rule, output_format=resolved.format)
    except SigmaError as exc:
        raise ConversionFailedError(resolved.backend_id, resolved.pipelines, exc, resolved) from exc
    except Exception as exc:
        # pySigma does not confine its failures to SigmaError. Measured
        # against the r2026-07-01 corpus, 391 of 3,651 loadable rules
        # (10.7%) raise something else on the kusto backends — 359
        # AttributeError ("'SigmaNumber' object has no attribute
        # '__annotations__'"), 31 InvalidHashAlgorithmError, 1 TypeError.
        #
        # Before this branch those escaped convert() entirely. The
        # conversion route converts every backend inside one handler and
        # catches only ConversionFailedError / UnknownBackendError, and
        # the app installs no global exception handler — so a single
        # unwrapped AttributeError returned a 500 for the whole
        # conversion stage, not just the one backend's tab.
        #
        # Broad by intent, and narrow in scope: the try block is exactly
        # two third-party calls, so this cannot mask a defect in our own
        # code.
        #
        # Deliberately not logged here — I-8 keeps core/convert/ free of
        # I/O. Nothing is swallowed: ``cause`` retains the original
        # exception and its text reaches the user through the rendered
        # error, exactly as the SigmaError branch above already does.
        # A web-layer caller that wants these in the access log can read
        # ``ConversionFailedError.cause``.
        raise ConversionFailedError(resolved.backend_id, resolved.pipelines, exc, resolved) from exc

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
            resolved,
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
    category_overrides: tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...] = (),
) -> ProcessingPipeline | None:
    """Compose a single ``ProcessingPipeline`` from the named pipelines.

    Each named entry in ``plugins.pipelines`` is a callable (either a
    factory function returning a ``ProcessingPipeline`` or a Pipeline class
    whose ``__call__`` returns a bound copy). We instantiate each, sort by
    priority, and sum them — the same composition ``ProcessingPipelineResolver``
    does internally, without the detour through name-lookup.

    ``category_overrides`` is the data-driven gap-filler from
    ``data/pipelines.yml`` (priority 5 — runs before the upstream
    pipelines). Returns ``None`` when no pipelines apply AND no overrides
    exist; pySigma backends accept that and use their built-in defaults.
    """
    pipelines: list[ProcessingPipeline] = []

    # Override pipeline runs first (priority=5 in build_category_override_pipeline).
    override_pipeline = build_category_override_pipeline(category_overrides)
    if override_pipeline is not None:
        pipelines.append(override_pipeline)

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
        # deepcopy is load-bearing, not defensive habit.
        #
        # The factory returns a fresh ProcessingPipeline each call, but the
        # transformation objects *inside* it are module-level singletons —
        # two factory() calls yield different pipelines holding the same
        # transformation instances. pySigma-backend-kusto's
        # InvalidFieldTransformation.apply_detection_item then does:
        #
        #     self.message = f"...{field_name}. " + self.message
        #
        # which mutates that shared instance. Every conversion hitting an
        # invalid field permanently grows the message, and the growth is
        # visible to every later conversion in the process. Converting
        # rule B after rule A produced an error for B naming A's fields;
        # with one uvicorn process per replica and users sharing replicas,
        # that crossed HTTP request boundaries.
        #
        # Copying before use means the mutation lands on a private clone,
        # so the shared singleton is never written to at all and stays
        # pristine for the process lifetime. ~1.1ms per pipeline against a
        # ~100ms cold conversion, and conversions are cached by content
        # hash, so this is not on the warm path.
        pipelines.append(deepcopy(factory()))

    if not pipelines:
        return None

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
