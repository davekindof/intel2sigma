"""pySigma wrapper and pipeline matrix.

Public API:

* :func:`convert` — produce a SIEM query from an :class:`~intel2sigma.core.model.SigmaRule`.
* :func:`all_backend_ids` — enumerate declared backend ids for UI tabs / CLI help.
* :func:`backend_label` — human-readable backend label for display.
* Error types: :class:`UnknownBackendError`, :class:`ConversionFailedError`,
  :class:`PipelineMatrixError`.
"""

from intel2sigma.core.convert.engine import (
    ConversionFailedError,
    convert,
)
from intel2sigma.core.convert.pipelines import (
    PipelineMatrixError,
    ResolvedConversion,
    UnknownBackendError,
    all_backend_ids,
    backend_label,
    load_pipeline_matrix,
    resolve,
)

__all__ = [
    "ConversionFailedError",
    "PipelineMatrixError",
    "ResolvedConversion",
    "UnknownBackendError",
    "all_backend_ids",
    "backend_label",
    "convert",
    "load_pipeline_matrix",
    "resolve",
]
