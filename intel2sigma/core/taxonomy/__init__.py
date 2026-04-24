"""Observation-taxonomy catalog (data-driven).

Public API:

* :func:`load_taxonomy` — read and validate the bundled ``data/taxonomy/``
  directory, returning an immutable registry.
* :class:`TaxonomyRegistry` — the registry object itself.
* :class:`TaxonomyLoadError` — raised on any data or schema violation.
* Schema types (:class:`ObservationTypeSpec`, :class:`TaxonomyField`,
  :class:`PlatformVariant`, and the enums) for callers that need to reason
  about catalog shape programmatically.
"""

from intel2sigma.core.taxonomy.loader import (
    TaxonomyLoadError,
    TaxonomyRegistry,
    load_taxonomy,
)
from intel2sigma.core.taxonomy.schema import (
    CategoryGroup,
    FieldType,
    ObservationTypeSpec,
    PlatformTier,
    PlatformVariant,
    TaxonomyField,
)

__all__ = [
    "CategoryGroup",
    "FieldType",
    "ObservationTypeSpec",
    "PlatformTier",
    "PlatformVariant",
    "TaxonomyField",
    "TaxonomyLoadError",
    "TaxonomyRegistry",
    "load_taxonomy",
]
