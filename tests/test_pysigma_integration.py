"""pySigma acceptance test.

Feeds the canonical YAML produced by :mod:`intel2sigma.core.serialize` into
pySigma's own loader. If pySigma rejects it, the serializer is non-canonical
and v0 exit criteria are not met.
"""

from __future__ import annotations

from sigma.rule import SigmaRule as PySigmaRule

from intel2sigma.core.model import SigmaRule
from intel2sigma.core.serialize import to_yaml


def test_pysigma_accepts_canonical_yaml(smoke_rule: SigmaRule) -> None:
    text = to_yaml(smoke_rule)
    rule = PySigmaRule.from_yaml(text)

    assert rule is not None
    assert str(rule.title) == smoke_rule.title
    # pySigma's UUID comparison: compare string form to avoid library-version
    # differences in how the id is exposed.
    assert str(rule.id) == str(smoke_rule.id)
    assert rule.logsource.product == smoke_rule.logsource.product
    assert rule.logsource.category == smoke_rule.logsource.category
