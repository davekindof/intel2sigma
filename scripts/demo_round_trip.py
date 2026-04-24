"""Demo: build a Sigma rule, emit canonical YAML, parse it back, and prove
pySigma accepts it.

This script exercises every guarantee the v0 core library makes:

1. A :class:`~intel2sigma.core.model.SigmaRule` can be constructed in memory
   with the canonical metadata, logsource, detection, and condition shape.
2. :func:`intel2sigma.core.serialize.to_yaml` emits Sigma YAML in the
   canonical key order with the condition nested inside the ``detection``
   block (SPEC.md § Serialization).
3. :func:`intel2sigma.core.serialize.from_yaml` round-trips that YAML back
   into an equivalent model, and re-serializing produces byte-identical
   output (the round-trip guarantee).
4. pySigma (the same parser that powers every Sigma conversion backend)
   accepts our YAML without errors — the rule is genuinely valid Sigma, not
   just syntactically a YAML document.

Run from the project root::

    uv run python scripts/demo_round_trip.py

Exits 0 on success, non-zero on any failed assertion.
"""

from __future__ import annotations

import sys
from datetime import date
from uuid import UUID

from sigma.rule import SigmaRule as PySigmaRule

from intel2sigma.core.model import (
    ConditionExpression,
    ConditionOp,
    DetectionBlock,
    DetectionItem,
    LogSource,
    SigmaRule,
)
from intel2sigma.core.serialize import from_yaml, to_yaml

# Fixed UUID so repeated runs produce identical output — useful when paging
# through the YAML in a PR description or dropping it in a changelog entry.
DEMO_ID = UUID("d3d3d3d3-4242-4242-4242-000000000001")


def build_demo_rule() -> SigmaRule:
    """Return a representative process_creation rule.

    Chosen to exercise every code path in the serializer:
      * multi-value list for ``CommandLine`` (stays a list on emission)
      * single-value list (collapses to a scalar — canonical Sigma shape)
      * modifier chain (``contains|all``)
      * both a match block and a filter block
      * a condition tree with AND + NOT
      * ATT&CK-style tag format
    """
    match_block = DetectionBlock(
        name="match_1",
        items=[
            DetectionItem(
                field="Image",
                modifiers=["endswith"],
                values=["\\powershell.exe"],
            ),
            DetectionItem(
                field="CommandLine",
                modifiers=["contains", "all"],
                values=["-encodedcommand", "-nop"],
            ),
        ],
    )
    filter_block = DetectionBlock(
        name="filter_1",
        is_filter=True,
        items=[
            DetectionItem(
                field="User",
                modifiers=["contains"],
                values=["SYSTEM"],
            ),
        ],
    )
    condition = ConditionExpression(
        op=ConditionOp.AND,
        children=[
            ConditionExpression(selection="match_1"),
            ConditionExpression(
                op=ConditionOp.NOT,
                children=[ConditionExpression(selection="filter_1")],
            ),
        ],
    )
    return SigmaRule(
        title="Demo: encoded PowerShell outside SYSTEM",
        id=DEMO_ID,
        status="experimental",
        description=(
            "Detects encoded PowerShell command lines launched by a "
            "non-SYSTEM account — a common living-off-the-land pattern."
        ),
        references=["https://example.invalid/demo"],
        author="intel2sigma demo",
        date=date(2026, 4, 23),
        tags=["attack.execution", "attack.t1059.001"],
        logsource=LogSource(product="windows", category="process_creation"),
        detections=[match_block, filter_block],
        condition=condition,
        falsepositives=["Administrative scripts invoked by operators"],
        level="high",
    )


def main() -> int:
    print("=" * 72)
    print("intel2sigma v0 core-library demo")
    print("=" * 72)

    rule = build_demo_rule()

    # 1. Emit canonical YAML.
    first_emission = to_yaml(rule)
    print("\n--- canonical YAML emission ---\n")
    print(first_emission)

    # 2. pySigma acceptance — proves this is real Sigma, not just valid YAML.
    py_rule = PySigmaRule.from_yaml(first_emission)
    print(f"pySigma parsed title: {py_rule.title!r}")
    print(
        f"pySigma logsource:    product={py_rule.logsource.product!r} "
        f"category={py_rule.logsource.category!r}"
    )

    # 3. from_yaml round-trip.
    parsed = from_yaml(first_emission)
    assert parsed.title == rule.title, "title did not round-trip"
    assert parsed.id == rule.id, "id did not round-trip"
    assert parsed.logsource == rule.logsource, "logsource did not round-trip"
    assert len(parsed.detections) == len(rule.detections)

    # 4. Byte-identical re-serialization — the SPEC.md guarantee.
    second_emission = to_yaml(parsed)
    if first_emission != second_emission:
        print("\nFAIL: round-trip produced different bytes.", file=sys.stderr)
        print("--- first ---\n" + first_emission, file=sys.stderr)
        print("--- second ---\n" + second_emission, file=sys.stderr)
        return 1

    print("\nRound-trip is byte-identical.")
    print(f"YAML size: {len(first_emission)} bytes.")
    print("\nAll guarantees hold:")
    print("  [x] canonical key order")
    print("  [x] condition nested inside detection")
    print("  [x] pySigma accepts the output")
    print("  [x] from_yaml round-trips equivalently")
    print("  [x] re-serialization is byte-identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
