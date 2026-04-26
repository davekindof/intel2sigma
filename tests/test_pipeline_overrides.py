"""Tests for the data-driven category-override pipeline (Phase B3).

pySigma's microsoft_xdr / microsoft_365_defender pipelines map a fixed
set of Sigma logsource categories to Defender XDR table names. Sysmon-
only categories that aren't in that set used to fail conversion with
"Unable to determine table name from rule". The override layer in
``data/pipelines.yml`` plus
:func:`build_category_override_pipeline` fills those gaps by setting
``query_table`` in the pipeline state at priority 5 (before the
upstream's priority-10 SetQueryTableState).

Tests verify the override fires for each gap category against both
Kusto-flavored backends, AND that categories already covered upstream
are NOT touched (the override pipeline shouldn't shadow real mappings).
"""

from __future__ import annotations

from datetime import date
from uuid import UUID

import pytest

from intel2sigma.core.convert import ConversionFailedError, convert
from intel2sigma.core.convert.pipelines import (
    build_category_override_pipeline,
    load_pipeline_matrix,
)
from intel2sigma.core.model import (
    ConditionExpression,
    DetectionBlock,
    DetectionItem,
    LogSource,
    SigmaRule,
)


def _rule_with_category(category: str, field: str, value: str) -> SigmaRule:
    return SigmaRule(
        title=f"{category} test",
        id=UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        date=date(2026, 4, 26),
        logsource=LogSource(product="windows", category=category),
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(field=field, modifiers=[], values=[value]),
                ],
            )
        ],
        condition=ConditionExpression(selection="match_1"),
    )


# ---------------------------------------------------------------------------
# Phase B3: pipelines.yml carries the override data
# ---------------------------------------------------------------------------


def test_kusto_backends_carry_category_overrides() -> None:
    """The bundled matrix declares overrides for both Kusto backends."""
    matrix = load_pipeline_matrix()
    for backend_id in ("kusto_mde", "kusto_sentinel"):
        spec = matrix.backends[backend_id]
        assert spec.category_overrides, (
            f"{backend_id} should declare overrides for Sysmon-only "
            f"categories (create_remote_thread, pipe_created, etc.)"
        )
        # Spot-check the load-bearing entries.
        assert "create_remote_thread" in spec.category_overrides
        assert spec.category_overrides["create_remote_thread"].table == "DeviceEvents"


def test_build_category_override_pipeline_returns_none_for_empty() -> None:
    """No overrides → no pipeline. Callers skip composition."""
    assert build_category_override_pipeline(()) is None


def test_build_category_override_pipeline_emits_processing_items() -> None:
    """Each override produces at least one ProcessingItem (table set);
    overrides with a filter produce two (table set + condition add).
    """
    overrides = (
        ("create_remote_thread", "DeviceEvents", ()),
        ("driver_load", "DeviceEvents", (("ActionType", "DriverLoad"),)),
    )
    pipeline = build_category_override_pipeline(overrides)
    assert pipeline is not None
    # 1 item for create_remote_thread + 2 for driver_load (table + filter) = 3.
    assert len(pipeline.items) == 3
    # Override pipeline runs before upstream (priority 10).
    assert pipeline.priority < 10


# ---------------------------------------------------------------------------
# End-to-end: gap categories now convert cleanly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("category", "expected_table"),
    [
        ("create_remote_thread", "DeviceEvents"),
        ("pipe_created", "DeviceEvents"),
        ("raw_access_thread", "DeviceEvents"),
        ("wmi_event", "DeviceEvents"),
        ("driver_load", "DeviceEvents"),
        ("process_access", "DeviceEvents"),
        ("dns_query", "DeviceNetworkEvents"),
        ("ps_script", "DeviceEvents"),
        ("ps_module", "DeviceEvents"),
    ],
)
@pytest.mark.parametrize("backend_id", ["kusto_mde", "kusto_sentinel"])
def test_gap_category_converts_against_kusto_backends(
    category: str, expected_table: str, backend_id: str
) -> None:
    """Every Sysmon-only / gap category produces a query starting with
    the correct Defender XDR table — no more "Unable to determine table
    name" errors.

    Uses the Defender-native ``ActionType`` field (no modifier) so we
    don't trip the field-mapping validator; the test target is the
    table-name resolution, not the field map.
    """
    rule = _rule_with_category(category, "ActionType", "TestActionType")
    out = convert(rule, backend_id)
    # Defender / Sentinel KQL queries always start with "<TableName>\n| ...".
    assert out.startswith(expected_table), (
        f"{backend_id}/{category}: expected query to start with "
        f"{expected_table!r}, got: {out[:120]!r}"
    )


def test_existing_pysigma_mapping_not_shadowed() -> None:
    """``process_creation`` is in pySigma's upstream mapping → DeviceProcessEvents.
    Our override layer mustn't shadow it (we have no override for
    process_creation in pipelines.yml, so this is really a guard against
    accidentally adding one).
    """
    rule = _rule_with_category("process_creation", "ProcessCommandLine", "evil")
    out = convert(rule, "kusto_mde")
    assert out.startswith("DeviceProcessEvents")


def test_unmappable_category_still_friendlier_error_when_genuinely_uncovered() -> None:
    """A category that's in NEITHER our overrides NOR pySigma's upstream
    map still produces the operator-friendly error, not a raw pySigma
    traceback. Verifies the friendlier-error path is still wired even
    after the override layer exists.
    """
    rule = _rule_with_category("category_we_definitely_dont_cover", "Field", "x")
    with pytest.raises(ConversionFailedError) as exc_info:
        convert(rule, "kusto_mde")
    msg = str(exc_info.value)
    # Friendly guidance survives.
    assert "table mapping" in msg or "Splunk" in msg or "table name" in msg
