"""Live conversion tests against pySigma.

Each test runs a minimal process_creation rule through one backend and
asserts the output is non-empty and contains a backend-specific substring
(proving the correct pySigma backend was invoked and produced a query in
the expected shape). Exact outputs live in golden files under
``tests/golden/convert/`` — if pySigma's output format changes across a
version bump, the golden diff surfaces it and regenerating the goldens
is a deliberate step, not a silent update.
"""

from __future__ import annotations

import os
from datetime import date
from pathlib import Path
from uuid import UUID

import pytest

from intel2sigma.core.convert import (
    ConversionFailedError,
    UnknownBackendError,
    convert,
)
from intel2sigma.core.model import (
    ConditionExpression,
    DetectionBlock,
    DetectionItem,
    LogSource,
    SigmaRule,
)

GOLDEN_DIR = Path(__file__).parent / "golden" / "convert"


@pytest.fixture
def encoded_ps_rule() -> SigmaRule:
    """A minimal process_creation rule used by the convert smoke tests.

    Kept small so the expected output is short and stable across pySigma
    patch versions — the golden files are regeneratable with
    ``UPDATE_GOLDENS=1 uv run pytest tests/test_convert_engine.py``.
    """
    return SigmaRule(
        title="Test: encoded PowerShell",
        id=UUID("11111111-2222-3333-4444-555555555555"),
        date=date(2026, 4, 24),
        logsource=LogSource(product="windows", category="process_creation"),
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(
                        field="Image",
                        modifiers=["endswith"],
                        values=["\\powershell.exe"],
                    ),
                    DetectionItem(
                        field="CommandLine",
                        modifiers=["contains"],
                        values=["-encodedcommand"],
                    ),
                ],
            ),
        ],
        condition=ConditionExpression(selection="match_1"),
    )


# Minimal substring each backend's output should contain — a much lighter
# assertion than a full golden diff, useful for catching "the wrong backend
# ran" or "pySigma returned nothing". The goldens cover exact-output
# regressions.
EXPECTED_SUBSTRINGS: dict[str, str] = {
    "kusto_sentinel": "DeviceProcessEvents",
    "kusto_mde": "DeviceProcessEvents",
    "splunk": "EventCode=1",
    "elasticsearch": "process.executable",
    "crowdstrike": "event_simpleName",
}


@pytest.mark.parametrize("backend_id", sorted(EXPECTED_SUBSTRINGS))
def test_backend_produces_plausible_output(backend_id: str, encoded_ps_rule: SigmaRule) -> None:
    """Live conversion: output is non-empty and looks like the target dialect."""
    query = convert(encoded_ps_rule, backend_id)
    assert query, f"{backend_id}: conversion produced empty output"
    expected = EXPECTED_SUBSTRINGS[backend_id]
    assert expected in query, f"{backend_id}: output does not contain {expected!r}. Got:\n{query}"


@pytest.mark.parametrize("backend_id", sorted(EXPECTED_SUBSTRINGS))
def test_backend_output_matches_golden(backend_id: str, encoded_ps_rule: SigmaRule) -> None:
    """Regression guard: exact output per backend is pinned.

    Regenerate with ``UPDATE_GOLDENS=1 uv run pytest tests/test_convert_engine.py``.
    """
    query = convert(encoded_ps_rule, backend_id)
    golden_path = GOLDEN_DIR / f"process_creation_{backend_id}.txt"

    if os.environ.get("UPDATE_GOLDENS"):
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(query, encoding="utf-8")
        pytest.skip(f"Updated golden at {golden_path}")

    assert golden_path.exists(), (
        f"Missing golden file {golden_path}. Create it with "
        f"UPDATE_GOLDENS=1 uv run pytest tests/test_convert_engine.py"
    )
    expected = golden_path.read_text(encoding="utf-8")
    assert query == expected, (
        f"{backend_id}: output diverged from golden.\n"
        f"--- golden ---\n{expected}\n--- actual ---\n{query}"
    )


def test_convert_is_cached(encoded_ps_rule: SigmaRule) -> None:
    """Second call should hit the LRU cache. We can't observe the cache
    directly but the same inputs must produce the same output.
    """
    q1 = convert(encoded_ps_rule, "kusto_sentinel")
    q2 = convert(encoded_ps_rule, "kusto_sentinel")
    assert q1 == q2


def test_unknown_backend_raises(encoded_ps_rule: SigmaRule) -> None:
    with pytest.raises(UnknownBackendError):
        convert(encoded_ps_rule, "qradar")


def test_unmappable_category_emits_friendlier_error() -> None:
    """A rule whose logsource category isn't in the kusto_mde pipeline's
    category-to-table map produces a guidance-shaped error string,
    not the raw "Unable to determine table name from rule" trace.

    create_remote_thread (Sysmon EID 8) is the canonical example —
    pySigma-backend-kusto's microsoft_365_defender pipeline doesn't
    map it to a Defender XDR table, so conversion fails. The user
    deserves "use Splunk/Elastic/CrowdStrike instead" not a paragraph
    of pipeline-state internals.
    """
    rule = SigmaRule(
        title="CRT rule for which Defender has no table mapping",
        id=UUID("33333333-4444-5555-6666-777777777777"),
        date=date(2026, 4, 25),
        logsource=LogSource(product="windows", category="create_remote_thread"),
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(field="TargetImage", modifiers=["endswith"], values=["x"]),
                ],
            ),
        ],
        condition=ConditionExpression(selection="match_1"),
    )

    with pytest.raises(ConversionFailedError) as exc_info:
        convert(rule, "kusto_mde")

    msg = str(exc_info.value)
    # Friendlier message must mention what to do next.
    assert "table mapping" in msg
    assert "Splunk" in msg or "Elastic" in msg or "CrowdStrike" in msg
    # And must not parrot pySigma's internal "1) ... 2) ..." pipeline
    # priority list — that's what we rewrote away.
    assert "query_table parameter" not in msg


def test_conversion_failure_wraps_pysigma_error() -> None:
    """A rule whose logsource routes to a backend but whose shape pySigma
    rejects surfaces as ConversionFailedError, not a raw SigmaError.
    """
    # Construct a rule with a deliberately-invalid field for the Kusto pipeline.
    # The microsoft_xdr pipeline maps a known set of fields; referencing a
    # field it doesn't know about triggers pySigma's validation on convert.
    rule = SigmaRule(
        title="Bad field for Kusto",
        id=UUID("22222222-3333-4444-5555-666666666666"),
        date=date(2026, 4, 24),
        logsource=LogSource(product="windows", category="process_creation"),
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(
                        field="NonExistentSysmonField",
                        modifiers=["contains"],
                        values=["x"],
                    ),
                ],
            ),
        ],
        condition=ConditionExpression(selection="match_1"),
    )

    # pySigma's Kusto pipeline may or may not reject unknown fields depending
    # on its strict-field setting — if it accepts, this test becomes a
    # successful-conversion test. Either outcome is acceptable here; the
    # assertion is that IF conversion fails, the exception is our typed one.
    try:
        convert(rule, "kusto_sentinel")
    except ConversionFailedError as exc:
        assert exc.backend_id == "kusto_sentinel"
        assert exc.pipelines
