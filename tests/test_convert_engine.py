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
from intel2sigma.core.serialize import from_yaml

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
    """A rule whose logsource category is in NEITHER the pySigma upstream
    map NOR our intel2sigma override layer produces the operator-friendly
    error.

    Originally used ``create_remote_thread`` as the canonical example; the
    Phase B3 override layer (commit landing this change) added a table
    mapping for it, so the canonical example moved to a category that's
    truly unsupported by Defender XDR — a Linux logsource. Defender XDR
    is Windows-focused; Linux process_creation has no mapping there
    upstream, and we don't override it because the right answer is
    "use Splunk/Elastic instead".
    """
    rule = SigmaRule(
        title="Rule against a category neither side maps",
        id=UUID("33333333-4444-5555-6666-777777777777"),
        date=date(2026, 4, 25),
        # A made-up category — neither pySigma upstream nor our override
        # layer maps this to a Defender XDR table.
        logsource=LogSource(product="windows", category="not_a_real_category_xyz"),
        detections=[
            DetectionBlock(
                name="match_1",
                items=[
                    DetectionItem(field="Image", modifiers=["endswith"], values=["x"]),
                ],
            ),
        ],
        condition=ConditionExpression(selection="match_1"),
    )

    with pytest.raises(ConversionFailedError) as exc_info:
        convert(rule, "kusto_mde")

    msg = str(exc_info.value)
    assert "table mapping" in msg or "Splunk" in msg or "Elastic" in msg
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


def test_unsupported_telemetry_says_so_instead_of_promising_a_fix() -> None:
    """A logsource the backend's schema cannot contain is reported as final.

    "Unable to determine table name" covers two situations users need
    told apart: telemetry the platform simply does not have (Okta on
    Defender XDR), and telemetry it has but pySigma has not mapped.
    Both used to render as the second, so an Okta user was told about
    Sysmon categories and invited to wait for a fix that is not coming.

    The unsupported set is data — ``unsupported_products`` in
    ``pipelines.yml`` (I-5) — so adding a platform needs no Python.

    Zeek is the example because it has no ingestion path into Defender
    XDR at all. Third-party network-sensor telemetry can reach
    Sentinel-native tables through a CEF/syslog connector, but not the
    advanced-hunting tables this backend queries.
    """
    rule = SigmaRule(
        title="Zeek DNS query",
        id=UUID("77777777-8888-9999-aaaa-bbbbbbbbbbbb"),
        date=date(2026, 7, 28),
        logsource=LogSource(product="zeek", service="dns"),
        detections=[
            DetectionBlock(
                name="match_1",
                items=[DetectionItem(field="query", modifiers=[], values=["x"])],
            ),
        ],
        condition=ConditionExpression(selection="match_1"),
    )

    with pytest.raises(ConversionFailedError) as exc_info:
        convert(rule, "kusto_sentinel")

    msg = str(exc_info.value)
    assert "Zeek network-sensor telemetry" in msg, "should name the telemetry that is absent"
    assert "cannot be expressed" in msg, "should be framed as final, not as a to-do"
    # Must NOT imply someone is coming to fix it.
    assert "coverage gap" not in msg
    # The old message name-dropped an unrelated Sysmon category.
    assert "create_remote_thread" not in msg


def test_saas_platforms_are_reported_as_unmapped_not_impossible() -> None:
    """Okta must NOT be called impossible — Defender can ingest it.

    This is the regression guard for a real mistake. Okta was originally
    added to ``unsupported_products`` on the assumption that Defender XDR
    has no Okta tables. It does: Microsoft ships an Okta connector for
    Defender for Identity (preview, 2026-06) and another for Defender for
    Cloud Apps, both of which surface in advanced hunting. The same holds
    for AWS, GCP, GitHub, Bitbucket and OneLogin via Cloud Apps.

    None of them convert today, but "unmapped" and "impossible" are
    different claims, and only the first is true. Asserting the second
    would talk a user out of a detection that a pipeline mapping — or
    simply a newer Microsoft connector — can deliver.
    """
    rule = SigmaRule(
        title="Okta admin role assigned",
        id=UUID("99999999-aaaa-bbbb-cccc-dddddddddddd"),
        date=date(2026, 7, 29),
        logsource=LogSource(product="okta", service="okta"),
        detections=[
            DetectionBlock(
                name="match_1",
                items=[DetectionItem(field="eventType", modifiers=[], values=["x"])],
            ),
        ],
        condition=ConditionExpression(selection="match_1"),
    )

    with pytest.raises(ConversionFailedError) as exc_info:
        convert(rule, "kusto_sentinel")

    msg = str(exc_info.value)
    assert "cannot be expressed" not in msg, (
        "Defender for Identity and Defender for Cloud Apps both ingest Okta; "
        "calling this impossible is factually wrong and discourages a "
        "detection the platform can support"
    )
    assert "gap that can be closed" in msg


def test_unmapped_but_supported_logsource_is_reported_as_a_closable_gap() -> None:
    """The counter-case: a platform the backend does cover, just unmapped.

    Windows endpoint telemetry *is* in Defender XDR, so a missing table
    mapping there is a gap that a ``category_overrides`` entry closes.
    Reporting it as impossible would talk a user out of a detection we
    could support — which is why absence from ``unsupported_products``
    is the safe default.
    """
    rule = SigmaRule(
        title="Windows stream hash rule",
        id=UUID("88888888-9999-aaaa-bbbb-cccccccccccc"),
        date=date(2026, 7, 28),
        logsource=LogSource(product="windows", category="create_stream_hash"),
        detections=[
            DetectionBlock(
                name="match_1",
                items=[DetectionItem(field="TargetFilename", modifiers=[], values=["x"])],
            ),
        ],
        condition=ConditionExpression(selection="match_1"),
    )

    with pytest.raises(ConversionFailedError) as exc_info:
        convert(rule, "kusto_sentinel")

    msg = str(exc_info.value)
    assert "gap that can be closed" in msg
    assert "property of the platform" not in msg, (
        "windows telemetry exists in Defender XDR; calling this impossible "
        "would talk the user out of a supportable detection"
    )


def test_conversion_errors_do_not_leak_between_rules() -> None:
    """One rule's conversion error must not name another rule's fields.

    pySigma-backend-kusto's ``InvalidFieldTransformation`` mutates its own
    ``self.message`` when it rejects a field::

        self.message = f"...{field_name}. " + self.message

    and the transformation objects inside a pipeline are module-level
    singletons — the factory returns a fresh ProcessingPipeline each call
    but the transformations within it are shared. So every conversion
    that hit an invalid field permanently grew a message every later
    conversion could see.

    That crossed HTTP request boundaries: the server runs one uvicorn
    process per replica (I-3, and per-request scaling means users share
    replicas), so one user's rule field names surfaced in another user's
    error message. Field names in a proprietary detection disclose what
    an organisation monitors, which makes this a confidentiality bug
    rather than a cosmetic one.

    ``_compose_pipeline`` deep-copies each factory-produced pipeline so
    the mutation lands on a private clone and the shared singleton is
    never written to.
    """
    field_a = "TotallyMadeUpFieldAlpha"
    field_b = "TotallyMadeUpFieldBeta"

    def convert_with_bad_field(field: str, rule_id: str) -> str:
        rule = SigmaRule(
            title=f"Rule using {field}",
            id=UUID(rule_id),
            date=date(2026, 7, 28),
            logsource=LogSource(product="windows", category="process_creation"),
            detections=[
                DetectionBlock(
                    name="match_1",
                    items=[DetectionItem(field=field, modifiers=["contains"], values=["x"])],
                ),
            ],
            condition=ConditionExpression(selection="match_1"),
        )
        try:
            convert(rule, "kusto_sentinel")
        except ConversionFailedError as exc:
            return str(exc)
        return ""

    convert_with_bad_field(field_a, "55555555-6666-7777-8888-999999999999")
    second = convert_with_bad_field(field_b, "66666666-7777-8888-9999-aaaaaaaaaaaa")

    # The second rule never referenced field_a. If it appears, pipeline
    # state is being shared across conversions again.
    assert field_a not in second, (
        f"conversion error for the second rule leaked the first rule's field "
        f"{field_a!r}; pipeline transformation state is shared across "
        f"conversions.\nSecond rule's error: {second}"
    )
    assert field_b in second, (
        f"expected the second rule's own field {field_b!r} in its error, "
        f"so this test fails loudly if the error shape changes rather than "
        f"passing vacuously.\nSecond rule's error: {second}"
    )


def test_non_sigma_exception_is_wrapped_not_propagated() -> None:
    """pySigma failures that are NOT SigmaError must still surface as
    ConversionFailedError.

    pySigma does not confine its failures to its own exception base. A
    numeric detection value on the kusto backends raises a bare
    ``AttributeError`` ("'SigmaNumber' object has no attribute
    '__annotations__'") from inside the processing pipeline. Measured
    against the r2026-07-01 corpus, 391 of 3,651 loadable rules (10.7%)
    raise a non-SigmaError this way.

    That mattered because the conversion route converts all five
    backends inside one handler, catches only ConversionFailedError /
    UnknownBackendError, and the app installs no global exception
    handler — so one unwrapped AttributeError returned a 500 for the
    entire conversion stage rather than an error message on one tab.

    The assertion is deliberately about the exception *type*, not the
    message: if pySigma later fixes the underlying bug this test still
    passes, because a successful conversion is also an acceptable
    outcome. What must never happen is a raw non-typed exception
    escaping ``convert()``.

    The rule is loaded from YAML rather than constructed in-process on
    purpose. Building the equivalent ``SigmaRule`` by hand does *not*
    reproduce: the round-trip through :func:`to_yaml` inside
    ``convert()`` renders the numeric ``EventID`` differently, and the
    conversion then fails at table determination (a SigmaError) without
    ever reaching the code path this test exists to cover.
    """
    fixture = Path(__file__).parent / "fixtures" / "kusto_numeric_eventid.yml"
    rule = from_yaml(fixture.read_text(encoding="utf-8"))

    try:
        convert(rule, "kusto_sentinel")
    except ConversionFailedError as exc:
        # Wrapped correctly; the original is retained for callers.
        assert exc.cause is not None
        assert exc.backend_id == "kusto_sentinel"
    except Exception as exc:  # pragma: no cover - the regression itself
        pytest.fail(
            f"convert() leaked a raw {type(exc).__name__}; it must wrap "
            f"non-SigmaError failures in ConversionFailedError so the "
            f"conversion route can render them instead of returning 500. "
            f"Original: {exc}"
        )
